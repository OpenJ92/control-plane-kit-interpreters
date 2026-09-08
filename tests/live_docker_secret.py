"""Owning-gate local Docker witness; not published-product acceptance."""

from __future__ import annotations

import json
import hashlib
import os
from uuid import uuid4

from control_plane_kit_core.secrets import SecretFileMode, SecretValue
from control_plane_kit_interpreters.docker import DockerSdkClient, DockerSdkSecretMount


def main() -> None:
    import docker

    client = docker.from_env()
    if client.info().get("ID") != os.environ["CPK_SECRET_ENGINE_ID"]:
        client.close()
        raise RuntimeError("local secret fixture engine mismatch")
    run_id = os.environ["CPK_SECRET_TEST_RUN"]
    labels = {"org.openj92.cpk.test-run": run_id}
    image_id = os.environ["CPK_SECRET_READER_IMAGE"]
    helper_image = os.environ["CPK_SECRET_HELPER_IMAGE"]
    sdk = DockerSdkClient(client=client, configuration_helper_image=helper_image)
    resources = []
    helper_ids = []
    original_helper = sdk._create_configuration_helper

    def tracked_helper(*args, **kwargs):
        helper = original_helper(*args, **kwargs)
        helper_ids.append(helper.id)
        return helper

    sdk._create_configuration_helper = tracked_helper
    secret = SecretValue("numeric-reader-disposable-test-material")
    token = uuid4().hex
    target = "/run/secrets/cpk-fixture"
    cleanup_failed = False
    try:
        inspected = sdk.inspect_image(image_id)
        assert inspected is not None and inspected.image_id == image_id
        assert inspected.secret_file_owner_uid() == 10006
        assert client.images.get(image_id).labels.get("org.openj92.cpk.test-run") == run_id
        network = client.networks.create(f"cpk-secret-net-{token}", labels=labels)
        resources.append((client.networks, network.id))
        volume = client.volumes.create(name=f"cpk-secret-volume-{token}", labels=labels)
        resources.append((client.volumes, volume.name))
        sdk.materialize_secret_file(volume.name, secret, SecretFileMode.OWNER_READ_ONLY,
                                    owner_uid=inspected.secret_file_owner_uid())
        evidence = sdk.inspect_secret_file(volume.name)
        assert evidence.uid == 10006 and evidence.mode == 0o400 and evidence.regular_file
        mount = DockerSdkSecretMount(target, volume.name)
        read_script = (
            "import os, pathlib, hashlib\n"
            "assert os.getuid() == 10006\n"
            f"p=pathlib.Path({target!r})\n"
            f"assert hashlib.sha256(p.read_bytes()).hexdigest() == {hashlib.sha256(secret.reveal().encode()).hexdigest()!r}\n"
            "try: p.write_bytes(b'x')\n"
            "except OSError: pass\n"
            "else: raise SystemExit(4)\n"
        )
        deny_script = (
            "import os, pathlib\n"
            "assert os.getuid() == 10007\n"
            f"p=pathlib.Path({target!r})\n"
            "try: p.read_bytes()\n"
            "except PermissionError: pass\n"
            "else: raise SystemExit(5)\n"
        )
        for suffix, script, user in (("reader", read_script, None), ("other", deny_script, "10007")):
            kwargs = {} if user is None else {"user": user}
            container = client.containers.create(
                inspected.image_id, name=f"cpk-secret-{suffix}-{token}",
                labels=labels, command=["python", "-B", "-c", script],
                mounts=[dict(mount.docker_mount())], network=network.id,
                read_only=True, cap_drop=["ALL"], security_opt=["no-new-privileges"],
                **kwargs)
            resources.append((client.containers, container.id))
            container.start()
            result = container.wait(timeout=30)
            logs = container.logs(stdout=True, stderr=True, tail=30)
            assert secret.reveal().encode() not in logs, "material leaked"
            assert result.get("StatusCode") == 0, "numeric reader access law failed"
            container.reload()
            assert container.attrs["Image"] == inspected.image_id
            assert container.attrs["Config"]["User"] == (user or "10006")
            assert container.attrs["Mounts"][0]["RW"] is False
    finally:
        for manager, identity in reversed(resources):
            try:
                resource = manager.get(identity)
                resource.reload()
                observed_labels = resource.attrs.get("Labels") or resource.attrs.get("Config", {}).get("Labels", {})
                if observed_labels.get("org.openj92.cpk.test-run") != run_id:
                    cleanup_failed = True
                    continue
                if isinstance(resource, docker.models.containers.Container):
                    resource.remove(force=True)
                else:
                    resource.remove()
                try:
                    manager.get(identity)
                except docker.errors.NotFound:
                    pass
                else:
                    cleanup_failed = True
            except docker.errors.NotFound:
                pass
            except Exception:
                cleanup_failed = True
        for identity in helper_ids:
            try:
                client.containers.get(identity)
            except docker.errors.NotFound:
                pass
            else:
                cleanup_failed = True
        client.close()
        if cleanup_failed:
            raise RuntimeError("local secret fixture cleanup incomplete")
    print(json.dumps({"status": "passed", "numeric_reader": True,
                      "unrelated_uid_denied": True, "readonly": True, "residue": "absent"}))


if __name__ == "__main__":
    main()
