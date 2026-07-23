"""Live Docker proof for SDK-backed read-only secret files."""

from __future__ import annotations

import hashlib
import json
from uuid import uuid4

from control_plane_kit_core.secrets import SecretFileMode, SecretValue

from control_plane_kit_interpreters.docker import (
    DockerSdkClient,
    DockerSdkSecretMount,
)


SECRET_TEXT = "live-secret-content-not-in-output"


def main() -> None:
    suffix = uuid4().hex[:12]
    network_name = f"cpk-live-secret-{suffix}"
    volume_name = f"cpk-live-secret-{suffix}"
    container_name = f"cpk-live-secret-{suffix}"
    target_path = "/run/secrets/api-token"
    labels = {
        "control-plane-kit.live-proof": "secret-delivery",
        "control-plane-kit.disposable": "true",
    }
    secret = SecretValue(SECRET_TEXT)
    expected_digest = hashlib.sha256(SECRET_TEXT.encode("utf-8")).hexdigest()
    sdk = DockerSdkClient()

    try:
        sdk.pull_image(sdk.configuration_helper_image)
        sdk.create_network(name=network_name, labels=labels)
        sdk.create_volume(name=volume_name, labels=labels)
        sdk.materialize_secret_file(
            volume_name,
            secret,
            SecretFileMode.OWNER_READ_ONLY,
        )
        digest = sdk.secret_file_digest(volume_name)
        if digest != expected_digest:
            raise AssertionError("secret digest did not match runtime value")
        sdk.run_container(
            name=container_name,
            image=sdk.configuration_helper_image,
            network=network_name,
            aliases=(container_name,),
            environment={},
            labels=labels,
            volumes={},
            command=(
                "python",
                "-B",
                "-c",
                _read_only_assertion_script(target_path, expected_digest),
            ),
            secret_mounts=(
                DockerSdkSecretMount(target_path, volume_name),
            ),
        )
        container = sdk.client.containers.get(container_name)
        result = container.wait(timeout=30)
        status_code = result.get("StatusCode")
        if status_code != 0:
            logs = container.logs(stdout=True, stderr=True).decode(
                "utf-8",
                errors="replace",
            )
            if SECRET_TEXT in logs:
                raise AssertionError("secret content leaked into container logs")
            raise AssertionError(f"secret container exited {status_code}: {logs}")
    finally:
        _cleanup(sdk, container_name, network_name, volume_name)

    print(
        json.dumps(
            {
                "status": "passed",
                "secret_digest": expected_digest,
                "read_only_mount": True,
            },
            sort_keys=True,
        )
    )


def _read_only_assertion_script(target_path: str, expected_digest: str) -> str:
    return (
        "from pathlib import Path\n"
        "import hashlib, sys\n"
        f"target = Path({target_path!r})\n"
        "content = target.read_bytes()\n"
        f"if hashlib.sha256(content).hexdigest() != {expected_digest!r}:\n"
        "    raise SystemExit(2)\n"
        "try:\n"
        "    target.write_text('mutated', encoding='utf-8')\n"
        "except OSError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(3)\n"
    )


def _cleanup(
    sdk: DockerSdkClient,
    container_name: str,
    network_name: str,
    volume_name: str,
) -> None:
    for action, name in (
        (sdk.remove_container, container_name),
        (sdk.remove_network, network_name),
        (sdk.remove_volume, volume_name),
    ):
        try:
            action(name)
        except Exception:
            pass


if __name__ == "__main__":
    main()
