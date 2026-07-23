"""Live Docker proof for SDK-backed read-only configuration artifacts."""

from __future__ import annotations

import json
from uuid import uuid4

from control_plane_kit_core.configuration import (
    ConfigurationArtifact,
    ConfigurationFileMode,
    ConfigurationMediaType,
)

from control_plane_kit_interpreters.docker import (
    DockerSdkClient,
    DockerSdkConfigurationMount,
)


CONTENT = '{"marker":"configuration-content-not-in-argv"}\n'


def main() -> None:
    suffix = uuid4().hex[:12]
    network_name = f"cpk-live-config-{suffix}"
    volume_name = f"cpk-live-config-{suffix}"
    container_name = f"cpk-live-config-{suffix}"
    labels = {
        "control-plane-kit.live-proof": "configuration-artifact",
        "control-plane-kit.disposable": "true",
    }
    artifact = ConfigurationArtifact(
        "service-config",
        "/etc/service/config.json",
        ConfigurationMediaType.JSON,
        CONTENT,
        ConfigurationFileMode.READ_ONLY,
    )
    sdk = DockerSdkClient()

    try:
        sdk.pull_image(sdk.configuration_helper_image)
        sdk.create_network(name=network_name, labels=labels)
        sdk.create_volume(name=volume_name, labels=labels)
        sdk.materialize_configuration_artifact(volume_name, artifact)
        digest = sdk.configuration_artifact_digest(volume_name)
        if digest != artifact.content_digest:
            raise AssertionError("configuration digest did not match artifact")
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
                _read_only_assertion_script(artifact.content_digest),
            ),
            configuration_mounts=(
                DockerSdkConfigurationMount(artifact, volume_name),
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
            raise AssertionError(
                f"configuration container exited {status_code}: {logs}"
            )
    finally:
        _cleanup(sdk, container_name, network_name, volume_name)

    print(
        json.dumps(
            {
                "status": "passed",
                "configuration_artifact": artifact.artifact_id,
                "content_digest": artifact.content_digest,
                "read_only_mount": True,
            },
            sort_keys=True,
        )
    )


def _read_only_assertion_script(expected_digest: str) -> str:
    return (
        "from pathlib import Path\n"
        "import hashlib, sys\n"
        "target = Path('/etc/service/config.json')\n"
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
