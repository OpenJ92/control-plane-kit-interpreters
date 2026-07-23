from __future__ import annotations

from io import BytesIO
import subprocess
import sys
import tarfile
import unittest

from control_plane_kit_core.configuration import (
    ConfigurationArtifact,
    ConfigurationFileMode,
    ConfigurationMediaType,
)

from control_plane_kit_interpreters.docker.sdk import (
    DockerSdkClient,
    DockerSdkConfigurationMount,
    DockerSdkResourceInspection,
)


class FakeNotFound(Exception):
    pass


class FakeErrors:
    NotFound = FakeNotFound


class FakeDockerModule:
    errors = FakeErrors

    def __init__(self, client: FakeDockerClient) -> None:
        self.client = client

    def from_env(self) -> FakeDockerClient:
        return self.client


class FakeImage:
    def __init__(self, tags: list[str]) -> None:
        self.tags = tags


class FakeResource:
    def __init__(
        self,
        name: str,
        *,
        labels: dict[str, str] | None = None,
        image: str | None = None,
        running: bool = False,
    ) -> None:
        self.name = name
        self.image = FakeImage([image]) if image else None
        self.attrs = {
            "Config": {"Labels": labels or {}},
            "State": {"Running": running},
        }
        self.started = False
        self.stopped = False
        self.removed = False
        self.force_removed = False
        self.archives: dict[str, bytes] = {}
        self.execs: list[list[str]] = []
        self.connections: list[dict[str, object]] = []

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def remove(self, *, force: bool = False) -> None:
        self.removed = True
        self.force_removed = force

    def put_archive(self, path: str, data: bytes) -> None:
        self.archives[path] = data

    def get_archive(self, path: str) -> tuple[list[bytes], dict[str, object]]:
        if path != "/artifact/content" or "/artifact" not in self.archives:
            raise FakeNotFound(path)
        return [self.archives["/artifact"]], {}

    def exec_run(self, command: list[str]) -> tuple[int, bytes]:
        self.execs.append(command)
        return (0, b"")

    def connect(self, container: FakeResource, *, aliases: list[str]) -> None:
        self.connections.append({"container": container.name, "aliases": aliases})


class FakeManager:
    def __init__(self) -> None:
        self.resources: dict[str, FakeResource] = {}
        self.created: list[dict[str, object]] = []
        self.created_containers: list[FakeResource] = []
        self.volume_archives: dict[str, dict[str, bytes]] = {}
        self.pulled: list[str] = []

    def get(self, name: str) -> FakeResource:
        try:
            return self.resources[name]
        except KeyError as error:
            raise FakeNotFound(name) from error

    def create(self, *, name: str, labels: dict[str, str]) -> FakeResource:
        resource = FakeResource(name, labels=labels)
        self.resources[name] = resource
        self.created.append({"name": name, "labels": labels})
        return resource

    def create_container(self, image: str, **kwargs: object) -> FakeResource:
        resource = FakeResource(
            str(kwargs["name"]),
            labels={},
            image=image,
            running=False,
        )
        volumes = kwargs.get("volumes", {})
        if isinstance(volumes, dict) and volumes:
            volume_name = next(iter(volumes))
            resource.archives = self.volume_archives.setdefault(str(volume_name), {})
        self.resources[resource.name] = resource
        self.created_containers.append(resource)
        self.created.append({"image": image, **kwargs})
        return resource

    def pull(self, image: str) -> None:
        self.pulled.append(image)


class FakeDockerClient:
    def __init__(self) -> None:
        self.networks = FakeManager()
        self.volumes = FakeManager()
        self.images = FakeManager()
        self.containers = FakeManager()
        self.containers.create = self.containers.create_container


class DockerSdkClientTests(unittest.TestCase):
    def test_client_surface_matches_operations_realization_boundary(self) -> None:
        self.assertEqual(
            {
                name
                for name in dir(DockerSdkClient)
                if not name.startswith("_")
                and callable(getattr(DockerSdkClient, name))
            },
            {
                "configuration_artifact_digest",
                "create_network",
                "create_volume",
                "inspect_container",
                "inspect_network",
                "inspect_volume",
                "materialize_configuration_artifact",
                "pull_image",
                "remove_container",
                "remove_network",
                "remove_volume",
                "run_container",
                "start_container",
                "stop_container",
            },
        )

    def test_module_import_does_not_eagerly_import_docker_sdk(self) -> None:
        script = """
import sys
import control_plane_kit_interpreters.docker.sdk

assert "docker" not in sys.modules
"""

        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_client_creation_lazily_uses_docker_from_env(self) -> None:
        fake_client = FakeDockerClient()
        client = DockerSdkClient(docker_module=FakeDockerModule(fake_client))

        self.assertIs(client.client, fake_client)

    def test_missing_resources_are_absent_only_for_sdk_not_found_errors(self) -> None:
        sdk = DockerSdkClient(
            client=FakeDockerClient(),
            docker_module=FakeDockerModule(FakeDockerClient()),
        )

        self.assertIsNone(sdk.inspect_network("missing"))
        self.assertIsNone(sdk.inspect_volume("missing"))
        self.assertIsNone(sdk.inspect_container("missing"))

    def test_inspection_is_normalized_to_operations_shape(self) -> None:
        fake_client = FakeDockerClient()
        fake_client.containers.resources["web"] = FakeResource(
            "web",
            labels={"cpk.owner": "workspace-a"},
            image="ghcr.io/openj92/example@sha256:abc",
            running=True,
        )
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        inspection = sdk.inspect_container("web")

        self.assertEqual(
            inspection,
            DockerSdkResourceInspection(
                name="web",
                running=True,
                image="ghcr.io/openj92/example@sha256:abc",
                labels={"cpk.owner": "workspace-a"},
            ),
        )

    def test_network_volume_image_and_container_calls_use_sdk_boundary(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        sdk.create_network(name="cpk-net", labels={"cpk.workspace": "w"})
        sdk.create_volume(name="cpk-vol", labels={"cpk.workspace": "w"})
        sdk.pull_image("ghcr.io/openj92/example@sha256:abc")
        sdk.run_container(
            name="web",
            image="ghcr.io/openj92/example@sha256:abc",
            network="cpk-net",
            aliases=("web", "api"),
            environment={"PORT": "8080"},
            labels={"cpk.workspace": "w"},
            volumes={"cpk-vol": "/data"},
            command=("python", "-V"),
            configuration_mounts=(
                DockerSdkConfigurationMount(_artifact(), "cpk-config"),
            ),
        )

        self.assertEqual(
            fake_client.networks.created,
            [{"name": "cpk-net", "labels": {"cpk.workspace": "w"}}],
        )
        self.assertEqual(
            fake_client.volumes.created,
            [{"name": "cpk-vol", "labels": {"cpk.workspace": "w"}}],
        )
        self.assertEqual(
            fake_client.images.pulled,
            ["ghcr.io/openj92/example@sha256:abc"],
        )
        self.assertEqual(
            fake_client.containers.created,
            [
                {
                    "image": "ghcr.io/openj92/example@sha256:abc",
                    "detach": True,
                    "name": "web",
                    "environment": {"PORT": "8080"},
                    "labels": {"cpk.workspace": "w"},
                    "volumes": {"cpk-vol": {"bind": "/data", "mode": "rw"}},
                    "mounts": [
                        {
                            "Type": "volume",
                            "Source": "cpk-config",
                            "Target": "/etc/service/config.json",
                            "ReadOnly": True,
                            "VolumeOptions": {"Subpath": "content"},
                        }
                    ],
                    "command": ["python", "-V"],
                }
            ],
        )
        self.assertEqual(
            fake_client.networks.resources["cpk-net"].connections,
            [{"container": "web", "aliases": ["web", "api"]}],
        )
        self.assertTrue(fake_client.containers.resources["web"].started)

    def test_container_and_network_lifecycle_delegate_to_sdk_resources(self) -> None:
        fake_client = FakeDockerClient()
        network = FakeResource("cpk-net")
        container = FakeResource("web")
        volume = FakeResource("cpk-vol")
        fake_client.networks.resources["cpk-net"] = network
        fake_client.containers.resources["web"] = container
        fake_client.volumes.resources["cpk-vol"] = volume
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        sdk.start_container("web")
        sdk.stop_container("web")
        sdk.remove_container("web")
        sdk.remove_network("cpk-net")
        sdk.remove_volume("cpk-vol")

        self.assertTrue(container.started)
        self.assertTrue(container.stopped)
        self.assertTrue(container.removed)
        self.assertTrue(container.force_removed)
        self.assertFalse(network.started)
        self.assertTrue(network.removed)
        self.assertFalse(network.force_removed)
        self.assertTrue(volume.removed)
        self.assertFalse(volume.force_removed)

    def test_configuration_materialization_uses_bounded_helper_and_digest(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        artifact = _artifact()

        sdk.materialize_configuration_artifact("cpk-config", artifact)
        digest = sdk.configuration_artifact_digest("cpk-config")

        helpers = fake_client.containers.created
        self.assertEqual(len(helpers), 2)
        self.assertEqual(helpers[0]["network_disabled"], True)
        self.assertEqual(helpers[0]["read_only"], True)
        self.assertEqual(helpers[0]["cap_drop"], ["ALL"])
        self.assertEqual(helpers[0]["security_opt"], ["no-new-privileges"])
        self.assertEqual(
            helpers[0]["volumes"],
            {"cpk-config": {"bind": "/artifact", "mode": "rw"}},
        )
        self.assertEqual(
            helpers[1]["volumes"],
            {"cpk-config": {"bind": "/artifact", "mode": "ro"}},
        )
        self.assertEqual(digest, artifact.content_digest)
        self.assertTrue(
            all(
                resource.force_removed
                for resource in fake_client.containers.created_containers
            )
        )

    def test_configuration_content_is_not_passed_as_helper_command(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        artifact = _artifact('{"marker":"configuration-content-not-in-argv"}\n')

        sdk.materialize_configuration_artifact("cpk-config", artifact)

        helper_command = fake_client.containers.created[0]["command"]
        self.assertNotIn(artifact.content, helper_command)
        helper = fake_client.containers.created_containers[0]
        with tarfile.open(fileobj=BytesIO(helper.archives["/artifact"]), mode="r") as tar:
            member = tar.extractfile("content")
            self.assertIsNotNone(member)
            assert member is not None
            self.assertEqual(member.read().decode("utf-8"), artifact.content)
        self.assertEqual(
            helper.execs,
            [["chmod", artifact.file_mode.value, "/artifact/content"]],
        )

    def test_missing_configuration_content_returns_absent_digest(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        self.assertIsNone(sdk.configuration_artifact_digest("missing-config"))


def _artifact(content: str = '{"workers":2}\n') -> ConfigurationArtifact:
    return ConfigurationArtifact(
        "service-config",
        "/etc/service/config.json",
        ConfigurationMediaType.JSON,
        content,
        ConfigurationFileMode.READ_ONLY,
    )


if __name__ == "__main__":
    unittest.main()
