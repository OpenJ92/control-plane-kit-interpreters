from __future__ import annotations

import subprocess
import sys
import unittest

from control_plane_kit_interpreters.docker.sdk import (
    DockerSdkClient,
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

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def remove(self, *, force: bool = False) -> None:
        self.removed = True
        self.force_removed = force


class FakeManager:
    def __init__(self) -> None:
        self.resources: dict[str, FakeResource] = {}
        self.created: list[dict[str, object]] = []
        self.pulled: list[str] = []
        self.ran: list[dict[str, object]] = []

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

    def pull(self, image: str) -> None:
        self.pulled.append(image)

    def run(self, image: str, **kwargs: object) -> FakeResource:
        resource = FakeResource(
            str(kwargs["name"]),
            labels=dict(kwargs.get("labels", {})),
            image=image,
            running=True,
        )
        self.resources[resource.name] = resource
        self.ran.append({"image": image, **kwargs})
        return resource


class FakeDockerClient:
    def __init__(self) -> None:
        self.networks = FakeManager()
        self.volumes = FakeManager()
        self.images = FakeManager()
        self.containers = FakeManager()


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
                "create_network",
                "create_volume",
                "inspect_container",
                "inspect_network",
                "inspect_volume",
                "pull_image",
                "remove_container",
                "remove_network",
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
            fake_client.containers.ran,
            [
                {
                    "image": "ghcr.io/openj92/example@sha256:abc",
                    "detach": True,
                    "name": "web",
                    "network": "cpk-net",
                    "network_aliases": ["web", "api"],
                    "environment": {"PORT": "8080"},
                    "labels": {"cpk.workspace": "w"},
                    "volumes": {"cpk-vol": {"bind": "/data", "mode": "rw"}},
                }
            ],
        )

    def test_container_and_network_lifecycle_delegate_to_sdk_resources(self) -> None:
        fake_client = FakeDockerClient()
        network = FakeResource("cpk-net")
        container = FakeResource("web")
        fake_client.networks.resources["cpk-net"] = network
        fake_client.containers.resources["web"] = container
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        sdk.start_container("web")
        sdk.stop_container("web")
        sdk.remove_container("web")
        sdk.remove_network("cpk-net")

        self.assertTrue(container.started)
        self.assertTrue(container.stopped)
        self.assertTrue(container.removed)
        self.assertTrue(container.force_removed)
        self.assertFalse(network.started)
        self.assertTrue(network.removed)
        self.assertFalse(network.force_removed)


if __name__ == "__main__":
    unittest.main()
