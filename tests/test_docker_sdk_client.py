from __future__ import annotations

from io import BytesIO
import hashlib
import subprocess
import sys
import tarfile
import unittest

from control_plane_kit_core.configuration import (
    ConfigurationArtifact,
    ConfigurationFileMode,
    ConfigurationMediaType,
)
from control_plane_kit_core.probe_intents import EndpointContext
from control_plane_kit_core.secrets import SecretFileMode, SecretValue
from control_plane_kit_core.types import Protocol, Transport

from control_plane_kit_interpreters.docker.sdk import (
    DockerRegistryAuthConfig,
    DockerSdkClient,
    DockerSdkConfigurationMount,
    DockerSdkPortBinding,
    DockerSdkPublishedPort,
    DockerSdkResourceInspection,
    DockerSdkSecretMount,
    DockerTlsClientConfig,
    runtime_endpoint_observations,
    verify_published_ports,
)


class FakeNotFound(Exception):
    pass


class FakeErrors:
    NotFound = FakeNotFound


class FakeTlsFactory:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def TLSConfig(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(dict(kwargs))
        return {"tls_config": dict(kwargs)}


class FakeDockerModule:
    errors = FakeErrors

    def __init__(self, client: FakeDockerClient) -> None:
        self.client = client
        self.tls = FakeTlsFactory()
        self.docker_clients: list[dict[str, object]] = []
        self.from_env_calls = 0

    def from_env(self) -> FakeDockerClient:
        self.from_env_calls += 1
        return self.client

    def DockerClient(self, **kwargs: object) -> FakeDockerClient:
        self.docker_clients.append(dict(kwargs))
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
        published_ports: dict[str, object] | None = None,
        private_addresses: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.image = FakeImage([image]) if image else None
        self.attrs = {
            "Config": {"Labels": labels or {}},
            "State": {"Running": running},
            "NetworkSettings": {
                "Ports": published_ports or {},
                "Networks": {
                    name: {"IPAddress": address}
                    for name, address in (private_addresses or {}).items()
                },
            },
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
        self.pulled: list[object] = []

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
            labels=dict(kwargs.get("labels", {})),
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

    def pull(self, image: str, **kwargs: object) -> None:
        self.pulled.append({"image": image, **kwargs})


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
                "materialize_secret_file",
                "pull_image",
                "remove_container",
                "remove_network",
                "remove_volume",
                "run_container",
                "secret_file_digest",
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

    def test_tls_client_creation_uses_docker_client_without_leaking_secret_material(self) -> None:
        fake_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        config = DockerTlsClientConfig(
            endpoint="tcp://mac-mini.local:2376",
            ca_certificate=SecretValue("ca-certificate-secret"),
            client_certificate=SecretValue("client-certificate-secret"),
            client_key=SecretValue("client-key-secret"),
        )

        client = DockerSdkClient(docker_module=fake_module, tls_config=config)

        self.assertIs(client.client, fake_client)
        self.assertEqual(fake_module.from_env_calls, 0)
        self.assertEqual(
            fake_module.docker_clients,
            [
                {
                    "base_url": "tcp://mac-mini.local:2376",
                    "tls": {"tls_config": fake_module.tls.calls[0]},
                }
            ],
        )
        tls_call = fake_module.tls.calls[0]
        self.assertEqual(tls_call["verify"], True)
        self.assertTrue(str(tls_call["ca_cert"]).endswith("ca.pem"))
        self.assertTrue(str(tls_call["client_cert"][0]).endswith("cert.pem"))
        self.assertTrue(str(tls_call["client_cert"][1]).endswith("key.pem"))
        self.assertNotIn("ca-certificate-secret", repr(config))
        self.assertNotIn("client-certificate-secret", repr(client))
        self.assertNotIn("client-key-secret", repr(fake_module.docker_clients))

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
            published_ports={
                "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "49152"}],
                "53/udp": [{"HostIp": "127.0.0.1", "HostPort": "10053"}],
            },
            private_addresses={"cpk-net": "172.18.0.2"},
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
                published_ports=(
                    DockerSdkPublishedPort(
                        53,
                        Transport.UDP,
                        "127.0.0.1",
                        10053,
                    ),
                    DockerSdkPublishedPort(
                        8080,
                        Transport.TCP,
                        "127.0.0.1",
                        49152,
                    ),
                ),
                private_addresses={"cpk-net": "172.18.0.2"},
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
            secret_mounts=(
                DockerSdkSecretMount("/run/secrets/api-token", "cpk-secret"),
            ),
            port_bindings=(
                DockerSdkPortBinding(
                    "internal",
                    Protocol.HTTP,
                    8080,
                    "127.0.0.1",
                    None,
                ),
                DockerSdkPortBinding(
                    "dns",
                    Protocol.DNS_UDP,
                    53,
                    "127.0.0.1",
                    10053,
                ),
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
            [{"image": "ghcr.io/openj92/example@sha256:abc"}],
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
                        },
                        {
                            "Type": "volume",
                            "Source": "cpk-secret",
                            "Target": "/run/secrets/api-token",
                            "ReadOnly": True,
                            "VolumeOptions": {"Subpath": "content"},
                        }
                    ],
                    "command": ["python", "-V"],
                    "ports": {
                        "53/udp": ("127.0.0.1", 10053),
                        "8080/tcp": ("127.0.0.1", 0),
                    },
                }
            ],
        )
        self.assertEqual(
            fake_client.networks.resources["cpk-net"].connections,
            [{"container": "web", "aliases": ["web", "api"]}],
        )
        self.assertTrue(fake_client.containers.resources["web"].started)

    def test_pull_image_passes_bounded_auth_config_to_sdk_boundary(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        auth = DockerRegistryAuthConfig(
            username="cpk",
            password=SecretValue("registry-token-not-for-evidence"),
        )

        sdk.pull_image(
            "ghcr.io/openj92/private@sha256:" + "c" * 64,
            auth_config=auth,
        )

        self.assertEqual(
            fake_client.images.pulled,
            [
                {
                    "image": "ghcr.io/openj92/private@sha256:" + "c" * 64,
                    "auth_config": {
                        "username": "cpk",
                        "password": "registry-token-not-for-evidence",
                    },
                }
            ],
        )
        self.assertNotIn("registry-token-not-for-evidence", repr(auth))
        self.assertNotIn("registry-token-not-for-evidence", repr(sdk))

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

    def test_secret_materialization_uses_bounded_helper_and_digest(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        secret = SecretValue("correct-horse-battery-staple")

        sdk.materialize_secret_file(
            "cpk-secret",
            secret,
            SecretFileMode.OWNER_READ_ONLY,
        )
        digest = sdk.secret_file_digest("cpk-secret")

        helpers = fake_client.containers.created
        self.assertEqual(len(helpers), 2)
        self.assertEqual(helpers[0]["network_disabled"], True)
        self.assertEqual(helpers[0]["read_only"], True)
        self.assertEqual(helpers[0]["cap_drop"], ["ALL"])
        self.assertEqual(helpers[0]["security_opt"], ["no-new-privileges"])
        self.assertEqual(
            helpers[0]["volumes"],
            {"cpk-secret": {"bind": "/artifact", "mode": "rw"}},
        )
        self.assertEqual(
            helpers[1]["volumes"],
            {"cpk-secret": {"bind": "/artifact", "mode": "ro"}},
        )
        self.assertEqual(
            digest,
            hashlib.sha256(secret.reveal().encode("utf-8")).hexdigest(),
        )
        self.assertNotIn(secret.reveal(), repr(fake_client.containers.created))
        self.assertNotIn(secret.reveal(), repr(sdk))
        self.assertTrue(
            all(
                resource.force_removed
                for resource in fake_client.containers.created_containers
            )
        )

    def test_secret_value_is_not_passed_as_helper_command(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        secret = SecretValue("secret-content-not-in-argv")

        sdk.materialize_secret_file(
            "cpk-secret",
            secret,
            SecretFileMode.OWNER_READ_ONLY,
        )

        helper_command = fake_client.containers.created[0]["command"]
        self.assertNotIn(secret.reveal(), helper_command)
        helper = fake_client.containers.created_containers[0]
        with tarfile.open(fileobj=BytesIO(helper.archives["/artifact"]), mode="r") as tar:
            member = tar.extractfile("content")
            self.assertIsNotNone(member)
            assert member is not None
            self.assertEqual(member.read().decode("utf-8"), secret.reveal())
        self.assertEqual(
            helper.execs,
            [["chmod", SecretFileMode.OWNER_READ_ONLY.value, "/artifact/content"]],
        )

    def test_missing_secret_content_returns_absent_digest(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        self.assertIsNone(sdk.secret_file_digest("missing-secret"))

    def test_runtime_endpoint_observations_preserve_private_and_host_context(self) -> None:
        observations = runtime_endpoint_observations(
            subject_id="api",
            graph_id="graph-a",
            private_host="api",
            provider_ports=(
                DockerSdkPortBinding(
                    "internal",
                    Protocol.HTTP,
                    8080,
                    "127.0.0.1",
                    None,
                ),
                DockerSdkPortBinding(
                    "dns-udp",
                    Protocol.DNS_UDP,
                    53,
                    "127.0.0.1",
                    None,
                ),
            ),
            published_ports=(
                DockerSdkPublishedPort(53, Transport.UDP, "127.0.0.1", 10053),
                DockerSdkPublishedPort(8080, Transport.TCP, "127.0.0.1", 49152),
            ),
        )

        self.assertEqual(
            [
                (
                    value.socket_name,
                    value.protocol,
                    value.context,
                    value.address.value,
                )
                for value in observations
            ],
            [
                (
                    "dns-udp",
                    Protocol.DNS_UDP,
                    EndpointContext.RUNTIME_PRIVATE,
                    "dns+udp://api:53",
                ),
                (
                    "dns-udp",
                    Protocol.DNS_UDP,
                    EndpointContext.HOST_LOCAL,
                    "dns+udp://127.0.0.1:10053",
                ),
                (
                    "internal",
                    Protocol.HTTP,
                    EndpointContext.RUNTIME_PRIVATE,
                    "http://api:8080",
                ),
                (
                    "internal",
                    Protocol.HTTP,
                    EndpointContext.HOST_LOCAL,
                    "http://127.0.0.1:49152",
                ),
            ],
        )

    def test_udp_publication_is_not_inferred_from_tcp_publication(self) -> None:
        observations = runtime_endpoint_observations(
            subject_id="dns",
            graph_id="graph-a",
            private_host="dns",
            provider_ports=(
                DockerSdkPortBinding(
                    "dns-udp",
                    Protocol.DNS_UDP,
                    53,
                    "127.0.0.1",
                    None,
                ),
            ),
            published_ports=(
                DockerSdkPublishedPort(53, Transport.TCP, "127.0.0.1", 10053),
            ),
        )

        self.assertEqual(len(observations), 1)
        self.assertIs(observations[0].context, EndpointContext.RUNTIME_PRIVATE)

    def test_publication_postcondition_requires_exact_transport_and_host(self) -> None:
        requested = (
            DockerSdkPortBinding(
                "dns-udp",
                Protocol.DNS_UDP,
                53,
                "127.0.0.1",
                10053,
            ),
        )

        self.assertEqual(
            verify_published_ports(
                requested,
                (
                    DockerSdkPublishedPort(53, Transport.UDP, "127.0.0.1", 10053),
                ),
            ),
            (DockerSdkPublishedPort(53, Transport.UDP, "127.0.0.1", 10053),),
        )
        with self.assertRaisesRegex(RuntimeError, "postcondition"):
            verify_published_ports(
                requested,
                (
                    DockerSdkPublishedPort(53, Transport.TCP, "127.0.0.1", 10053),
                    DockerSdkPublishedPort(53, Transport.UDP, "0.0.0.0", 10053),
                ),
            )


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
