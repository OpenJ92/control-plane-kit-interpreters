from __future__ import annotations

from dataclasses import replace
from io import BytesIO
import hashlib
import os
from pathlib import Path
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
    DockerLocalAmbientClientConfig,
    DockerRegistryAuthConfig,
    DockerSdkBindMount,
    DockerSdkClient,
    DockerSdkConfigurationMount,
    DockerSdkImageInspection,
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
    def __init__(
        self,
        tags: list[str],
        *,
        image_id: str = "sha256:" + "b" * 64,
        repo_digests: tuple[str, ...] = (),
    ) -> None:
        self.tags = tags
        self.id = image_id
        self.attrs = {"RepoDigests": list(repo_digests)}


class FakeResource:
    def __init__(
        self,
        name: str,
        *,
        labels: dict[str, str] | None = None,
        image: str | None = None,
        image_id: str = "sha256:" + "b" * 64,
        running: bool = False,
        published_ports: dict[str, object] | None = None,
        private_addresses: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.image = FakeImage([image], image_id=image_id) if image else None
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
        self.wait_result: object = {"StatusCode": 0}
        self.log_output: bytes = b"200 3\n"

    def start(self) -> None:
        self.started = True
        self.attrs["State"]["Running"] = True

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

    def wait(self, *, timeout: int | None = None) -> object:
        return self.wait_result

    def logs(self, *, stdout: bool, stderr: bool, tail: int) -> bytes:
        return self.log_output

    def connect(self, container: FakeResource, *, aliases: list[str]) -> None:
        self.connections.append({"container": container.name, "aliases": aliases})
        container.attrs["NetworkSettings"]["Networks"][self.name] = {
            "IPAddress": ""
        }


MALFORMED_CONTAINER_STATES = (
    "attrs-missing", "attrs-none", "attrs-list", "attrs-text",
    "state-missing", "state-none", "state-list", "state-text",
    "running-missing", "running-none", "running-text", "running-zero", "running-one",
)
MISLEADING_CONTAINER_STATUSES = ("running", "exited", "unknown")


class StateInspectionResource(FakeResource):
    def __init__(self, *args, misleading_status: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.misleading_status = misleading_status
        self.status_reads = 0

    @property
    def status(self) -> str:
        self.status_reads += 1
        return self.misleading_status


def malform_container_state(resource: FakeResource, case: str) -> None:
    if case == "attrs-missing":
        del resource.attrs
    elif case.startswith("attrs-"):
        resource.attrs = {"attrs-none": None, "attrs-list": [], "attrs-text": "provider-state"}[case]
    elif case == "state-missing":
        del resource.attrs["State"]
    elif case.startswith("state-"):
        resource.attrs["State"] = {"state-none": None, "state-list": [], "state-text": "provider-state"}[case]
    elif case == "running-missing":
        del resource.attrs["State"]["Running"]
    else:
        resource.attrs["State"]["Running"] = {
            "running-none": None, "running-text": "false", "running-zero": 0, "running-one": 1,
        }[case]


class FakeManager:
    def __init__(self) -> None:
        self.resources: dict[str, FakeResource] = {}
        self.created: list[dict[str, object]] = []
        self.created_containers: list[FakeResource] = []
        self.volume_archives: dict[str, dict[str, bytes]] = {}
        self.pulled: list[object] = []
        self.get_error: Exception | None = None

    def get(self, name: str) -> FakeResource:
        if self.get_error is not None:
            raise self.get_error
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
        network = kwargs.get("network")
        resource = FakeResource(
            str(kwargs["name"]),
            labels=dict(kwargs.get("labels", {})),
            image=image,
            running=False,
            private_addresses={str(network): ""} if network is not None else {},
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
        self.resources[image] = FakeImage([], repo_digests=(image,))


class FakeDockerClient:
    def __init__(self) -> None:
        self.api = FakeDockerApi()
        self.networks = FakeManager()
        self.volumes = FakeManager()
        self.images = FakeManager()
        self.containers = FakeManager()
        self.containers.create = self.containers.create_container
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakeDockerApi:
    def create_endpoint_config(self, *, aliases: list[str]) -> dict[str, object]:
        return {"Aliases": aliases}


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
                "close",
                "create_network",
                "create_volume",
                "from_authority",
                "inspect_container",
                "inspect_image",
                "inspect_network",
                "inspect_volume",
                "materialize_configuration_artifact",
                "materialize_secret_file",
                "pull_image",
                "remove_container",
                "remove_network",
                "remove_volume",
                "run_http_probe",
                "run_container",
                "create_container",
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

    def test_http_probe_runs_bounded_helper_in_runtime_network(self) -> None:
        fake_client = FakeDockerClient()
        client = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        result = client.run_http_probe(
            network="cpk-net-workspace-docker",
            url="http://hello:8000/health/ready",
            timeout_seconds=5.0,
            maximum_response_bytes=128,
        )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.response_size, 3)
        self.assertEqual(result.exit_code, 0)
        helper = fake_client.containers.created[0]
        self.assertEqual(helper["network"], "cpk-net-workspace-docker")
        self.assertEqual(helper["read_only"], True)
        self.assertEqual(helper["cap_drop"], ["ALL"])
        self.assertEqual(helper["security_opt"], ["no-new-privileges"])
        self.assertIn("http://hello:8000/health/ready", helper["command"])
        self.assertTrue(fake_client.containers.created_containers[0].force_removed)

    def test_client_creation_lazily_uses_docker_from_env(self) -> None:
        fake_client = FakeDockerClient()
        client = DockerSdkClient(docker_module=FakeDockerModule(fake_client))

        self.assertIs(client.client, fake_client)

    def test_from_authority_can_defer_local_ambient_connection_until_effect(self) -> None:
        fake_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        client = DockerSdkClient.from_authority(
            DockerLocalAmbientClientConfig(),
            docker_module=fake_module,
            connect_on_init=False,
        )

        self.assertIsNone(client.client)
        self.assertEqual(fake_module.from_env_calls, 0)

        self.assertIsNone(client.inspect_network("missing"))

        self.assertIs(client.client, fake_client)
        self.assertEqual(fake_module.from_env_calls, 1)

    def test_tls_client_creation_uses_docker_client_without_leaking_secret_material(self) -> None:
        fake_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        config = DockerTlsClientConfig(
            endpoint="tcp://mac-mini.local:2376",
            ca_certificate=SecretValue("ca-certificate-secret"),
            client_certificate=SecretValue("client-certificate-secret"),
            client_key=SecretValue("client-key-secret"),
        )

        client = DockerSdkClient.from_authority(
            config,
            docker_module=fake_module,
        )

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

    def test_tls_client_close_removes_credentials_and_closes_sdk_once(self) -> None:
        fake_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        client = DockerSdkClient.from_authority(
            DockerTlsClientConfig(
                endpoint="tcp://mac-mini.local:2376",
                ca_certificate=SecretValue("ca-certificate-secret"),
                client_certificate=SecretValue("client-certificate-secret"),
                client_key=SecretValue("client-key-secret"),
            ),
            docker_module=fake_module,
        )
        tls_call = fake_module.tls.calls[0]
        paths = (
            Path(str(tls_call["ca_cert"])),
            Path(str(tls_call["client_cert"][0])),
            Path(str(tls_call["client_cert"][1])),
        )
        directory = paths[0].parent

        self.assertTrue(directory.is_dir())
        for path in paths:
            self.assertTrue(path.is_file())
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

        client.close()
        client.close()

        self.assertEqual(fake_client.close_calls, 1)
        self.assertIsNone(client.client)
        self.assertIsNone(client.tls_config)
        self.assertFalse(directory.exists())
        for path in paths:
            self.assertFalse(path.exists())
            self.assertNotIn(str(path), repr(client))

    def test_missing_resources_are_absent_only_for_sdk_not_found_errors(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        self.assertIsNone(sdk.inspect_network("missing"))
        self.assertIsNone(sdk.inspect_volume("missing"))
        self.assertIsNone(sdk.inspect_container("missing"))

        inspect_image = getattr(sdk, "inspect_image", None)
        self.assertTrue(callable(inspect_image))
        self.assertIsNone(inspect_image("ghcr.io/openj92/missing@sha256:" + "a" * 64))

    def test_image_absence_does_not_swallow_non_not_found_sdk_errors(self) -> None:
        fake_client = FakeDockerClient()
        fake_client.images.get_error = TimeoutError("daemon transport detail")
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        inspect_image = getattr(sdk, "inspect_image", None)

        self.assertTrue(callable(inspect_image))
        with self.assertRaises(TimeoutError):
            inspect_image("ghcr.io/openj92/example@sha256:" + "a" * 64)

    def test_exact_reference_image_inspection_normalizes_id_and_repo_digests(self) -> None:
        reference = "ghcr.io/openj92/example@sha256:" + "a" * 64
        image_id = "sha256:" + "b" * 64
        fake_client = FakeDockerClient()
        fake_client.images.resources[reference] = FakeImage(
            [],
            image_id=image_id,
            repo_digests=(reference, "ghcr.io/openj92/foreign@sha256:" + "c" * 64),
        )
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        inspect_image = getattr(sdk, "inspect_image", None)

        self.assertTrue(callable(inspect_image))
        inspection = inspect_image(reference)
        self.assertEqual(getattr(inspection, "image_id", None), image_id)
        self.assertEqual(
            getattr(inspection, "repo_digests", None),
            (
                reference,
                "ghcr.io/openj92/foreign@sha256:" + "c" * 64,
            ),
        )

    def test_image_inspection_rejects_noncanonical_provider_image_ids(self) -> None:
        reference = "ghcr.io/openj92/example@sha256:" + "a" * 64
        cases = (
            "sha256:" + "B" * 64,
            "sha256:" + "b" * 63,
            "sha256:" + "b" * 65,
            "sha256:" + "g" * 64,
        )
        for image_id in cases:
            with self.subTest(image_id=image_id):
                with self.assertRaises(ValueError):
                    DockerSdkImageInspection(image_id, (reference,))

                fake_client = FakeDockerClient()
                fake_client.images.resources[reference] = FakeImage(
                    [],
                    image_id=image_id,
                    repo_digests=(reference,),
                )
                sdk = DockerSdkClient(
                    client=fake_client,
                    docker_module=FakeDockerModule(fake_client),
                )

                with self.assertRaises(RuntimeError):
                    sdk.inspect_image(reference)

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
                image_id="sha256:" + "b" * 64,
                network_names=("cpk-net",),
            ),
        )

    def test_container_inspection_rejects_ambiguous_image_identity(self) -> None:
        cases = (
            ("missing", None),
            ("blank", " "),
            ("malformed", "sha256:not-a-digest"),
            ("wrong-length", "sha256:" + "a" * 63),
        )
        for name, image_id in cases:
            with self.subTest(case=name):
                fake_client = FakeDockerClient()
                resource = FakeResource(
                    "web",
                    image="ghcr.io/openj92/example@sha256:" + "a" * 64,
                    image_id=image_id,
                )
                if name == "missing":
                    del resource.image.id
                fake_client.containers.resources["web"] = resource
                sdk = DockerSdkClient(
                    client=fake_client,
                    docker_module=FakeDockerModule(fake_client),
                )

                with self.assertRaisesRegex(
                    RuntimeError,
                    "Docker container image inspection was malformed",
                ):
                    sdk.inspect_container("web")

    def test_container_inspection_rejects_unknown_state_without_status_fallback(self) -> None:
        for case in MALFORMED_CONTAINER_STATES:
            for status in MISLEADING_CONTAINER_STATUSES:
                with self.subTest(case=case, status=status):
                    raw = FakeDockerClient()
                    resource = StateInspectionResource(
                        "web", image="ghcr.io/openj92/example@sha256:" + "a" * 64,
                        misleading_status=status,
                    )
                    malform_container_state(resource, case)
                    raw.containers.resources["web"] = resource
                    sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
                    caught = None
                    try:
                        sdk.inspect_container("web")
                    except RuntimeError as error:
                        caught = error
                    with self.subTest(boundary="reject-malformed-state"):
                        self.assertIsNotNone(caught)
                        self.assertIs(type(caught), RuntimeError)
                        self.assertEqual(caught.args, ("Docker container state inspection was malformed",))
                    with self.subTest(boundary="never-read-status"):
                        self.assertEqual(resource.status_reads, 0)
                    self.assertFalse(resource.started or resource.stopped or resource.removed)

    def test_container_inspection_uses_only_exact_boolean_running(self) -> None:
        for running in (True, False):
            for status in MISLEADING_CONTAINER_STATUSES:
                with self.subTest(running=running, status=status):
                    raw = FakeDockerClient()
                    resource = StateInspectionResource(
                        "web", image="ghcr.io/openj92/example@sha256:" + "a" * 64,
                        running=running, misleading_status=status,
                    )
                    raw.containers.resources["web"] = resource
                    sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
                    inspection = sdk.inspect_container("web")
                    self.assertIs(inspection.running, running)
                    self.assertEqual(resource.status_reads, 0)
                    self.assertFalse(resource.started or resource.stopped or resource.removed)

    def test_resource_inspection_equality_includes_runtime_identity(self) -> None:
        inspection = DockerSdkResourceInspection(
            name="web",
            running=True,
            image="ghcr.io/openj92/example@sha256:" + "a" * 64,
            labels={"cpk.owner": "workspace-a"},
            image_id="sha256:" + "b" * 64,
            network_names=("cpk-net",),
        )

        self.assertNotEqual(
            inspection,
            replace(inspection, image_id="sha256:" + "c" * 64),
        )
        self.assertNotEqual(
            inspection,
            replace(inspection, network_names=("foreign-net",)),
        )

    def test_create_container_attaches_exact_intended_network_and_aliases(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        create_container = getattr(sdk, "create_container", None)

        self.assertTrue(callable(create_container))
        try:
            create_container(
                name="web",
                image="ghcr.io/openj92/example@sha256:" + "a" * 64,
                environment={"PORT": "8080"},
                labels={"cpk.workspace": "w"},
                volumes={},
                network="cpk-net",
                aliases=("web", "api"),
            )
        except TypeError:
            self.fail("create_container lacks exact network attachment material")
        created = fake_client.containers.created[0]
        self.assertEqual(created["network"], "cpk-net")
        self.assertEqual(
            created["networking_config"],
            {
                "cpk-net": {"Aliases": ["web", "api"]},
            },
        )
        self.assertNotIn("network_mode", created)
        self.assertNotIn("network_disabled", created)
        self.assertEqual(
            tuple(
                fake_client.containers.resources["web"]
                .attrs["NetworkSettings"]["Networks"]
            ),
            ("cpk-net",),
        )
        self.assertFalse(fake_client.containers.resources["web"].started)

    def test_start_container_is_distinct_from_create_with_network(self) -> None:
        fake_client = FakeDockerClient()
        fake_client.containers.resources["web"] = FakeResource("web")
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )

        sdk.start_container("web")

        self.assertTrue(fake_client.containers.resources["web"].started)
        self.assertEqual(fake_client.networks.created, [])

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

    def test_bind_mounts_are_explicit_create_container_material(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        sdk.create_network(name="cpk-net", labels={"cpk.workspace": "w"})

        sdk.run_container(
            name="web",
            image="ghcr.io/openj92/example@sha256:abc",
            network="cpk-net",
            aliases=("web",),
            environment={},
            labels={"cpk.workspace": "w"},
            volumes={},
            bind_mounts=(
                DockerSdkBindMount(
                    "/var/run/docker.sock",
                    "/var/run/docker.sock",
                    read_only=False,
                ),
            ),
            supplementary_groups=("987",),
        )

        self.assertEqual(
            fake_client.containers.created[0]["mounts"],
            [
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Target": "/var/run/docker.sock",
                    "ReadOnly": False,
                }
            ],
        )
        self.assertEqual(fake_client.containers.created[0]["group_add"], ["987"])

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
