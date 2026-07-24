from __future__ import annotations

import socket
import unittest

import httpx

from control_plane_kit_core.algebra import BlockSockets, ProviderSocket
from control_plane_kit_core.configuration import (
    ConfigurationArtifact,
    ConfigurationFileMode,
    ConfigurationMediaType,
)
from control_plane_kit_core.environment import (
    PublicStaticEnvironmentBinding,
    SocketDerivedEnvironmentBinding,
)
from control_plane_kit_core.operations.execution import EffectResultKind
from control_plane_kit_core.planning import (
    ActivityId,
    NodeTarget,
    ReconcileNode,
    ReconcileRuntime,
    RuntimeTarget,
    StartNode,
    StartRuntime,
    RemoveRuntimeResource,
    StopNode,
    WaitForHealthy,
)
from control_plane_kit_core.products import (
    ContainerServerProduct,
    OciImageReference,
    ProductDescriptorDigest,
    ProductIdentity,
    ProductReference,
    ProductRuntimeContract,
    ProviderRuntimePort,
)
from control_plane_kit_core.runtime_effects import (
    ImagePullAuthority,
    RuntimeEffectKind,
    RuntimeEffectRequest,
    RuntimeEffectSource,
    RuntimeProductMaterial,
)
from control_plane_kit_core.secrets import (
    SecretEnvironmentDelivery,
    SecretFileDelivery,
    SecretFileMode,
    SecretFilePathBinding,
    SecretMissing,
    SecretProviderAuthority,
    SecretProviderId,
    SecretReference,
    SecretResolved,
    SecretResolution,
    SecretValue,
)
from control_plane_kit_core.types import Protocol, RuntimeKind
from control_plane_kit_core.verification import HttpCheck, VerificationContract
from control_plane_kit_core.verification import (
    PostgresPasswordAuthentication,
    PostgresQueryCheck,
    RedisCheck,
    VerificationPolicy,
)

from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter, DockerSdkClient
from control_plane_kit_interpreters.secrets import (
    ImagePullCredentialDenied,
    ImagePullCredentialMissing,
    ImagePullCredentialResolved,
    ResolvedImagePullCredential,
)
from test_docker_sdk_client import (
    FakeDockerClient,
    FakeDockerModule,
    FakeResource,
)


class DockerRuntimeInterpreterTests(unittest.TestCase):
    def test_start_runtime_creates_owned_network_without_product_material(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute(
            _request(StartRuntime(RuntimeTarget("docker")), products=())
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "created")
        created = fake_client.networks.created[0]
        self.assertEqual(created["labels"]["org.openj92.cpk.kind"], "runtime-network")
        self.assertEqual(created["labels"]["org.openj92.cpk.runtime"], "docker")

    def test_reconcile_runtime_reuses_owned_network_from_prior_graph(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        interpreter.execute(_request(StartRuntime(RuntimeTarget("docker")), products=()))

        result = interpreter.execute(
            _request(
                ReconcileRuntime(RuntimeTarget("docker")),
                products=(),
                desired_graph_id="graph-updated",
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "reused")
        self.assertEqual(len(fake_client.networks.created), 1)

    def test_remove_runtime_removes_only_owned_runtime_network_from_prior_graph(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        first = interpreter.execute(_request(StartRuntime(RuntimeTarget("docker")), products=()))
        network = fake_client.networks.resources[str(first.evidence["network"])]

        result = interpreter.execute(
            _request(
                RemoveRuntimeResource(RuntimeTarget("docker")),
                products=(),
                desired_graph_id="graph-empty",
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "removed")
        self.assertTrue(network.removed)

    def test_start_node_pulls_digest_image_creates_network_container_and_observations(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute(_request(StartNode(NodeTarget("api"))))

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "created")
        self.assertEqual(
            fake_client.images.pulled,
            [{"image": "ghcr.io/openj92/runtime-fixture@sha256:" + "a" * 64}],
        )
        container = _workload_container_record(fake_client)
        self.assertEqual(
            container["image"],
            "ghcr.io/openj92/runtime-fixture@sha256:" + "a" * 64,
        )
        self.assertEqual(container["environment"], {"PORT": "8080"})
        self.assertEqual(container["ports"], {})
        self.assertEqual(container["labels"]["org.openj92.cpk.node"], "api")
        self.assertEqual(
            [
                (
                    observation.subject_id,
                    observation.socket_name,
                    observation.address.value,
                )
                for observation in result.observations
            ],
            [("api", "http", "http://api:8080")],
        )

    def test_start_node_passes_socket_derived_environment_to_container(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        socket_environment=(
                            SocketDerivedEnvironmentBinding(
                                "UPSTREAM_URL",
                                "http://upstream:8080",
                                "upstream.internal->api.upstream",
                            ),
                        ),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        container = _workload_container_record(fake_client)
        self.assertEqual(
            container["environment"],
            {
                "PORT": "8080",
                "UPSTREAM_URL": "http://upstream:8080",
            },
        )

    def test_start_node_uses_selected_public_environment_material(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        public_environment=(
                            PublicStaticEnvironmentBinding("PORT", "9090"),
                        ),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        container = _workload_container_record(fake_client)
        self.assertEqual(container["environment"], {"PORT": "9090"})

    def test_start_node_uses_existing_owned_runtime_network_from_prior_graph(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        interpreter.execute(_request(StartRuntime(RuntimeTarget("docker")), products=()))

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                desired_graph_id="graph-updated",
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "created")
        self.assertEqual(len(fake_client.networks.created), 1)

    def test_reconcile_node_recreates_owned_container_when_material_changes(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        first = interpreter.execute(_request(StartNode(NodeTarget("api"))))
        existing = fake_client.containers.resources[str(first.evidence["container"])]

        result = interpreter.execute(
            _request(
                ReconcileNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        socket_environment=(
                            SocketDerivedEnvironmentBinding(
                                "UPSTREAM_URL",
                                "http://replacement:8080",
                                "replacement.internal->api.upstream",
                            ),
                        ),
                    ),
                ),
                desired_graph_id="graph-updated",
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "recreated")
        self.assertTrue(existing.force_removed)
        self.assertEqual(len(_workload_container_records(fake_client)), 2)
        self.assertEqual(
            _workload_container_records(fake_client)[-1]["environment"],
            {
                "PORT": "8080",
                "UPSTREAM_URL": "http://replacement:8080",
            },
        )

    def test_existing_owned_container_is_started_without_recreation(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        first = interpreter.execute(_request(StartNode(NodeTarget("api"))))
        container_name = first.evidence["container"]
        existing = fake_client.containers.resources[str(container_name)]
        existing.attrs["State"]["Running"] = False

        second = interpreter.execute(_request(StartNode(NodeTarget("api"))))

        self.assertIs(second.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(second.evidence["action"], "started")
        self.assertTrue(existing.started)
        self.assertEqual(len(_workload_container_records(fake_client)), 1)

    def test_unowned_container_conflict_fails_before_mutation(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        request = _request(StartNode(NodeTarget("api")))
        first = interpreter.execute(request)
        container_name = str(first.evidence["container"])
        fake_client.containers.resources[container_name].attrs["Config"]["Labels"] = {
            "org.openj92.cpk.fingerprint": "foreign",
        }
        fake_client.images.pulled.clear()

        result = interpreter.execute(request)

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.container-ownership-conflict")
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(len(_workload_container_records(fake_client)), 1)

    def test_stop_node_stops_only_owned_container(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        first = interpreter.execute(_request(StartNode(NodeTarget("api"))))
        container = fake_client.containers.resources[str(first.evidence["container"])]
        container.attrs["State"]["Running"] = True

        result = interpreter.execute(_request(StopNode(NodeTarget("api"))))

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "stopped")
        self.assertTrue(container.stopped)

    def test_secret_bearing_product_is_explicitly_failed_without_secret_material(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(_material(_product_with_secret_delivery()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.secret-resolution-required")
        self.assertEqual(fake_client.networks.created, [])
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(fake_client.containers.created, [])

    def test_start_node_resolves_secret_environment_before_docker_mutation(self) -> None:
        fake_client = FakeDockerClient()
        resolver = FakeSecretResolver(
            fake_client,
            SecretResolved(
                SecretReference("secret://local/api-token"),
                SecretValue("resolved-api-token"),
            ),
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            secret_resolver=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(_material(_product_with_secret_delivery()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, ["secret://local/api-token"])
        self.assertEqual(resolver.networks_created_during_resolution, [0])
        container = _workload_container_record(fake_client)
        self.assertEqual(
            container["environment"],
            {
                "API_TOKEN": "resolved-api-token",
                "PORT": "8080",
            },
        )
        self.assertNotIn("resolved-api-token", repr(result))

    def test_start_node_missing_secret_fails_before_docker_mutation(self) -> None:
        fake_client = FakeDockerClient()
        resolver = FakeSecretResolver(
            fake_client,
            SecretMissing(SecretReference("secret://local/api-token")),
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            secret_resolver=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(_material(_product_with_secret_delivery()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.secret-resolution-missing")
        self.assertEqual(fake_client.networks.created, [])
        self.assertEqual(fake_client.volumes.created, [])
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(fake_client.containers.created, [])

    def test_start_node_resolves_file_secret_as_read_only_mount(self) -> None:
        fake_client = FakeDockerClient()
        resolver = FakeSecretResolver(
            fake_client,
            SecretResolved(
                SecretReference("secret://local/api-token"),
                SecretValue("file-secret-content"),
            ),
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            secret_resolver=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(_material(_product_with_file_secret_delivery()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        secret_volumes = [
            volume
            for volume in fake_client.volumes.created
            if volume["labels"]["org.openj92.cpk.volume.kind"] == "secret-file"
        ]
        self.assertEqual(len(secret_volumes), 1)
        self.assertNotIn("file-secret-content", repr(secret_volumes))
        container = _workload_container_record(fake_client)
        self.assertEqual(
            container["environment"],
            {
                "API_TOKEN_FILE": "/run/secrets/api-token",
                "PORT": "8080",
            },
        )
        secret_mounts = [
            mount
            for mount in container["mounts"]
            if mount["Target"] == "/run/secrets/api-token"
        ]
        self.assertEqual(
            secret_mounts,
            [
                {
                    "Type": "volume",
                    "Source": secret_volumes[0]["name"],
                    "Target": "/run/secrets/api-token",
                    "ReadOnly": True,
                    "VolumeOptions": {"Subpath": "content"},
                }
            ],
        )
        self.assertNotIn("file-secret-content", repr(result))

    def test_start_node_resolves_pull_authority_before_image_pull(self) -> None:
        fake_client = FakeDockerClient()
        resolver = FakeImagePullCredentialResolver(
            ImagePullCredentialResolved(
                ResolvedImagePullCredential(
                    username="cpk",
                    password=SecretValue("private-registry-token"),
                )
            )
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            image_pull_credentials=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        pull_authority=ImagePullAuthority(
                            "ghcr.io",
                            "openj92/runtime-fixture",
                            SecretReference("secret://registry/ghcr/runtime-fixture"),
                        ),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(
            fake_client.images.pulled,
            [
                {
                    "image": "ghcr.io/openj92/runtime-fixture@sha256:" + "a" * 64,
                    "auth_config": {
                        "username": "cpk",
                        "password": "private-registry-token",
                    },
                }
            ],
        )
        self.assertEqual(
            resolver.requests,
            ["secret://registry/ghcr/runtime-fixture"],
        )
        self.assertNotIn("private-registry-token", repr(result))

    def test_start_node_requires_resolver_when_pull_authority_is_present(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        pull_authority=ImagePullAuthority(
                            "ghcr.io",
                            "openj92/runtime-fixture",
                            SecretReference("secret://registry/ghcr/runtime-fixture"),
                        ),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.image-pull-authority-required")
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(fake_client.containers.created, [])


    def test_start_node_missing_pull_credential_fails_before_container_creation(self) -> None:
        fake_client = FakeDockerClient()
        resolver = FakeImagePullCredentialResolver(
            ImagePullCredentialMissing(
                SecretReference("secret://registry/ghcr/runtime-fixture")
            )
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            image_pull_credentials=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        pull_authority=ImagePullAuthority(
                            "ghcr.io",
                            "openj92/runtime-fixture",
                            SecretReference("secret://registry/ghcr/runtime-fixture"),
                        ),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.image-pull-credential-missing")
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(fake_client.containers.created, [])

    def test_start_node_denied_pull_credential_fails_before_container_creation(self) -> None:
        fake_client = FakeDockerClient()
        resolver = FakeImagePullCredentialResolver(
            ImagePullCredentialDenied(SecretReference("secret://registry/ghcr/runtime-fixture"))
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            image_pull_credentials=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        pull_authority=ImagePullAuthority(
                            "ghcr.io",
                            "openj92/runtime-fixture",
                            SecretReference("secret://registry/ghcr/runtime-fixture"),
                        ),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.image-pull-credential-denied")
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(fake_client.containers.created, [])

    def test_start_node_wrong_scope_pull_authority_fails_closed(self) -> None:
        fake_client = FakeDockerClient()
        resolver = FakeImagePullCredentialResolver(
            ImagePullCredentialResolved(
                ResolvedImagePullCredential(
                    username="cpk",
                    password=SecretValue("private-registry-token"),
                )
            )
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            image_pull_credentials=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        pull_authority=ImagePullAuthority(
                            "ghcr.io",
                            "openj92/other",
                            SecretReference("secret://registry/ghcr/other"),
                        ),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.image-pull-authority-scope-mismatch")
        self.assertEqual(resolver.requests, [])
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(fake_client.containers.created, [])

    def test_wait_for_healthy_executes_http_verification_against_runtime_endpoint(self) -> None:
        fake_client = FakeDockerClient()
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            return httpx.Response(200, text="ok")

        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            http_transport=httpx.MockTransport(handler),
        )

        result = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_health_check()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "verified-healthy")
        self.assertEqual(requests, ["http://api:8080/health/ready"])
        self.assertEqual(
            result.evidence["checks"][0]["outcome"],
            "passed",
        )

    def test_wait_for_healthy_fails_when_http_verification_fails(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            http_transport=httpx.MockTransport(
                lambda request: httpx.Response(503, text="not ready")
            ),
        )

        result = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_health_check()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.health-check-failed")
        self.assertEqual(result.failure.details["checks"][0]["outcome"], "failed")

    def test_wait_for_healthy_executes_postgres_verification_with_secret(self) -> None:
        fake_client = FakeDockerClient()
        transport = FakePostgresTransport([True])
        resolver = FakeSecretResolver(
            fake_client,
            SecretResolved(
                SecretReference("secret://local/postgres/password"),
                SecretValue("postgres-secret"),
            ),
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            postgres_transport=transport,
            secret_resolver=resolver,
        )

        result = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_postgres_health_check()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "verified-healthy")
        self.assertEqual(
            transport.calls,
            [("api", 5432, "cpk", "cpk", "postgres-secret", 5.0)],
        )
        self.assertEqual(resolver.requests, ["secret://local/postgres/password"])
        self.assertEqual(result.evidence["checks"][0]["outcome"], "passed")
        self.assertNotIn("postgres-secret", repr(result))

    def test_wait_for_healthy_fails_when_postgres_verification_fails(self) -> None:
        fake_client = FakeDockerClient()
        transport = FakePostgresTransport([socket.timeout()])
        resolver = FakeSecretResolver(
            fake_client,
            SecretResolved(
                SecretReference("secret://local/postgres/password"),
                SecretValue("postgres-secret"),
            ),
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            postgres_transport=transport,
            secret_resolver=resolver,
        )

        result = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_postgres_health_check()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.health-check-failed")
        self.assertEqual(result.failure.details["checks"][0]["outcome"], "timed-out")
        self.assertNotIn("postgres-secret", repr(result))

    def test_wait_for_healthy_rejects_unsupported_verification_kind(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_redis_health_check()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.UNSUPPORTED)
        self.assertEqual(result.failure.code, "docker.health-check-unsupported")



class FakeImagePullCredentialResolver:
    def __init__(self, result) -> None:
        self.result = result
        self.requests: list[str] = []

    def resolve(self, authority: ImagePullAuthority):
        self.requests.append(authority.credential_reference.reference_id)
        return self.result


class FakeSecretResolver:
    authority = SecretProviderAuthority(
        SecretProviderId("local"),
        (("api-token",),),
    )

    def __init__(self, fake_client: FakeDockerClient, result: SecretResolution) -> None:
        self.fake_client = fake_client
        self.result = result
        self.requests: list[str] = []
        self.networks_created_during_resolution: list[int] = []

    def resolve(self, reference: SecretReference) -> SecretResolution:
        self.requests.append(reference.reference_id)
        self.networks_created_during_resolution.append(
            len(self.fake_client.networks.created)
        )
        return self.result


class FakePostgresTransport:
    def __init__(self, results: list[bool | Exception]) -> None:
        self.results = results
        self.calls: list[tuple[str, int, str, str, str, float]] = []

    def select_one(
        self,
        target,
        *,
        database: str,
        username: str,
        password: SecretValue,
        timeout_seconds: float,
    ) -> bool:
        self.calls.append(
            (
                target.connect_host,
                target.port,
                database,
                username,
                password.reveal(),
                timeout_seconds,
            )
        )
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _request(
    operation,
    *,
    products: tuple[RuntimeProductMaterial, ...] | None = None,
    desired_graph_id: str = "graph-desired",
) -> RuntimeEffectRequest:
    return RuntimeEffectRequest(
        effect_id="effect-a",
        kind=RuntimeEffectKind.REALIZE_ACTIVITY,
        runtime_kind=RuntimeKind.DOCKER,
        source=RuntimeEffectSource(
            workspace_id="workspace-a",
            request_id="request-a",
            run_id="run-a",
            plan_id="plan-a",
            base_graph_id="graph-base",
            desired_graph_id=desired_graph_id,
            intent_event_id="event-started",
        ),
        activity_id=ActivityId("activity-a"),
        operation=operation,
        products=(_material(_product()),) if products is None else products,
    )


def _material(
    product: ContainerServerProduct,
    *,
    public_environment: tuple[PublicStaticEnvironmentBinding, ...] | None = None,
    socket_environment: tuple[SocketDerivedEnvironmentBinding, ...] = (),
    pull_authority: ImagePullAuthority | None = None,
) -> RuntimeProductMaterial:
    reference = ProductReference(
        product.identity,
        ProductDescriptorDigest("b" * 64),
    )
    return RuntimeProductMaterial(
        node_id="api",
        runtime_id="docker",
        reference=reference,
        product=product,
        public_environment=(
            product.runtime_contract.public_environment
            if public_environment is None
            else public_environment
        ),
        socket_environment=socket_environment,
        pull_authority=pull_authority,
    )


def _product() -> ContainerServerProduct:
    return ContainerServerProduct(
        identity=ProductIdentity("openj92", "runtime-fixture", 1),
        image=OciImageReference(
            registry="ghcr.io",
            repository="openj92/runtime-fixture",
            digest="sha256:" + "a" * 64,
        ),
        runtime_contract=ProductRuntimeContract(
            sockets=BlockSockets(
                providers=(ProviderSocket("http", Protocol.HTTP),),
            ),
            provider_ports=(ProviderRuntimePort("http", 8080),),
            public_environment=(PublicStaticEnvironmentBinding("PORT", "8080"),),
            configuration_artifacts=(_artifact(),),
        ),
    )


def _product_with_health_check() -> ContainerServerProduct:
    product = _product()
    return ContainerServerProduct(
        identity=product.identity,
        image=product.image,
        runtime_contract=ProductRuntimeContract(
            sockets=product.runtime_contract.sockets,
            provider_ports=product.runtime_contract.provider_ports,
            public_environment=product.runtime_contract.public_environment,
            configuration_artifacts=product.runtime_contract.configuration_artifacts,
            verification=VerificationContract(
                (
                    HttpCheck(
                        check_id="ready",
                        provider_socket="http",
                        path="/health/ready",
                    ),
                ),
            ),
        ),
    )


def _product_with_postgres_health_check() -> ContainerServerProduct:
    product = _product()
    return ContainerServerProduct(
        identity=product.identity,
        image=product.image,
        runtime_contract=ProductRuntimeContract(
            sockets=BlockSockets(
                providers=(ProviderSocket("postgres", Protocol.POSTGRES),),
            ),
            provider_ports=(ProviderRuntimePort("postgres", 5432),),
            public_environment=product.runtime_contract.public_environment,
            verification=VerificationContract(
                (
                    PostgresQueryCheck(
                        check_id="select-one",
                        provider_socket="postgres",
                        authentication=PostgresPasswordAuthentication(
                            database="cpk",
                            username="cpk",
                            password_reference=SecretReference(
                                "secret://local/postgres/password"
                            ),
                        ),
                        policy=VerificationPolicy(timeout_seconds=5.0),
                    ),
                ),
            ),
        ),
    )


def _product_with_redis_health_check() -> ContainerServerProduct:
    product = _product()
    return ContainerServerProduct(
        identity=product.identity,
        image=product.image,
        runtime_contract=ProductRuntimeContract(
            sockets=BlockSockets(
                providers=(ProviderSocket("redis", Protocol.REDIS),),
            ),
            provider_ports=(ProviderRuntimePort("redis", 6379),),
            public_environment=product.runtime_contract.public_environment,
            verification=VerificationContract(
                (
                    RedisCheck(
                        check_id="redis-ping",
                        provider_socket="redis",
                    ),
                ),
            ),
        ),
    )


def _product_with_secret_delivery() -> ContainerServerProduct:
    product = _product()
    return ContainerServerProduct(
        identity=product.identity,
        image=product.image,
        runtime_contract=ProductRuntimeContract(
            sockets=product.runtime_contract.sockets,
            provider_ports=product.runtime_contract.provider_ports,
            public_environment=product.runtime_contract.public_environment,
            secret_deliveries=(
                SecretEnvironmentDelivery(
                    "API_TOKEN",
                    SecretReference("secret://local/api-token"),
                ),
            ),
        ),
    )


def _product_with_file_secret_delivery() -> ContainerServerProduct:
    product = _product()
    return ContainerServerProduct(
        identity=product.identity,
        image=product.image,
        runtime_contract=ProductRuntimeContract(
            sockets=product.runtime_contract.sockets,
            provider_ports=product.runtime_contract.provider_ports,
            public_environment=product.runtime_contract.public_environment,
            secret_deliveries=(
                SecretFileDelivery(
                    "/run/secrets/api-token",
                    SecretReference("secret://local/api-token"),
                    SecretFileMode.OWNER_READ_ONLY,
                    SecretFilePathBinding("API_TOKEN_FILE"),
                ),
            ),
        ),
    )


def _artifact() -> ConfigurationArtifact:
    return ConfigurationArtifact(
        "service-config",
        "/etc/service/config.json",
        ConfigurationMediaType.JSON,
        '{"workers":2}\n',
        ConfigurationFileMode.READ_ONLY,
    )


def _workload_container_record(fake_client: FakeDockerClient) -> dict[str, object]:
    records = _workload_container_records(fake_client)
    assert len(records) == 1
    return records[0]


def _workload_container_records(fake_client: FakeDockerClient) -> list[dict[str, object]]:
    image = "ghcr.io/openj92/runtime-fixture@sha256:" + "a" * 64
    return [
        record
        for record in fake_client.containers.created
        if record.get("image") == image
    ]


if __name__ == "__main__":
    unittest.main()
