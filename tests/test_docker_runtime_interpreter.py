from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import socket
import unittest
from unittest.mock import Mock, patch

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
    RemoveNodeResource,
    RuntimeTarget,
    StartNode,
    StartRuntime,
    RemoveRuntimeResource,
    StopNode,
    StopRuntime,
    WaitForHealthy,
)
from control_plane_kit_core.lifecycle import ResourceLifecycle
from control_plane_kit_core.products import (
    ContainerServerProduct,
    OciImageReference,
    ProductDescriptorDigest,
    ProductIdentity,
    ProductReference,
    ProductRuntimeContract,
    ProviderRuntimePort,
    RetainedDataMount,
)
from control_plane_kit_core.runtime_authority import (
    RuntimeAuthorityAccessDelivery,
    RuntimeAuthorityAccessDeliveryKind,
    RuntimeAuthorityReference,
)
from control_plane_kit_core.runtime_effects import (
    ImagePullAuthority,
    RuntimeEffectKind,
    RuntimeEffectRequest,
    RuntimeEffectSource,
    RuntimeProductMaterial,
)
from control_plane_kit_core.operations.run_identity import RunId
from control_plane_kit_core.secrets import (
    SecretEnvironmentDelivery,
    SecretFileDelivery,
    SecretFileMode,
    SecretFilePathBinding,
    SecretMissing,
    SecretProviderEndpointReference,
    SecretProviderAuthority,
    SecretProviderId,
    SecretReference,
    SecretResolutionGrant,
    SecretResolved,
    SecretResolution,
    SecretUseIntent,
    SecretValue,
)
from control_plane_kit_core.types import Protocol, RuntimeKind
from control_plane_kit_core.verification import (
    HttpCheck,
    HttpVerificationEvidence,
    VerificationContract,
    VerificationOutcome,
)
from control_plane_kit_core.verification import (
    PostgresPasswordAuthentication,
    PostgresQueryCheck,
    RedisCheck,
    VerificationPolicy,
)

from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter, DockerSdkClient
from control_plane_kit_interpreters.docker.runtime import _resource_name
from control_plane_kit_interpreters.docker.sdk import DockerSdkHttpProbeResult
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
    OVERSIZED_HELPER_RECORD,
    REJECTED_HELPER_RECORD,
)


@dataclass(frozen=True)
class RuntimeHttpProbeResult:
    status_code: int | None
    response_size: int
    exit_code: int
    classification: str
    body_sha256_matches: bool | None

    @property
    def timed_out(self) -> bool:
        return self.classification == "timed-out"


class DockerRuntimeInterpreterTests(unittest.TestCase):
    def test_long_workspace_preserves_distinct_node_names_and_exact_reuse(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        names = []
        for node_id in ("hello-086f197e4a13", "hello-b49b98b66962"):
            with self.subTest(node_id=node_id):
                request = _request(
                    StartNode(NodeTarget(node_id)),
                    products=(replace(_material(_product()), node_id=node_id),),
                )
                request = replace(
                    request,
                    source=replace(
                        request.source,
                        workspace_id="cpk-convergence-cpk-public-convergence-j01gyrlh",
                    ),
                )
                started = interpreter.execute(request)
                self.assertIs(started.kind, EffectResultKind.SUCCEEDED)
                name = started.evidence["container"]
                names.append(name)
                self.assertLessEqual(len(name), 63)
                self.assertEqual(
                    fake_client.containers.resources[name].attrs["Config"]["Labels"][
                        "org.openj92.cpk.node"
                    ],
                    node_id,
                )
                count = len(_workload_container_records(fake_client))
                replayed = interpreter.execute(request)
                self.assertIs(replayed.kind, EffectResultKind.SUCCEEDED)
                self.assertEqual(replayed.evidence["container"], name)
                self.assertEqual(len(_workload_container_records(fake_client)), count)
        self.assertEqual(len(set(names)), 2)

    def test_resource_names_keep_short_spelling_and_bounded_digest_suffix(self) -> None:
        for kind, parts in (
            ("net", ("workspace-a", "docker")),
            ("node", ("workspace-a", "api")),
            ("vol", ("workspace-a", "api", "data")),
        ):
            with self.subTest(kind=kind):
                digest = hashlib.sha256(
                    ("\0".join((kind, *parts)) + "\0").encode("utf-8")
                ).hexdigest()[:12]
                self.assertEqual(
                    _resource_name(kind, *parts),
                    f"cpk-{kind}-{'-'.join(parts)}-{digest}",
                )
                long_parts = ("workspace-" * 8, *parts[1:])
                digest = hashlib.sha256(
                    ("\0".join((kind, *long_parts)) + "\0").encode("utf-8")
                ).hexdigest()[:12]
                name = _resource_name(kind, *long_parts)
                self.assertLessEqual(len(name), 63)
                self.assertRegex(name, r"\A[a-zA-Z0-9][a-zA-Z0-9_.-]*[a-f0-9]\Z")
                self.assertTrue(name.endswith(f"-{digest}"))
                self.assertEqual(_resource_name(kind, *long_parts), name)

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

    def test_start_node_materializes_and_replays_exact_configuration_artifact(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        request = _request(StartNode(NodeTarget("api")))

        first = interpreter.execute(request)
        fake_client.containers.resources[str(first.evidence["container"])].attrs[
            "State"
        ]["Running"] = True
        replay = interpreter.execute(request)

        self.assertIs(first.kind, EffectResultKind.SUCCEEDED)
        self.assertIs(replay.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(replay.evidence["action"], "reused")
        configuration_volumes = [
            volume
            for volume in fake_client.volumes.created
            if volume["labels"]["org.openj92.cpk.volume.kind"] == "configuration"
        ]
        self.assertEqual(len(configuration_volumes), 1)
        volume = configuration_volumes[0]
        self.assertEqual(
            volume["labels"]["org.openj92.cpk.artifact.digest"],
            _artifact().content_digest,
        )
        container = _workload_container_record(fake_client)
        self.assertIn(
            {
                "Type": "volume",
                "Source": volume["name"],
                "Target": "/etc/service/config.json",
                "ReadOnly": True,
                "VolumeOptions": {"Subpath": "content"},
            },
            container["mounts"],
        )
        self.assertEqual(len(_workload_container_records(fake_client)), 1)

    def test_start_node_completes_owned_configuration_volume_with_absent_content(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        interpreter = DockerRuntimeInterpreter(sdk)
        request = _request(StartNode(NodeTarget("api")))
        first = interpreter.execute(request)
        volume = next(
            value
            for value in fake_client.volumes.created
            if value["labels"]["org.openj92.cpk.volume.kind"] == "configuration"
        )
        fake_client.containers.resources.pop(str(first.evidence["container"]))
        fake_client.containers.volume_archives[str(volume["name"])].clear()

        replay = interpreter.execute(request)

        self.assertIs(replay.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(
            sdk.configuration_artifact_digest(str(volume["name"])),
            _artifact().content_digest,
        )
        self.assertEqual(len(_configuration_volumes(fake_client)), 1)

    def test_start_node_rejects_wrong_configuration_digest_before_image_or_container(self) -> None:
        fake_client = FakeDockerClient()
        sdk = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        interpreter = DockerRuntimeInterpreter(sdk)
        request = _request(StartNode(NodeTarget("api")))
        first = interpreter.execute(request)
        volume = next(
            value
            for value in fake_client.volumes.created
            if value["labels"]["org.openj92.cpk.volume.kind"] == "configuration"
        )
        fake_client.containers.resources.pop(str(first.evidence["container"]))
        fake_client.containers.volume_archives[str(volume["name"])].clear()
        sdk.materialize_configuration_artifact(
            str(volume["name"]),
            ConfigurationArtifact(
                "service-config",
                "/etc/service/config.json",
                ConfigurationMediaType.JSON,
                '{"workers":3}\n',
                ConfigurationFileMode.READ_ONLY,
            ),
        )
        fake_client.images.pulled.clear()

        result = interpreter.execute(request)

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.configuration-digest-conflict")
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(len(_workload_container_records(fake_client)), 1)

    def test_retained_volume_is_mounted_and_survives_stop_and_compute_removal(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        material = _material(_product_with_retained_data())

        started = interpreter.execute(
            _request(StartNode(NodeTarget("api")), products=(material,))
        )
        retained = next(
            volume
            for volume in fake_client.volumes.created
            if volume["labels"]["org.openj92.cpk.volume.kind"] == "retained-data"
        )
        container = _workload_container_record(fake_client)
        self.assertEqual(
            container["volumes"],
            {retained["name"]: {"bind": "/var/lib/service", "mode": "rw"}},
        )
        resource = fake_client.volumes.resources[str(retained["name"])]
        fake_client.containers.resources[str(started.evidence["container"])].attrs[
            "State"
        ]["Running"] = True

        stopped = interpreter.execute(
            _request(StopNode(NodeTarget("api")), products=(material,))
        )
        removed = interpreter.execute(
            _request(RemoveNodeResource(NodeTarget("api")), products=(material,))
        )

        self.assertIs(stopped.kind, EffectResultKind.SUCCEEDED)
        self.assertIs(removed.kind, EffectResultKind.SUCCEEDED)
        self.assertFalse(resource.removed)
        self.assertIn(str(retained["name"]), fake_client.volumes.resources)

    def test_unowned_retained_volume_fails_before_image_or_container_mutation(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        material = _material(_product_with_retained_data())
        request = _request(StartNode(NodeTarget("api")), products=(material,))
        first = interpreter.execute(request)
        retained = next(
            volume
            for volume in fake_client.volumes.created
            if volume["labels"]["org.openj92.cpk.volume.kind"] == "retained-data"
        )
        fake_client.containers.resources.pop(str(first.evidence["container"]))
        fake_client.volumes.resources[str(retained["name"])].attrs["Config"][
            "Labels"
        ] = {}
        fake_client.images.pulled.clear()

        result = interpreter.execute(request)

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.retained-volume-ownership-conflict")
        self.assertEqual(fake_client.images.pulled, [])
        self.assertEqual(len(_workload_container_records(fake_client)), 1)

    def test_runtime_stop_is_a_non_deleting_logical_barrier(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        started = interpreter.execute(
            _request(StartRuntime(RuntimeTarget("docker")), products=())
        )
        network = fake_client.networks.resources[str(started.evidence["network"])]

        result = interpreter.execute(
            _request(StopRuntime(RuntimeTarget("docker")), products=())
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "logical-stop")
        self.assertFalse(network.removed)

    def test_docker_timeout_is_uncertain_without_exception_text(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        def fail_inspection(name: str) -> FakeResource:
            raise TimeoutError("daemon output carried sensitive material")

        fake_client.networks.get = fail_inspection
        result = interpreter.execute(
            _request(StartRuntime(RuntimeTarget("docker")), products=())
        )

        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(result.failure.code, "docker.effect-uncertain")
        self.assertEqual(result.failure.message, "TimeoutError")
        self.assertEqual(fake_client.networks.created, [])

    def test_reconcile_failure_after_removal_is_uncertain_and_redacted(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        first = interpreter.execute(_request(StartNode(NodeTarget("api"))))
        existing = fake_client.containers.resources[str(first.evidence["container"])]

        def fail_run(**kwargs: object) -> None:
            raise RuntimeError("container response carried sensitive material")

        interpreter.client.run_container = fail_run
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

        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(result.failure.code, "docker.effect-uncertain")
        self.assertEqual(result.failure.message, "RuntimeError")
        self.assertTrue(existing.force_removed)
        self.assertNotIn("container response carried sensitive material", repr(result))

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
        prior_pulls = list(fake_client.images.pulled)

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
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "recreated")
        self.assertTrue(existing.force_removed)
        self.assertEqual(fake_client.images.pulled, prior_pulls)
        self.assertEqual(len(_workload_container_records(fake_client)), 2)
        self.assertEqual(
            _workload_container_records(fake_client)[-1]["environment"],
            {
                "PORT": "8080",
                "UPSTREAM_URL": "http://replacement:8080",
            },
        )

    def test_reconcile_rejects_image_admission_before_owned_resource_mutation(self) -> None:
        for case in ("wrong-cached-digest", "pull-unavailable", "wrong-pulled-digest"):
            with self.subTest(case=case):
                fake_client = FakeDockerClient()
                interpreter = DockerRuntimeInterpreter(DockerSdkClient(
                    client=fake_client, docker_module=FakeDockerModule(fake_client),
                ))
                first = interpreter.execute(_request(StartNode(NodeTarget("api"))))
                self.assertIs(first.kind, EffectResultKind.SUCCEEDED)
                existing = fake_client.containers.resources[str(first.evidence["container"])]
                reference = _product().image.execution_reference
                image = fake_client.images.resources[reference]
                original_pull = fake_client.images.pull

                def wrong_pull(image_reference: str, **kwargs: object) -> None:
                    original_pull(image_reference, **kwargs)
                    fake_client.images.resources[image_reference].attrs["RepoDigests"] = []

                if case == "wrong-cached-digest":
                    image.attrs["RepoDigests"] = []
                    pull = Mock(wraps=original_pull)
                else:
                    del fake_client.images.resources[reference]
                    pull = Mock(side_effect=(
                        RuntimeError("private registry response")
                        if case == "pull-unavailable" else wrong_pull
                    ))
                fake_client.images.pull = pull
                before = [list(manager.created) for manager in (
                    fake_client.networks, fake_client.volumes, fake_client.containers,
                )]
                result = interpreter.execute(_request(
                    ReconcileNode(NodeTarget("api")),
                    products=(_material(_product(), public_environment=(
                        PublicStaticEnvironmentBinding("PORT", "9090"),
                    )),),
                ))

                self.assertIs(result.kind, (
                    EffectResultKind.UNCERTAIN if case == "pull-unavailable"
                    else EffectResultKind.FAILED
                ))
                self.assertEqual(result.failure.code, (
                    "docker.effect-uncertain" if case == "pull-unavailable"
                    else "docker.image-reference-conflict"
                ))
                self.assertFalse(existing.force_removed)
                self.assertEqual(before, [manager.created for manager in (
                    fake_client.networks, fake_client.volumes, fake_client.containers,
                )])
                self.assertEqual(pull.call_count, 0 if case == "wrong-cached-digest" else 1)
                self.assertNotIn("private registry response", repr(result))

    def test_reconcile_missing_image_uses_one_permitted_pull(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(DockerSdkClient(
            client=fake_client, docker_module=FakeDockerModule(fake_client),
        ))
        first = interpreter.execute(_request(StartNode(NodeTarget("api"))))
        self.assertIs(first.kind, EffectResultKind.SUCCEEDED)
        reference = _product().image.execution_reference
        del fake_client.images.resources[reference]
        prior_pulls = len(fake_client.images.pulled)

        result = interpreter.execute(_request(
            ReconcileNode(NodeTarget("api")),
            products=(_material(_product(), public_environment=(
                PublicStaticEnvironmentBinding("PORT", "9090"),
            )),),
        ))

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "recreated")
        self.assertEqual(fake_client.images.pulled[prior_pulls:], [{"image": reference}])

    def test_reconcile_requires_pull_authority_before_cached_image_access(self) -> None:
        fake_client = FakeDockerClient()
        reference = SecretReference("secret://registry/ghcr/runtime-fixture")
        resolver = FakeImagePullCredentialResolver(ImagePullCredentialMissing(reference))
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(client=fake_client, docker_module=FakeDockerModule(fake_client)),
            image_pull_credentials=resolver,
        )
        first = interpreter.execute(_request(StartNode(NodeTarget("api"))))
        self.assertIs(first.kind, EffectResultKind.SUCCEEDED)
        existing = fake_client.containers.resources[str(first.evidence["container"])]
        before = [list(manager.created) for manager in (
            fake_client.networks, fake_client.volumes, fake_client.containers,
        )]
        with patch.object(fake_client.images, "get", wraps=fake_client.images.get) as inspect_image:
            result = interpreter.execute(_request(
                ReconcileNode(NodeTarget("api")),
                products=(_material(_product(), pull_authority=ImagePullAuthority(
                    "ghcr.io", "openj92/runtime-fixture", reference,
                )),),
            ))
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.image-pull-credential-missing")
        self.assertEqual(resolver.requests, [reference.reference_id])
        inspect_image.assert_not_called()
        self.assertFalse(existing.force_removed)
        self.assertEqual(before, [manager.created for manager in (
            fake_client.networks, fake_client.volumes, fake_client.containers,
        )])

    def test_reconcile_node_recreates_owned_container_when_public_environment_changes(
        self,
    ) -> None:
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
                        public_environment=(
                            PublicStaticEnvironmentBinding("PORT", "9090"),
                        ),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "recreated")
        self.assertTrue(existing.force_removed)
        self.assertEqual(
            _workload_container_records(fake_client)[-1]["environment"],
            {"PORT": "9090"},
        )

    def test_reconcile_node_reuses_canonically_equivalent_environment_material(
        self,
    ) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        public_environment = (
            PublicStaticEnvironmentBinding("MODE", "ready"),
            PublicStaticEnvironmentBinding("PORT", "8080"),
        )
        socket_environment = (
            SocketDerivedEnvironmentBinding(
                "CACHE_URL",
                "http://cache:8080",
                "cache.internal->api.cache",
            ),
            SocketDerivedEnvironmentBinding(
                "UPSTREAM_URL",
                "http://upstream:8080",
                "upstream.internal->api.upstream",
            ),
        )
        interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        public_environment=public_environment,
                        socket_environment=socket_environment,
                    ),
                ),
            )
        )

        result = interpreter.execute(
            _request(
                ReconcileNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        public_environment=tuple(reversed(public_environment)),
                        socket_environment=tuple(reversed(socket_environment)),
                    ),
                ),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "reused")
        self.assertEqual(len(_workload_container_records(fake_client)), 1)

    def test_reconcile_node_tracks_delegation_verifier_projection_material(
        self,
    ) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        name = "CPK_GATEWAY_DELEGATION_VERIFIERS"
        verifier_a = '[{"key_id":"A","public_key":"public-A"}]'
        verifier_a_b = (
            '[{"key_id":"A","public_key":"public-A"},'
            '{"key_id":"B","public_key":"public-B"}]'
        )
        verifier_b = '[{"key_id":"B","public_key":"public-B"}]'
        interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        public_environment=(
                            PublicStaticEnvironmentBinding(name, verifier_a),
                        ),
                    ),
                ),
            )
        )

        overlap = interpreter.execute(
            _request(
                ReconcileNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        public_environment=(
                            PublicStaticEnvironmentBinding(name, verifier_a_b),
                        ),
                    ),
                ),
            )
        )
        active = interpreter.execute(
            _request(
                ReconcileNode(NodeTarget("api")),
                products=(
                    _material(
                        _product(),
                        public_environment=(
                            PublicStaticEnvironmentBinding(name, verifier_b),
                        ),
                    ),
                ),
            )
        )

        self.assertEqual(overlap.evidence["action"], "recreated")
        self.assertEqual(active.evidence["action"], "recreated")
        records = _workload_container_records(fake_client)
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["environment"], {name: verifier_a})
        self.assertEqual(records[1]["environment"], {name: verifier_a_b})
        self.assertEqual(records[2]["environment"], {name: verifier_b})
        for record in records:
            self.assertNotIn("public-A", repr(record["labels"]))
            self.assertNotIn("public-B", repr(record["labels"]))

    def test_reconcile_node_recreates_when_authority_delivery_changes(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        interpreter.execute(_request(StartNode(NodeTarget("api"))))
        delivery = RuntimeAuthorityAccessDelivery(
            RuntimeAuthorityReference("local-docker"),
            RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT,
        )

        with patch(
            "control_plane_kit_interpreters.docker.runtime.os.stat",
            return_value=type("SocketStat", (), {"st_gid": 987})(),
        ):
            result = interpreter.execute(
                _request(
                    ReconcileNode(NodeTarget("api")),
                    authority_ref=RuntimeAuthorityReference("local-docker"),
                    authority_deliveries=(delivery,),
                )
            )

        self.assertEqual(result.evidence["action"], "recreated")
        record = _workload_container_records(fake_client)[-1]
        self.assertEqual(record["group_add"], ["987"])
        self.assertEqual(len(_bind_mounts(record)), 1)

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
        client = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        calls: list[dict[str, object]] = []
        client.run_http_probe = (  # type: ignore[method-assign]
            lambda **kwargs: calls.append(dict(kwargs))
            or RuntimeHttpProbeResult(200, 3, 0, "completed", None)
        )
        interpreter = DockerRuntimeInterpreter(client)

        result = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_health_check()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "verified-healthy")
        self.assertEqual(len(calls), 1)
        self.assertTrue(str(calls[0]["network"]).startswith("cpk-net-workspace-a-docker-"))
        self.assertEqual(calls[0]["url"], "http://api:8080/health/ready")
        with self.subTest(boundary="typed-completion-is-authoritative"):
            self.assertEqual(len(result.observations), 1)
        with self.subTest(boundary="generic-check-duplicate-is-absent"):
            self.assertNotIn("checks", result.evidence)
        if result.observations:
            completion = result.observations[0]
            self.assertIs(completion.outcome, VerificationOutcome.PASSED)
            self.assertEqual(
                completion.evidence,
                HttpVerificationEvidence(200, 3),
            )

    def test_wait_for_healthy_fails_when_http_verification_fails(self) -> None:
        fake_client = FakeDockerClient()
        client = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        client.run_http_probe = (  # type: ignore[method-assign]
            lambda **_: RuntimeHttpProbeResult(503, 9, 0, "completed", None)
        )
        interpreter = DockerRuntimeInterpreter(
            client,
        )

        result = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_health_check()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.health-check-failed")
        with self.subTest(boundary="typed-failure-is-authoritative"):
            self.assertEqual(len(result.observations), 1)
        with self.subTest(boundary="generic-check-duplicate-is-absent"):
            self.assertNotIn("checks", result.failure.details)
        if result.observations:
            completion = result.observations[0]
            self.assertIs(completion.outcome, VerificationOutcome.FAILED)
            self.assertEqual(
                completion.evidence,
                HttpVerificationEvidence(503, 9),
            )

    def test_wait_for_healthy_emits_typed_body_digest_match_and_mismatch(self) -> None:
        expected_digest = hashlib.sha256(b"hello").hexdigest()
        cases = (
            ("match", True, EffectResultKind.SUCCEEDED, VerificationOutcome.PASSED),
            ("mismatch", False, EffectResultKind.FAILED, VerificationOutcome.FAILED),
        )
        for boundary, matches, result_kind, completion_outcome in cases:
            with self.subTest(boundary=boundary):
                fake_client = FakeDockerClient()
                client = DockerSdkClient(
                    client=fake_client,
                    docker_module=FakeDockerModule(fake_client),
                )
                calls: list[dict[str, object]] = []
                probe = RuntimeHttpProbeResult(
                    200,
                    5,
                    0,
                    "completed",
                    matches,
                )
                client.run_http_probe = (  # type: ignore[method-assign]
                    lambda **kwargs: calls.append(dict(kwargs)) or probe
                )
                interpreter = DockerRuntimeInterpreter(client)

                result = interpreter.execute(
                    _request(
                        WaitForHealthy(NodeTarget("api")),
                        products=(
                            _material(
                                _product_with_health_check(
                                    expected_body_sha256=expected_digest,
                                )
                            ),
                        ),
                    )
                )

                self.assertEqual(
                    calls,
                    [
                        {
                            "network": calls[0]["network"],
                            "url": "http://api:8080/health/ready",
                            "timeout_seconds": 5.0,
                            "maximum_response_bytes": 16_384,
                            "expected_body_sha256": expected_digest,
                        }
                    ],
                )
                self.assertIs(result.kind, result_kind)
                self.assertEqual(len(result.observations), 1)
                if result.kind is EffectResultKind.SUCCEEDED:
                    self.assertNotIn("checks", result.evidence)
                else:
                    self.assertNotIn("checks", result.failure.details)
                if not result.observations:
                    continue
                completion = result.observations[0]
                self.assertIs(completion.outcome, completion_outcome)
                self.assertEqual(
                    completion.evidence,
                    HttpVerificationEvidence(200, 5, expected_digest, matches),
                )

    def test_wait_for_healthy_maps_private_probe_failures_without_fabrication(self) -> None:
        expected_digest = hashlib.sha256(b"hello").hexdigest()
        cases = (
            (
                "redirect",
                RuntimeHttpProbeResult(
                    REJECTED_HELPER_RECORD["status_code"],
                    REJECTED_HELPER_RECORD["response_bytes"],
                    0,
                    REJECTED_HELPER_RECORD["category"],
                    REJECTED_HELPER_RECORD["match"],
                ),
                VerificationOutcome.REJECTED,
            ),
            (
                "oversize",
                RuntimeHttpProbeResult(
                    OVERSIZED_HELPER_RECORD["status_code"],
                    OVERSIZED_HELPER_RECORD["response_bytes"],
                    0,
                    OVERSIZED_HELPER_RECORD["category"],
                    OVERSIZED_HELPER_RECORD["match"],
                ),
                VerificationOutcome.MALFORMED,
            ),
            (
                "timeout",
                RuntimeHttpProbeResult(None, 0, 124, "timed-out", None),
                VerificationOutcome.TIMED_OUT,
            ),
            (
                "unavailable",
                RuntimeHttpProbeResult(None, 0, 1, "unavailable", None),
                VerificationOutcome.FAILED,
            ),
        )
        for boundary, probe, expected_outcome in cases:
            with self.subTest(boundary=boundary):
                fake_client = FakeDockerClient()
                client = DockerSdkClient(
                    client=fake_client,
                    docker_module=FakeDockerModule(fake_client),
                )
                client.run_http_probe = lambda **_: probe  # type: ignore[method-assign]
                result = DockerRuntimeInterpreter(client).execute(
                    _request(
                        WaitForHealthy(NodeTarget("api")),
                        products=(
                            _material(
                                _product_with_health_check(
                                    expected_body_sha256=expected_digest,
                                )
                            ),
                        ),
                    )
                )

                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertEqual(len(result.observations), 1)
                self.assertNotIn("checks", result.failure.details)
                if not result.observations:
                    continue
                completion = result.observations[0]
                self.assertIs(completion.outcome, expected_outcome)
                self.assertIsNone(completion.evidence)

    def test_wait_for_healthy_uses_product_verification_cadence(self) -> None:
        fake_client = FakeDockerClient()
        client = DockerSdkClient(
            client=fake_client,
            docker_module=FakeDockerModule(fake_client),
        )
        responses = iter(
            (
                DockerSdkHttpProbeResult(503, 9, 0),
                DockerSdkHttpProbeResult(200, 9, 0),
            )
        )
        client.run_http_probe = lambda **_: next(responses)  # type: ignore[method-assign]
        interpreter = DockerRuntimeInterpreter(client)
        product = _product_with_health_check(
            policy=VerificationPolicy(
                interval_seconds=1.5,
                maximum_attempts=2,
            )
        )

        with patch("control_plane_kit_interpreters.timing.time.sleep") as sleep:
            result = interpreter.execute(
                _request(
                    WaitForHealthy(NodeTarget("api")),
                    products=(_material(product),),
                )
            )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        sleep.assert_called_once_with(1.5)

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


    def test_local_runtime_authority_uses_ambient_docker_client(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("local-docker"),
            ),
            _local_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "created")
        self.assertEqual(len(fake_client.networks.created), 1)

    def test_local_runtime_authority_does_not_mount_socket_without_delivery(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute_with_authority(
            _request(
                StartNode(NodeTarget("api")),
                authority_ref=RuntimeAuthorityReference("local-docker"),
            ),
            _local_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(_bind_mounts(_workload_container_record(fake_client)), [])

    def test_explicit_local_socket_delivery_mounts_socket_at_docker_boundary(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        delivery = RuntimeAuthorityAccessDelivery(
            RuntimeAuthorityReference("local-docker"),
            RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT,
        )

        with patch(
            "control_plane_kit_interpreters.docker.runtime.os.stat",
            return_value=type("SocketStat", (), {"st_gid": 987})(),
        ):
            result = interpreter.execute_with_authority(
                _request(
                    StartNode(NodeTarget("api")),
                    authority_ref=RuntimeAuthorityReference("local-docker"),
                    authority_deliveries=(delivery,),
                ),
                _local_runtime_authority(),
            )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        record = _workload_container_record(fake_client)
        self.assertEqual(
            _bind_mounts(record),
            [
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Target": "/var/run/docker.sock",
                    "ReadOnly": False,
                }
            ],
        )
        self.assertEqual(record["group_add"], ["987"])
        self.assertNotIn("/var/run/docker.sock", repr(result.descriptor()))

    def test_unsupported_authority_delivery_fails_without_docker_mutation(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )
        delivery = RuntimeAuthorityAccessDelivery(
            RuntimeAuthorityReference("local-docker"),
            RuntimeAuthorityAccessDeliveryKind.CLOUD_CREDENTIAL_SECRET_SESSION,
        )

        result = interpreter.execute_with_authority(
            _request(
                StartNode(NodeTarget("api")),
                authority_ref=RuntimeAuthorityReference("local-docker"),
                authority_deliveries=(delivery,),
            ),
            _local_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.UNSUPPORTED)
        self.assertEqual(
            result.failure.code,
            "docker.runtime-authority-delivery-unsupported",
        )
        self.assertEqual(_workload_container_records(fake_client), [])

    def test_remote_tls_runtime_authority_resolves_secret_refs_before_docker_mutation(self) -> None:
        fake_client = FakeDockerClient()
        ambient_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        resolver = MappingSecretResolver(
            fake_client,
            {
                "secret://local/docker/ca": "ca-certificate-secret",
                "secret://local/docker/cert": "client-certificate-secret",
                "secret://local/docker/key": "client-key-secret",
            },
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=ambient_client,
                docker_module=fake_module,
            ),
            secret_resolver=resolver,
        )

        result = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("remote-docker"),
            ),
            _remote_tls_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(
            resolver.requests,
            [
                "secret://local/docker/ca",
                "secret://local/docker/cert",
                "secret://local/docker/key",
            ],
        )
        self.assertEqual(resolver.networks_created_during_resolution, [0, 0, 0])
        self.assertEqual(len(fake_client.networks.created), 1)
        self.assertEqual(
            fake_module.docker_clients[0]["base_url"],
            "tcp://mac-mini.local:2376",
        )
        self.assertEqual(fake_client.close_calls, 1)
        self.assertEqual(ambient_client.close_calls, 0)
        self.assertNotIn("client-key-secret", repr(result.descriptor()))
        self.assertNotIn("client-key-secret", repr(interpreter))

    def test_remote_tls_runtime_authority_closes_client_after_uncertain_effect(self) -> None:
        fake_client = FakeDockerClient()
        ambient_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        resolver = MappingSecretResolver(
            fake_client,
            {
                "secret://local/docker/ca": "ca-certificate-secret",
                "secret://local/docker/cert": "client-certificate-secret",
                "secret://local/docker/key": "client-key-secret",
            },
        )
        fake_client.networks.create = Mock(
            side_effect=RuntimeError("remote effect failed")
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=ambient_client,
                docker_module=fake_module,
            ),
            secret_resolver=resolver,
        )

        result = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("remote-docker"),
            ),
            _remote_tls_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(fake_client.close_calls, 1)
        self.assertEqual(ambient_client.close_calls, 0)

    def test_remote_tls_runtime_authority_closes_client_when_execution_raises(self) -> None:
        fake_client = FakeDockerClient()
        ambient_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        resolver = MappingSecretResolver(
            fake_client,
            {
                "secret://local/docker/ca": "ca-certificate-secret",
                "secret://local/docker/cert": "client-certificate-secret",
                "secret://local/docker/key": "client-key-secret",
            },
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=ambient_client,
                docker_module=fake_module,
            ),
            secret_resolver=resolver,
        )

        with patch.object(
            DockerRuntimeInterpreter,
            "execute",
            side_effect=RuntimeError("unexpected execution failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected execution failure"):
                interpreter.execute_with_authority(
                    _request(
                        StartRuntime(RuntimeTarget("docker")),
                        products=(),
                        authority_ref=RuntimeAuthorityReference("remote-docker"),
                    ),
                    _remote_tls_runtime_authority(),
                )

        self.assertEqual(fake_client.close_calls, 1)
        self.assertEqual(ambient_client.close_calls, 0)

    def test_remote_tls_client_close_failure_is_bounded_and_uncertain(self) -> None:
        class FailingCloseDockerClient(FakeDockerClient):
            def close(self) -> None:
                super().close()
                raise RuntimeError("/tmp/cpk-docker-tls-secret/key.pem")

        fake_client = FailingCloseDockerClient()
        ambient_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        resolver = MappingSecretResolver(
            fake_client,
            {
                "secret://local/docker/ca": "ca-certificate-secret",
                "secret://local/docker/cert": "client-certificate-secret",
                "secret://local/docker/key": "client-key-secret",
            },
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=ambient_client,
                docker_module=fake_module,
            ),
            secret_resolver=resolver,
        )

        result = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("remote-docker"),
            ),
            _remote_tls_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(
            result.failure.code,
            "docker.runtime-authority-client-close-uncertain",
        )
        self.assertNotIn("/tmp/cpk-docker-tls-secret", repr(result.descriptor()))
        self.assertEqual(fake_client.close_calls, 1)
        self.assertEqual(ambient_client.close_calls, 0)

    def test_local_runtime_authority_does_not_close_ambient_client(self) -> None:
        ambient_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=ambient_client,
                docker_module=FakeDockerModule(ambient_client),
            )
        )

        result = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("local-docker"),
            ),
            _local_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(ambient_client.close_calls, 0)

    def test_remote_tls_runtime_authority_missing_secret_fails_before_docker_mutation(self) -> None:
        fake_client = FakeDockerClient()
        resolver = MappingSecretResolver(fake_client, {})
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            secret_resolver=resolver,
        )

        result = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("remote-docker"),
            ),
            _remote_tls_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.runtime-authority-secret-missing")
        self.assertEqual(fake_client.networks.created, [])
        self.assertNotIn("secret://local/docker/ca", repr(result.descriptor()))

    def test_remote_tls_runtime_authority_requires_secret_resolver(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("remote-docker"),
            ),
            _remote_tls_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(
            result.failure.code,
            "docker.runtime-authority-secret-resolver-required",
        )
        self.assertEqual(fake_client.networks.created, [])

    def test_unsupported_runtime_authority_kind_is_explicit_without_docker_mutation(self) -> None:
        fake_client = FakeDockerClient()
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            )
        )

        result = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("unknown-docker"),
            ),
            _unsupported_runtime_authority(),
        )

        self.assertIs(result.kind, EffectResultKind.UNSUPPORTED)
        self.assertEqual(result.failure.code, "docker.runtime-authority-kind-unsupported")
        self.assertEqual(fake_client.networks.created, [])

    def test_authorized_delivery_requires_exact_grant_without_legacy_fallback(self) -> None:
        fake_client = FakeDockerClient()
        reference = SecretReference("secret://local/api-token")
        authorized = FakeAuthorizedSecretResolver(
            fake_client,
            {(reference, SecretUseIntent.APPLICATION_CONTROL_TOKEN): "authorized-token"},
        )
        legacy = FakeSecretResolver(
            fake_client,
            SecretResolved(reference, SecretValue("legacy-token")),
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            secret_resolver=legacy,
            authorized_secret_resolver=authorized,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(_material(_product_with_secret_delivery()),),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.secret-resolution-denied")
        self.assertEqual(authorized.requests, [])
        self.assertEqual(legacy.requests, [])
        self.assertEqual(fake_client.networks.created, [])
        self.assertEqual(fake_client.images.pulled, [])

    def test_authorized_delivery_rejects_wrong_intent_grant_without_resolution(self) -> None:
        fake_client = FakeDockerClient()
        reference = SecretReference("secret://local/api-token")
        wrong_grant = _grant(reference, SecretUseIntent.POSTGRES_PASSWORD)
        resolver = FakeAuthorizedSecretResolver(
            fake_client,
            {(reference, SecretUseIntent.APPLICATION_CONTROL_TOKEN): "do-not-resolve"},
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            authorized_secret_resolver=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(_material(_product_with_secret_delivery()),),
                secret_resolution_grants=(wrong_grant,),
            )
        )

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.secret-resolution-denied")
        self.assertEqual(resolver.requests, [])
        self.assertEqual(fake_client.networks.created, [])
        self.assertNotIn("do-not-resolve", repr(result.descriptor()))

    def test_authorized_delivery_resolves_exact_grant_before_docker_mutation(self) -> None:
        fake_client = FakeDockerClient()
        reference = SecretReference("secret://local/api-token")
        grant = _grant(reference, SecretUseIntent.APPLICATION_CONTROL_TOKEN)
        resolver = FakeAuthorizedSecretResolver(
            fake_client,
            {(reference, grant.intent): "authorized-token"},
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            authorized_secret_resolver=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(_material(_product_with_secret_delivery()),),
                secret_resolution_grants=(grant,),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, [grant])
        self.assertEqual(resolver.networks_created_during_resolution, [0])
        self.assertEqual(
            _workload_container_record(fake_client)["environment"]["API_TOKEN"],
            "authorized-token",
        )

    def test_authorized_oci_credential_uses_strict_provider_material(self) -> None:
        fake_client = FakeDockerClient()
        reference = SecretReference("secret://registry/ghcr/runtime-fixture")
        grant = _grant(reference, SecretUseIntent.OCI_PULL_CREDENTIAL)
        resolver = FakeAuthorizedSecretResolver(
            fake_client,
            {(reference, grant.intent): json.dumps(
                {"username": "cpk", "password": "registry-token"}
            )},
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            authorized_secret_resolver=resolver,
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
                            reference,
                        ),
                    ),
                ),
                secret_resolution_grants=(grant,),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, [grant])
        self.assertEqual(
            fake_client.images.pulled[0]["auth_config"],
            {"username": "cpk", "password": "registry-token"},
        )
        self.assertNotIn("registry-token", repr(result.descriptor()))

    def test_authorized_file_delivery_materializes_only_after_exact_grant(self) -> None:
        fake_client = FakeDockerClient()
        reference = SecretReference("secret://local/api-token")
        grant = _grant(reference, SecretUseIntent.APPLICATION_CONTROL_TOKEN)
        resolver = FakeAuthorizedSecretResolver(
            fake_client,
            {(reference, grant.intent): "file-secret-content"},
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            authorized_secret_resolver=resolver,
        )

        result = interpreter.execute(
            _request(
                StartNode(NodeTarget("api")),
                products=(_material(_product_with_file_secret_delivery()),),
                secret_resolution_grants=(grant,),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, [grant])
        container = _workload_container_record(fake_client)
        self.assertEqual(
            container["environment"]["API_TOKEN_FILE"],
            "/run/secrets/api-token",
        )
        self.assertNotIn("file-secret-content", repr(result.descriptor()))

    def test_authorized_oci_identity_token_uses_exact_shape(self) -> None:
        fake_client = FakeDockerClient()
        reference = SecretReference("secret://registry/ghcr/runtime-fixture")
        grant = _grant(reference, SecretUseIntent.OCI_PULL_CREDENTIAL)
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            authorized_secret_resolver=FakeAuthorizedSecretResolver(
                fake_client,
                {(reference, grant.intent): '{"identitytoken":"registry-token"}'},
            ),
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
                            reference,
                        ),
                    ),
                ),
                secret_resolution_grants=(grant,),
            )
        )

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(
            fake_client.images.pulled[0]["auth_config"],
            {"identitytoken": "registry-token"},
        )
        self.assertNotIn("registry-token", repr(result.descriptor()))

    def test_malformed_authorized_oci_credential_fails_before_docker_mutation(self) -> None:
        reference = SecretReference("secret://registry/ghcr/runtime-fixture")
        grant = _grant(reference, SecretUseIntent.OCI_PULL_CREDENTIAL)
        malformed_values = (
            '{"username":"cpk","password":"token","extra":"no"}',
            '{"identitytoken":"token","username":"cpk"}',
            '{"auths":{"ghcr.io":{}}}',
            '{"username":"cpk","username":"other","password":"token"}',
        )
        for value in malformed_values:
            with self.subTest(value=value):
                fake_client = FakeDockerClient()
                interpreter = DockerRuntimeInterpreter(
                    DockerSdkClient(
                        client=fake_client,
                        docker_module=FakeDockerModule(fake_client),
                    ),
                    authorized_secret_resolver=FakeAuthorizedSecretResolver(
                        fake_client,
                        {(reference, grant.intent): value},
                    ),
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
                                    reference,
                                ),
                            ),
                        ),
                        secret_resolution_grants=(grant,),
                    )
                )
                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertEqual(
                    result.failure.code,
                    "docker.image-pull-credential-malformed",
                )
                self.assertEqual(fake_client.networks.created, [])
                self.assertEqual(fake_client.images.pulled, [])

    def test_authorized_postgres_password_requires_exact_grant_before_query(self) -> None:
        fake_client = FakeDockerClient()
        transport = FakePostgresTransport([True])
        reference = SecretReference("secret://local/postgres/password")
        resolver = FakeAuthorizedSecretResolver(
            fake_client,
            {(reference, SecretUseIntent.POSTGRES_PASSWORD): "postgres-secret"},
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=fake_client,
                docker_module=FakeDockerModule(fake_client),
            ),
            postgres_transport=transport,
            authorized_secret_resolver=resolver,
        )

        rejected = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_postgres_health_check()),),
            )
        )
        grant = _grant(reference, SecretUseIntent.POSTGRES_PASSWORD)
        accepted = interpreter.execute(
            _request(
                WaitForHealthy(NodeTarget("api")),
                products=(_material(_product_with_postgres_health_check()),),
                secret_resolution_grants=(grant,),
            )
        )

        self.assertIs(rejected.kind, EffectResultKind.FAILED)
        self.assertEqual(transport.calls, [
            ("api", 5432, "cpk", "cpk", "postgres-secret", 5.0)
        ])
        self.assertIs(accepted.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, [grant])

    def test_authorized_remote_tls_requires_all_three_exact_grants(self) -> None:
        fake_client = FakeDockerClient()
        fake_module = FakeDockerModule(fake_client)
        authority = _remote_tls_runtime_authority()
        uses = (
            (authority.authority.ca_certificate, SecretUseIntent.DOCKER_REMOTE_TLS_CA_CERTIFICATE),
            (authority.authority.client_certificate, SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_CERTIFICATE),
            (authority.authority.client_key, SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_KEY),
        )
        grants = tuple(_grant(reference, intent) for reference, intent in uses)
        resolver = FakeAuthorizedSecretResolver(
            fake_client,
            {(reference, intent): f"material-{index}" for index, (reference, intent) in enumerate(uses)},
        )
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(
                client=FakeDockerClient(),
                docker_module=fake_module,
            ),
            authorized_secret_resolver=resolver,
        )

        rejected = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("remote-docker"),
                secret_resolution_grants=grants[:2],
            ),
            authority,
        )
        self.assertIs(rejected.kind, EffectResultKind.FAILED)
        self.assertEqual(fake_client.networks.created, [])
        accepted = interpreter.execute_with_authority(
            _request(
                StartRuntime(RuntimeTarget("docker")),
                products=(),
                authority_ref=RuntimeAuthorityReference("remote-docker"),
                secret_resolution_grants=grants,
            ),
            authority,
        )

        self.assertIs(accepted.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, [*grants[:2], *grants])



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


class FakeAuthorizedSecretResolver:
    def __init__(
        self,
        fake_client: FakeDockerClient,
        values: dict[tuple[SecretReference, SecretUseIntent], str],
    ) -> None:
        self.fake_client = fake_client
        self.values = values
        self.requests: list[SecretResolutionGrant] = []
        self.networks_created_during_resolution: list[int] = []

    def resolve(self, grant: SecretResolutionGrant) -> SecretResolution:
        self.requests.append(grant)
        self.networks_created_during_resolution.append(
            len(self.fake_client.networks.created)
        )
        value = self.values.get((grant.reference, grant.intent))
        if value is None:
            return SecretMissing(grant.reference)
        return SecretResolved(grant.reference, SecretValue(value))


class MappingSecretResolver:
    authority = SecretProviderAuthority(
        SecretProviderId("local"),
        (("docker",),),
    )

    def __init__(self, fake_client: FakeDockerClient, values: dict[str, str]) -> None:
        self.fake_client = fake_client
        self.values = values
        self.requests: list[str] = []
        self.networks_created_during_resolution: list[int] = []

    def resolve(self, reference: SecretReference) -> SecretResolution:
        self.requests.append(reference.reference_id)
        self.networks_created_during_resolution.append(
            len(self.fake_client.networks.created)
        )
        value = self.values.get(reference.reference_id)
        if value is None:
            return SecretMissing(reference)
        return SecretResolved(reference, SecretValue(value))


@dataclass(frozen=True)
class FakeRuntimeAuthority:
    runtime_kind: RuntimeKind
    authority_kind: str
    authority: object


@dataclass(frozen=True)
class FakeRemoteDockerTlsAuthority:
    endpoint: str
    ca_certificate: SecretReference
    client_certificate: SecretReference
    client_key: SecretReference


def _local_runtime_authority() -> FakeRuntimeAuthority:
    return FakeRuntimeAuthority(
        RuntimeKind.DOCKER,
        "local-docker-socket",
        object(),
    )


def _remote_tls_runtime_authority() -> FakeRuntimeAuthority:
    return FakeRuntimeAuthority(
        RuntimeKind.DOCKER,
        "remote-docker-tls",
        FakeRemoteDockerTlsAuthority(
            endpoint="tcp://mac-mini.local:2376",
            ca_certificate=SecretReference("secret://local/docker/ca"),
            client_certificate=SecretReference("secret://local/docker/cert"),
            client_key=SecretReference("secret://local/docker/key"),
        ),
    )


def _unsupported_runtime_authority() -> FakeRuntimeAuthority:
    return FakeRuntimeAuthority(
        RuntimeKind.DOCKER,
        "ssh-docker-tunnel",
        object(),
    )


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
    authority_ref: RuntimeAuthorityReference | None = None,
    authority_deliveries: tuple[RuntimeAuthorityAccessDelivery, ...] = (),
    secret_resolution_grants: tuple[SecretResolutionGrant, ...] = (),
) -> RuntimeEffectRequest:
    return RuntimeEffectRequest(
        effect_id="event-started",
        kind=RuntimeEffectKind.REALIZE_ACTIVITY,
        runtime_kind=RuntimeKind.DOCKER,
        source=RuntimeEffectSource(
            workspace_id="workspace-a",
            request_id="request-a",
            run_id=RunId("run-a"),
            plan_id="plan-a",
            base_graph_id="graph-base",
            desired_graph_id=desired_graph_id,
            intent_event_id="event-started",
        ),
        activity_id=ActivityId("activity-a"),
        operation=operation,
        products=(_material(_product()),) if products is None else products,
        authority_ref=authority_ref,
        authority_deliveries=authority_deliveries,
        secret_resolution_grants=secret_resolution_grants,
    )


def _grant(
    reference: SecretReference,
    intent: SecretUseIntent,
) -> SecretResolutionGrant:
    return SecretResolutionGrant(
        authorization_id="suse_" + "a" * 64,
        workspace_id="workspace-a",
        reference_registration_id="sref_" + "b" * 64,
        provider_registration_id="sprov_" + "c" * 64,
        endpoint_reference=SecretProviderEndpointReference("provider-main"),
        credential_reference=SecretReference("secret://bootstrap/provider-token"),
        reference=reference,
        intent=intent,
        actor_subject="docker-interpreter",
        correlation_id="correlation-1192",
        intent_fingerprint="d" * 64,
        run_id="run-a",
        activity_id="activity-a",
        effect_id="event-started",
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


def _product_with_health_check(
    *,
    policy: VerificationPolicy | None = None,
    expected_body_sha256: str | None = None,
) -> ContainerServerProduct:
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
                        policy=policy or VerificationPolicy(),
                        expected_body_sha256=expected_body_sha256,
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
                    SecretUseIntent.APPLICATION_CONTROL_TOKEN,
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
                    SecretUseIntent.APPLICATION_CONTROL_TOKEN,
                    SecretFileMode.OWNER_READ_ONLY,
                    SecretFilePathBinding("API_TOKEN_FILE"),
                ),
            ),
        ),
    )


def _product_with_retained_data() -> ContainerServerProduct:
    product = _product()
    return ContainerServerProduct(
        identity=product.identity,
        image=product.image,
        runtime_contract=ProductRuntimeContract(
            sockets=product.runtime_contract.sockets,
            provider_ports=product.runtime_contract.provider_ports,
            public_environment=product.runtime_contract.public_environment,
            configuration_artifacts=product.runtime_contract.configuration_artifacts,
            retained_data_mounts=(
                RetainedDataMount("service-data", "/var/lib/service"),
            ),
            lifecycle=ResourceLifecycle.owned_with_retained_data("service-data"),
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


def _configuration_volumes(fake_client: FakeDockerClient) -> list[dict[str, object]]:
    return [
        volume
        for volume in fake_client.volumes.created
        if volume["labels"]["org.openj92.cpk.volume.kind"] == "configuration"
    ]


def _bind_mounts(record: dict[str, object]) -> list[object]:
    mounts = record.get("mounts")
    assert isinstance(mounts, list)
    return [mount for mount in mounts if isinstance(mount, dict) and mount.get("Type") == "bind"]


if __name__ == "__main__":
    unittest.main()
