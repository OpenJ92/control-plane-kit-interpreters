from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import socket
from io import BytesIO
import tarfile
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
    FakeImage,
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
    def test_reconcile_replaces_stale_image_with_same_secret_reader(self) -> None:
        raw = FakeDockerClient()
        old = _product_with_file_secret_delivery()
        desired = replace(old, image=replace(old.image, digest="sha256:" + "d" * 64))
        for product, image_id in ((old, "sha256:" + "b" * 64), (desired, "sha256:" + "c" * 64)):
            image = FakeImage([], image_id=image_id, repo_digests=(product.image.execution_reference,))
            image.attrs["Config"]["User"] = "10006"
            raw.images.resources[product.image.execution_reference] = image
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw)),
            secret_resolver=FakeSecretResolver(raw, SecretResolved(
                SecretReference("secret://local/api-token"), SecretValue("fixture"))))
        self.assertIs(interpreter.execute(_request(StartNode(NodeTarget("api")),
                      products=(_material(old),))).kind, EffectResultKind.SUCCEEDED)
        prior = raw.containers.resources[_workload_container_record(raw)["name"]]
        before = {name: dict(archive) for name, archive in raw.containers.volume_archives.items()}
        volume_count = len(raw.volumes.created)
        result = interpreter.execute(_request(ReconcileNode(NodeTarget("api")), products=(_material(desired),)))
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertTrue(prior.removed)
        self.assertEqual(raw.containers.volume_archives, before)
        self.assertEqual(len(raw.volumes.created), volume_count)
        replacement = raw.containers.resources[prior.name]
        self.assertEqual(replacement.image.id, "sha256:" + "c" * 64)
        self.assertEqual(replacement.attrs["Config"]["User"], "10006")

    def test_secret_observation_transport_interruption_remains_uncertain(self) -> None:
        for interrupted, expected in ((True, EffectResultKind.UNCERTAIN), (False, EffectResultKind.FAILED)):
            with self.subTest(interrupted=interrupted):
                raw = FakeDockerClient()
                product = _product_with_file_secret_delivery()
                interpreter = DockerRuntimeInterpreter(
                    DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw)),
                    secret_resolver=FakeSecretResolver(raw, SecretResolved(
                        SecretReference("secret://local/api-token"), SecretValue("fixture"))))
                request = _request(StartNode(NodeTarget("api")), products=(_material(product),))
                self.assertIs(interpreter.execute(request).kind, EffectResultKind.SUCCEEDED)
                target = raw.containers.resources[_workload_container_record(raw)["name"]]
                target.attrs["State"]["Running"] = False
                target.started = False

                def archive_stream():
                    yield b"incomplete archive prefix"
                    if interrupted:
                        raise OSError("fixture transport interrupted")

                def get_archive(resource, path):
                    return archive_stream(), {}

                with patch.object(FakeResource, "get_archive", get_archive):
                    result = interpreter.execute(request)
                self.assertIs(result.kind, expected)
                self.assertFalse(target.started)
                self.assertFalse(target.removed)
                self.assertTrue(all(helper.force_removed for helper in raw.containers.created_containers
                                    if helper is not target))

    def test_numeric_file_reader_propagates_through_start_and_reuse(self) -> None:
        for user, uid in (("10006", 10006), ("1:1", 1), ("10006:10008", 10006)):
            with self.subTest(user=user):
                self._assert_numeric_reader_start_and_reuse(user, uid)

    def _assert_numeric_reader_start_and_reuse(self, user: str, uid: int) -> None:
        raw = FakeDockerClient()
        product = _product_with_file_secret_delivery()
        reference = product.image.execution_reference
        image = FakeImage([], repo_digests=(reference,))
        image.attrs["Config"]["User"] = user
        raw.images.resources[reference] = image
        resolver = FakeSecretResolver(raw, SecretResolved(
            SecretReference("secret://local/api-token"), SecretValue("fixture")))
        sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
        interpreter = DockerRuntimeInterpreter(sdk, secret_resolver=resolver)
        for effect in (StartNode(NodeTarget("api")), StartNode(NodeTarget("api")), ReconcileNode(NodeTarget("api"))):
            result = interpreter.execute(_request(effect, products=(_material(product),)))
            self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
            record = _workload_container_record(raw)
            self.assertNotIn("user", record)
            self.assertIn(record["image"], (reference, image.id))
            volume = next(item["name"] for item in raw.volumes.created
                          if item["labels"].get("org.openj92.cpk.volume.kind") == "secret-file")
            with tarfile.open(fileobj=BytesIO(raw.containers.volume_archives[volume]["/artifact"]), mode="r") as archive:
                content = archive.getmember("content")
                self.assertEqual(content.uid, uid)
                self.assertEqual(content.mode, 0o400)
            target = raw.containers.resources[record["name"]]
            self.assertEqual(target.attrs["Config"]["User"], user)
            target.attrs["State"]["Running"] = False
        self.assertEqual(len(_workload_container_records(raw)), 1)

    def test_named_user_environment_only_delivery_is_unchanged(self) -> None:
        raw = FakeDockerClient()
        product = _product_with_secret_delivery()
        reference = product.image.execution_reference
        image = FakeImage([], repo_digests=(reference,))
        image.attrs["Config"]["User"] = "application"
        raw.images.resources[reference] = image
        interpreter = DockerRuntimeInterpreter(
            DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw)),
            secret_resolver=FakeSecretResolver(raw, SecretResolved(
                SecretReference("secret://local/api-token"), SecretValue("fixture"))))
        result = interpreter.execute(_request(StartNode(NodeTarget("api")), products=(_material(product),)))
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(_workload_container_record(raw)["environment"]["API_TOKEN"], "fixture")

    def test_unsupported_file_reader_fails_before_any_material_mutation(self) -> None:
        for effect in (StartNode(NodeTarget("api")), ReconcileNode(NodeTarget("api"))):
            for user in ("secrets", "01", "1:group", None):
                with self.subTest(effect=type(effect).__name__, user=user):
                    raw = FakeDockerClient()
                    product = _product_with_file_secret_delivery()
                    reference = product.image.execution_reference
                    image = FakeImage([], repo_digests=(reference,))
                    image.attrs["Config"]["User"] = user
                    raw.images.resources[reference] = image
                    resolver = FakeSecretResolver(raw, SecretResolved(
                        SecretReference("secret://local/api-token"), SecretValue("fixture")))
                    interpreter = DockerRuntimeInterpreter(
                        DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw)),
                        secret_resolver=resolver)
                    result = interpreter.execute(_request(effect, products=(_material(product),)))
                    self.assertIs(result.kind, EffectResultKind.FAILED)
                    self.assertEqual(raw.networks.created, [])
                    self.assertEqual(raw.volumes.created, [])
                    self.assertEqual(raw.containers.created, [])

    def test_reused_file_material_requires_owner_mode_content_and_readonly_mount(self) -> None:
        for effect in (StartNode(NodeTarget("api")), ReconcileNode(NodeTarget("api"))):
            for defect in ("uid", "mode", "content", "type", "missing", "mount", "mount-source", "mount-target", "subpath", "user", "image"):
                with self.subTest(effect=type(effect).__name__, defect=defect):
                    raw = FakeDockerClient()
                    product = _product_with_file_secret_delivery()
                    resolver = FakeSecretResolver(raw, SecretResolved(
                        SecretReference("secret://local/api-token"), SecretValue("fixture")))
                    interpreter = DockerRuntimeInterpreter(
                        DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw)),
                        secret_resolver=resolver)
                    request = _request(StartNode(NodeTarget("api")), products=(_material(product),))
                    self.assertIs(interpreter.execute(request).kind, EffectResultKind.SUCCEEDED)
                    record = _workload_container_record(raw)
                    target = raw.containers.resources[record["name"]]
                    target.attrs["State"]["Running"] = False
                    target.started = False
                    volume = next(item["name"] for item in raw.volumes.created
                                  if item["labels"].get("org.openj92.cpk.volume.kind") == "secret-file")
                    actual_mount = next(mount for mount in target.attrs["Mounts"]
                                        if mount["Name"] == volume and mount["Destination"] == "/run/secrets/api-token")
                    configured_mount = next(mount for mount in target.attrs["HostConfig"]["Mounts"]
                                            if mount["Source"] == volume and mount["Target"] == "/run/secrets/api-token")
                    if defect in ("uid", "mode", "content", "type"):
                        output = BytesIO()
                        with tarfile.open(fileobj=output, mode="w") as archive:
                            content = b"different" if defect == "content" else b"fixture"
                            member = tarfile.TarInfo("content")
                            member.size = len(content)
                            member.uid = 7 if defect == "uid" else 0
                            member.mode = 0o444 if defect == "mode" else 0o400
                            if defect == "type":
                                member.type = tarfile.SYMTYPE
                                member.linkname = "/unrelated"
                            archive.addfile(member, BytesIO(content))
                        raw.containers.volume_archives[volume]["/artifact"] = output.getvalue()
                    elif defect == "missing":
                        raw.containers.volume_archives[volume].clear()
                    elif defect == "mount":
                        actual_mount["RW"] = True
                    elif defect == "mount-source":
                        actual_mount["Name"] = "unrelated-volume"
                    elif defect == "mount-target":
                        actual_mount["Destination"] = "/unrelated"
                    elif defect == "subpath":
                        configured_mount["VolumeOptions"]["Subpath"] = "unrelated"
                    elif defect == "user":
                        target.attrs["Config"]["User"] = "10006"
                    else:
                        target.image.id = "sha256:" + "c" * 64
                    before = dict(raw.containers.volume_archives[volume])
                    volume_count = len(raw.volumes.created)
                    result = interpreter.execute(_request(effect, products=(_material(product),)))
                    self.assertIs(result.kind, EffectResultKind.FAILED)
                    self.assertFalse(target.started)
                    self.assertFalse(target.removed)
                    self.assertEqual(raw.containers.volume_archives[volume], before)
                    self.assertEqual(len(raw.volumes.created), volume_count)

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

    def test_reconcile_node_rejects_authority_change_without_prior_declaration(self) -> None:
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
        _local_socket_transport(fake_client)
        original = fake_client.containers.created_containers[-1]

        with patch(
            "control_plane_kit_interpreters.docker.runtime.os.stat",
            return_value=type("SocketStat", (), {"st_gid": 987})(),
        ):
            result = interpreter.execute(
                _request(
                    ReconcileNode(NodeTarget("api")),
                    authority_ref=RuntimeAuthorityReference("local-docker"),
                    authority_deliveries=(delivery,),
                    products=(_material(_product(), runtime_authority_deliveries=(delivery,)),),
                )
            )

        self.assertIs(result.kind, EffectResultKind.UNSUPPORTED)
        self.assertFalse(original.removed)
        self.assertEqual(len(_workload_container_records(fake_client)), 1)

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
        self.assertEqual(_workload_container_record(fake_client).get("group_add", []), [])

    def test_desktop_conformance_requires_fixed_provider_and_configured_evidence(self):
        for operation_type in (StartNode, ReconcileNode):
            for case, expected in (("qualified", EffectResultKind.SUCCEEDED),
                                   ("omitted", EffectResultKind.SUCCEEDED),
                                   ("version", EffectResultKind.FAILED),
                                   ("unknown", EffectResultKind.UNCERTAIN),
                                   ("null", EffectResultKind.UNCERTAIN),
                                   ("configured-canonical", EffectResultKind.FAILED),
                                   ("configured-foreign", EffectResultKind.FAILED),
                                   ("foreign", EffectResultKind.FAILED)):
                with self.subTest(operation=operation_type.__name__, case=case):
                    raw = FakeDockerClient()
                    _local_socket_transport(raw)
                    raw.info = Mock(return_value={"OperatingSystem": "Docker Desktop", "OSType": "linux"})
                    raw.version = Mock(return_value={"Version": "29.7.3" if case == "version" else "29.7.2", "ApiVersion": "1.55"})
                    provider_error = "token=cpk137-provider-private-value"
                    if case == "unknown":
                        raw.info.side_effect = RuntimeError(provider_error)
                    create = raw.containers.create
                    requested_sources = []
                    def create_with_desktop_mapping(image, **kwargs):
                        requested_sources.extend(mount["Source"] for mount in kwargs["mounts"]
                                                 if mount["Type"] == "bind")
                        resource = create(image, **kwargs)
                        for mount in resource.attrs["Mounts"]:
                            if mount["Type"] == "bind":
                                mount["Source"] = "/foreign" if case == "foreign" else "/run/host-services/docker.proxy.sock"
                        for mount in resource.attrs["HostConfig"]["Mounts"]:
                            if mount["Type"] == "bind":
                                mount["Source"] = (
                                    "/var/run/docker.sock" if case == "configured-canonical" else
                                    "/foreign" if case == "configured-foreign" else
                                    "/run/host-services/docker.proxy.sock")
                                if case == "omitted":
                                    del mount["ReadOnly"]
                                elif case == "null":
                                    mount["ReadOnly"] = None
                        return resource
                    raw.containers.create = create_with_desktop_mapping
                    delivery = RuntimeAuthorityAccessDelivery(RuntimeAuthorityReference("local-docker"), RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT)
                    product = _product()
                    product = replace(product, runtime_contract=replace(product.runtime_contract, configuration_artifacts=()))
                    request = _request(operation_type(NodeTarget("api")), authority_ref=delivery.authority_ref,
                                       authority_deliveries=(delivery,), products=(_material(product, runtime_authority_deliveries=(delivery,)),))
                    with patch("control_plane_kit_interpreters.docker.runtime.os.stat", return_value=type("SocketStat", (), {"st_gid": 987})()):
                        result = DockerRuntimeInterpreter(DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))).execute(request)
                    self.assertIs(result.kind, expected)
                    self.assertEqual(requested_sources, ["/var/run/docker.sock"])
                    self.assertEqual(raw.containers.created_containers[-1].attrs["Mounts"][0]["Source"],
                                     "/foreign" if case == "foreign" else "/run/host-services/docker.proxy.sock")
                    self.assertNotIn(provider_error, repr(result))
                    if expected is not EffectResultKind.SUCCEEDED:
                        self.assertEqual(result.observations, ())

    def test_same_runtime_materials_deliver_socket_only_to_declared_recipient(self):
        raw = FakeDockerClient()
        _local_socket_transport(raw)
        interpreter = DockerRuntimeInterpreter(DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw)))
        reference = RuntimeAuthorityReference("local-docker")
        delivery = RuntimeAuthorityAccessDelivery(reference, RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT)
        # Core's maintained material boundary supplies each selected node; provider
        # registration does not turn the two sibling materials into recipients.
        materials = tuple(replace(
            _material(_product()), node_id=name,
            runtime_authority_deliveries=(delivery,) if name == "controller" else (),
        ) for name in ("controller", "database", "custody"))
        with patch("control_plane_kit_interpreters.docker.runtime.os.stat", return_value=type("SocketStat", (), {"st_gid": 987})()):
            for material in materials:
                request = _request(StartNode(NodeTarget(material.node_id)), products=(material,),
                                   authority_ref=reference, authority_deliveries=material.runtime_authority_deliveries)
                result = interpreter.execute_with_authority(request, _local_runtime_authority())
                self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        records = _workload_container_records(raw)
        self.assertEqual(len(records), 3)
        for material, record in zip(materials, records, strict=True):
            declared = material.node_id == "controller"
            self.assertEqual(len(_bind_mounts(record)), 1 if declared else 0)
            self.assertEqual(record.get("group_add", []), ["987"] if declared else [])

    def test_unsafe_existing_authority_blocks_before_pull_or_runtime_mutation(self):
        for operation_type in (StartNode, ReconcileNode):
            for corruption in ("bind", "group", "missing-mounts", "missing-groups", "volume-at-socket"):
                with self.subTest(operation=operation_type.__name__, corruption=corruption):
                    raw = FakeDockerClient()
                    sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
                    interpreter = DockerRuntimeInterpreter(sdk)
                    request = _request(StartNode(NodeTarget("api")))
                    self.assertIs(interpreter.execute(request).kind, EffectResultKind.SUCCEEDED)
                    container = raw.containers.created_containers[-1]
                    if corruption == "bind":
                        container.attrs["Mounts"].append({"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True})
                    elif corruption == "volume-at-socket":
                        container.attrs["Mounts"].append({"Type": "volume", "Name": "socket", "Destination": "/var/run/docker.sock", "RW": True})
                    elif corruption == "group":
                        container.attrs["HostConfig"]["GroupAdd"] = ["987"]
                    elif corruption == "missing-mounts":
                        del container.attrs["Mounts"]
                    else:
                        del container.attrs["HostConfig"]["GroupAdd"]
                    # A cache miss would tempt the old sequence to pull first.
                    raw.images.resources.clear()
                    with patch.object(sdk, "pull_image", side_effect=AssertionError("pulled before authority guard")) as pull, patch.object(
                        sdk, "create_network", side_effect=AssertionError("network before authority guard"),
                    ) as network, patch.object(sdk, "remove_container") as remove, patch.object(sdk, "start_container") as start:
                        result = interpreter.execute(replace(request, operation=operation_type(NodeTarget("api"))))
                    self.assertIs(result.kind, EffectResultKind.UNSUPPORTED if corruption in ("bind", "group") else EffectResultKind.UNCERTAIN)
                    pull.assert_not_called()
                    network.assert_not_called()
                    remove.assert_not_called()
                    start.assert_not_called()
                    self.assertEqual(len(_workload_container_records(raw)), 1)

    def test_declared_reconcile_reuses_exact_material_but_rejects_changed_fingerprint(self):
        for change in ("none", "plan", "graph", "environment", "image"):
            with self.subTest(change=change):
                raw = FakeDockerClient()
                _local_socket_transport(raw)
                sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
                interpreter = DockerRuntimeInterpreter(sdk)
                delivery = RuntimeAuthorityAccessDelivery(RuntimeAuthorityReference("local-docker"), RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT)
                request = _request(StartNode(NodeTarget("api")), authority_ref=delivery.authority_ref,
                                   authority_deliveries=(delivery,), products=(_material(_product(), runtime_authority_deliveries=(delivery,)),))
                with patch("control_plane_kit_interpreters.docker.runtime.os.stat", return_value=type("SocketStat", (), {"st_gid": 987})()):
                    self.assertIs(interpreter.execute(request).kind, EffectResultKind.SUCCEEDED)
                    desired = replace(request, operation=ReconcileNode(NodeTarget("api")))
                    if change == "plan":
                        desired = replace(desired, source=replace(desired.source, plan_id="new-plan"))
                    elif change == "graph":
                        desired = replace(desired, source=replace(desired.source, desired_graph_id="new-graph"))
                    elif change == "environment":
                        desired = replace(desired, products=(replace(desired.products[0], public_environment=(PublicStaticEnvironmentBinding("VALUE", "new"),)),))
                    elif change == "image":
                        material = desired.products[0]
                        desired = replace(desired, products=(replace(material, product=replace(material.product, image=replace(material.product.image, digest="sha256:" + "c" * 64))),))
                    with patch.object(sdk, "pull_image") as pull, patch.object(sdk, "remove_container") as remove, patch.object(sdk, "create_container") as create:
                        result = interpreter.execute(desired)
                self.assertIs(result.kind, EffectResultKind.SUCCEEDED if change in ("none", "plan") else EffectResultKind.UNSUPPORTED)
                pull.assert_not_called()
                remove.assert_not_called()
                create.assert_not_called()

    def test_remote_selected_socket_rejects_before_tls_resolution_or_factory(self):
        raw = FakeDockerClient()
        sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
        delivery = RuntimeAuthorityAccessDelivery(RuntimeAuthorityReference("remote-docker"), RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT)
        request = _request(StartNode(NodeTarget("api")), authority_ref=delivery.authority_ref,
                           authority_deliveries=(delivery,), products=(_material(_product(), runtime_authority_deliveries=(delivery,)),))
        with patch.object(DockerSdkClient, "from_authority") as factory, patch(
            "control_plane_kit_interpreters.docker.runtime._resolve_runtime_authority_secret",
            side_effect=AssertionError("resolved before recipient locality"),
        ) as resolve:
            result = DockerRuntimeInterpreter(sdk, secret_resolver=object()).execute_with_authority(request, _remote_tls_runtime_authority())
        self.assertIs(result.kind, EffectResultKind.UNSUPPORTED)
        resolve.assert_not_called()
        factory.assert_not_called()
        self.assertEqual(raw.containers.created, [])

    def test_forged_recipient_material_fails_before_provider_or_secret_io(self):
        for authority_entry in (False, True):
            for defect in ("missing", "foreign", "undeclared"):
                with self.subTest(authority_entry=authority_entry, defect=defect):
                    raw = FakeDockerClient()
                    sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
                    delivery = RuntimeAuthorityAccessDelivery(RuntimeAuthorityReference("local-docker"), RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT)
                    material = _material(_product(), runtime_authority_deliveries=(delivery,))
                    request = _request(StartNode(NodeTarget("api")), authority_ref=delivery.authority_ref, authority_deliveries=(delivery,), products=(material,))
                    corrupt = () if defect == "missing" else (replace(material, **(
                        {"node_id": "foreign"} if defect == "foreign" else {"runtime_authority_deliveries": ()}
                    )),)
                    # Simulate a malformed caller crossing the interpreter boundary.
                    object.__setattr__(request, "products", corrupt)
                    with patch.object(sdk, "inspect_container") as inspect_container, patch(
                        "control_plane_kit_interpreters.docker.runtime._client_for_runtime_authority",
                        side_effect=AssertionError("connected before request validation"),
                    ) as connect, patch("control_plane_kit_interpreters.docker.runtime.os.stat") as stat:
                        interpreter = DockerRuntimeInterpreter(sdk)
                        result = interpreter.execute_with_authority(request, _local_runtime_authority()) if authority_entry else interpreter.execute(request)
                    self.assertIs(result.kind, EffectResultKind.FAILED)
                    connect.assert_not_called()
                    inspect_container.assert_not_called()
                    stat.assert_not_called()
                    self.assertEqual(raw.containers.created, [])

    def test_reconcile_matching_fingerprint_does_not_override_foreign_ownership(self):
        raw = FakeDockerClient()
        sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
        interpreter = DockerRuntimeInterpreter(sdk)
        request = _request(StartNode(NodeTarget("api")))
        self.assertIs(interpreter.execute(request).kind, EffectResultKind.SUCCEEDED)
        container = raw.containers.created_containers[-1]
        container.attrs["Config"]["Labels"]["org.openj92.cpk.workspace"] = "foreign"
        with patch.object(sdk, "start_container") as start, patch.object(sdk, "remove_container") as remove:
            result = interpreter.execute(replace(request, operation=ReconcileNode(NodeTarget("api"))))
        self.assertIs(result.kind, EffectResultKind.FAILED)
        start.assert_not_called()
        remove.assert_not_called()
        self.assertEqual(result.observations, ())

    def test_final_authority_drift_cannot_publish_success_observations(self):
        for operation_type in (StartNode, ReconcileNode):
            with self.subTest(operation=operation_type.__name__):
                raw = FakeDockerClient()
                sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
                original_start = FakeResource.start
                injected = []
                def start_with_drift(resource):
                    original_start(resource)
                    if resource.attrs["Config"]["Labels"].get("org.openj92.cpk.kind") == "container":
                        resource.attrs["HostConfig"]["GroupAdd"] = ["unexpected"]
                        injected.append(resource.name)
                with patch.object(FakeResource, "start", start_with_drift):
                    result = DockerRuntimeInterpreter(sdk).execute(_request(operation_type(NodeTarget("api"))))
                self.assertEqual(len(injected), 1)
                self.assertEqual(raw.containers.resources[injected[0]].attrs["HostConfig"]["GroupAdd"], ["unexpected"])
                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertEqual(result.observations, ())

    def test_reconcile_final_inspection_must_exist_and_conform(self):
        for corruption in ("absent", "image", "network", "stopped"):
            with self.subTest(corruption=corruption):
                raw = FakeDockerClient()
                sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
                original_inspect = sdk.inspect_container
                reads = 0
                def inspect_after_create(name):
                    nonlocal reads
                    reads += 1
                    observed = original_inspect(name)
                    if reads == 1:
                        return observed
                    if corruption == "absent":
                        return None
                    changes = {"image_id": "sha256:" + "f" * 64} if corruption == "image" else (
                        {"network_names": ("foreign",)} if corruption == "network" else {"running": False}
                    )
                    return replace(observed, **changes)
                with patch.object(sdk, "inspect_container", side_effect=inspect_after_create):
                    result = DockerRuntimeInterpreter(sdk).execute(_request(ReconcileNode(NodeTarget("api"))))
                self.assertIs(result.kind, EffectResultKind.UNCERTAIN if corruption == "absent" else EffectResultKind.FAILED)
                self.assertEqual(result.observations, ())

    def test_unknown_local_transport_cannot_deliver_or_stat_socket(self):
        raw = FakeDockerClient()
        delivery = RuntimeAuthorityAccessDelivery(RuntimeAuthorityReference("local-docker"), RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT)
        request = _request(StartNode(NodeTarget("api")), authority_ref=delivery.authority_ref,
                           authority_deliveries=(delivery,), products=(_material(_product(), runtime_authority_deliveries=(delivery,)),))
        with patch("control_plane_kit_interpreters.docker.runtime.os.stat") as stat:
            result = DockerRuntimeInterpreter(DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))).execute(request)
        self.assertIs(result.kind, EffectResultKind.UNSUPPORTED)
        stat.assert_not_called()
        self.assertEqual(raw.containers.created, [])

    def test_explicit_local_socket_delivery_mounts_socket_at_docker_boundary(self) -> None:
        fake_client = FakeDockerClient()
        _local_socket_transport(fake_client)
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
                    products=(_material(_product(), runtime_authority_deliveries=(delivery,)),),
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
                products=(_material(_product(), runtime_authority_deliveries=(delivery,)),),
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


def _local_socket_transport(raw, path="/var/run/docker.sock"):
    from docker.transport import UnixHTTPAdapter

    adapter = UnixHTTPAdapter("http+unix://" + path)
    raw.api.base_url = "http+docker://localhost"
    raw.api.get_adapter = lambda url: adapter


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
    runtime_authority_deliveries: tuple[RuntimeAuthorityAccessDelivery, ...] = (),
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
        runtime_authority_deliveries=runtime_authority_deliveries,
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
