from __future__ import annotations

import unittest

from control_plane_kit_core.algebra import BlockSockets, ProviderSocket
from control_plane_kit_core.configuration import (
    ConfigurationArtifact,
    ConfigurationFileMode,
    ConfigurationMediaType,
)
from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
from control_plane_kit_core.operations.execution import EffectResultKind
from control_plane_kit_core.planning import (
    ActivityId,
    NodeTarget,
    RuntimeTarget,
    StartNode,
    StartRuntime,
    StopNode,
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
    RuntimeEffectKind,
    RuntimeEffectRequest,
    RuntimeEffectSource,
    RuntimeProductMaterial,
)
from control_plane_kit_core.secrets import SecretEnvironmentDelivery, SecretReference
from control_plane_kit_core.types import Protocol, RuntimeKind

from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter, DockerSdkClient
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
            ["ghcr.io/openj92/runtime-fixture@sha256:" + "a" * 64],
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
        self.assertEqual(fake_client.containers.created, [])


def _request(
    operation,
    *,
    products: tuple[RuntimeProductMaterial, ...] | None = None,
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
            desired_graph_id="graph-desired",
            intent_event_id="event-started",
        ),
        activity_id=ActivityId("activity-a"),
        operation=operation,
        products=(_material(_product()),) if products is None else products,
    )


def _material(product: ContainerServerProduct) -> RuntimeProductMaterial:
    reference = ProductReference(
        product.identity,
        ProductDescriptorDigest("b" * 64),
    )
    return RuntimeProductMaterial(
        node_id="api",
        runtime_id="docker",
        reference=reference,
        product=product,
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
