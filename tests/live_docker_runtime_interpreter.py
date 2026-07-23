"""Live Docker proof for RuntimeEffectRequest -> Docker SDK interpretation."""

from __future__ import annotations

import json

from control_plane_kit_core.algebra import BlockSockets, ProviderSocket
from control_plane_kit_core.operations.execution import EffectResultKind
from control_plane_kit_core.planning import (
    ActivityId,
    NodeTarget,
    RuntimeTarget,
    StartNode,
    StartRuntime,
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
from control_plane_kit_core.types import Protocol, RuntimeKind

from control_plane_kit_interpreters.docker import (
    DockerRuntimeInterpreter,
    DockerSdkClient,
)


def main() -> None:
    sdk = DockerSdkClient()
    interpreter = DockerRuntimeInterpreter(sdk)
    start_runtime = _request(
        StartRuntime(RuntimeTarget("docker")),
        products=(),
    )
    start_node = _request(StartNode(NodeTarget("api")))
    container_name = None
    network_name = None
    try:
        runtime_result = interpreter.execute(start_runtime)
        if runtime_result.kind is not EffectResultKind.SUCCEEDED:
            raise AssertionError(runtime_result.descriptor())
        network_name = str(runtime_result.evidence["network"])

        node_result = interpreter.execute(start_node)
        if node_result.kind is not EffectResultKind.SUCCEEDED:
            raise AssertionError(node_result.descriptor())
        container_name = str(node_result.evidence["container"])
        container = sdk.inspect_container(container_name)
        if container is None or not container.running:
            raise AssertionError("runtime interpreter did not leave a running container")
        if not node_result.observations:
            raise AssertionError("runtime interpreter did not return endpoint observations")
    finally:
        for action, name in (
            (sdk.remove_container, container_name),
            (sdk.remove_network, network_name),
        ):
            if name:
                try:
                    action(name)
                except Exception:
                    pass

    print(
        json.dumps(
            {
                "status": "passed",
                "runtime_effect": "docker",
                "container_was_running": True,
                "observations": len(node_result.observations),
            },
            sort_keys=True,
        )
    )


def _request(
    operation,
    *,
    products: tuple[RuntimeProductMaterial, ...] | None = None,
) -> RuntimeEffectRequest:
    return RuntimeEffectRequest(
        effect_id=f"effect-{operation.__class__.__name__.lower()}",
        kind=RuntimeEffectKind.REALIZE_ACTIVITY,
        runtime_kind=RuntimeKind.DOCKER,
        source=RuntimeEffectSource(
            workspace_id="live-workspace",
            request_id="live-request",
            run_id="live-run",
            plan_id="live-plan",
            base_graph_id="live-base-graph",
            desired_graph_id="live-desired-graph",
            intent_event_id="live-intent",
        ),
        activity_id=ActivityId("live-activity"),
        operation=operation,
        products=(_material(),) if products is None else products,
    )


def _material() -> RuntimeProductMaterial:
    identity = ProductIdentity("control-plane-kit", "live-runtime-server", 1)
    product = ContainerServerProduct(
        identity=identity,
        image=OciImageReference(
            registry="docker.io",
            repository="library/nginx",
            digest="sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752",
            tag="alpine",
        ),
        runtime_contract=ProductRuntimeContract(
            sockets=BlockSockets(
                providers=(ProviderSocket("internal", Protocol.HTTP),),
            ),
            provider_ports=(ProviderRuntimePort("internal", 80),),
        ),
    )
    return RuntimeProductMaterial(
        node_id="api",
        runtime_id="docker",
        reference=ProductReference(identity, ProductDescriptorDigest("c" * 64)),
        product=product,
    )


if __name__ == "__main__":
    main()
