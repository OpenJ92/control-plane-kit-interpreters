"""Real listener fixtures for I189; no owner admission or network placement claim."""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import socket

import httpx
import uvicorn
import control_plane_kit_core as core
from control_plane_kit_core.probe_intents import EndpointContext, LiteralEndpointMaterial, RuntimeEndpointObservation
from control_plane_kit_core.runtime_effects import RuntimeEffectKind, RuntimeEffectRequest
from control_plane_kit_core.topology import validate_graph
from control_plane_kit_interpreters.probes.health_signing import Ed25519HealthCredentialPairSigner, HealthSigningKey
from control_plane_kit_interpreters.probes.health_transport import SignedGatewayHealthClient
from control_plane_kit_interpreters.probes.security import ProbeAddressPolicy
from control_plane_kit_servers_cpk_local_gateway.control_configuration import decode_gateway_control_configuration
from control_plane_kit_servers_cpk_local_gateway.health_relay import GatewayHealthRelay
from control_plane_kit_servers_cpk_local_gateway.health_relay_configuration import (
    GatewayHealthRelayConfiguration, GatewayHealthTargetBinding, gateway_health_relay_configuration_artifact,
)
from control_plane_kit_servers_cpk_local_gateway.health_transit_verification import gateway_health_transit_verifier_from_artifact
from control_plane_kit_servers_cpk_local_gateway.server import create_app
from health_signing_fixtures import RecordingResolver
from health_transport_fixtures import Transport
from docker_management_health_fixtures import BootstrapWorld


class LocalWorld(BootstrapWorld):
    """Real nonfresh workload introduction retains gateway/connector/ingress."""
    def __init__(self):
        super().__init__(core.ManagementBootstrapStage.AUTHENTICATED_MANAGEMENT_PATH)
        retained = {self.value.gateway.value, self.ingress.connector_node_id}
        graph = self.desired.graph
        self.current = validate_graph(replace(graph,
            nodes={key:node for key, node in graph.nodes.items() if key in retained},
            runtimes={key:replace(runtime, children=tuple(node for node in runtime.children if node in retained))
                for key, runtime in graph.runtimes.items()}))
        self.current.require_valid()
        self.plan = core.compile_graph_activity_plan(self.current, self.desired)
        assert self.plan.ready_for_execution
        activity, = (item for item in self.plan.activities
            if type(item.operation) is core.ObserveManagementBootstrap
            and item.operation.stage is core.ManagementBootstrapStage.GATEWAY_LOCAL_READY)
        self.activity_id, self.operation = activity.activity_id, activity.operation
        self.resign(request_id="request-gateway-local-ready", attempt_id="attempt-gateway-local-ready")
        core.resolve_management_observation(self.operation, self.current, self.desired,
            expected_operation=self.plan.activity(self.activity_id).operation)


@asynccontextmanager
async def serving(app):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False,
        lifespan="on", timeout_graceful_shutdown=1))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if task.done():
                    await task
                    raise AssertionError("test listener did not start")
                await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 5)
        finally:
            listener.close()
        assert task.done() and listener.fileno() == -1
        absent = False
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 1)
        except OSError:
            absent = True
        if not absent:
            writer.close()
            await writer.wait_closed()
            raise AssertionError("owned test listener remains reachable")


def local_destination(module, value, origin="http://127.0.0.1:18000"):
    endpoint = RuntimeEndpointObservation(value.value.gateway.value,
        value.value.gateway_target.provider_socket_name.value, "revision-a", core.Protocol.HTTP,
        EndpointContext.RUNTIME_PRIVATE, LiteralEndpointMaterial(origin))
    return module.SelectedLocalGateway(endpoint, ProbeAddressPolicy(runtime_private_authorities=frozenset({origin})))


def make_reader(module, value, *, transport=None, timeout=5):
    keys = RecordingResolver(value.value)
    reader = module.DockerManagedHealthReader(
        Ed25519HealthCredentialPairSigner(keys, lambda:value.now),
        SignedGatewayHealthClient(clock=lambda:value.now, public_resolver=value.resolver,
            transport=value.gateway_transport),
        module.LocalGatewayHealthClient(clock=lambda:value.now, transport=transport, timeout_seconds=timeout))
    return reader, keys


async def read(reader, value, *, destination=None, local=None, **changes):
    request = RuntimeEffectRequest("event-a", RuntimeEffectKind.REALIZE_ACTIVITY, core.RuntimeKind.DOCKER,
        value.source, value.activity_id, value.operation)
    values = dict(request=request, plan=value.plan, current=value.current, desired=value.desired,
        authority_context=value.authority_context, context=value.context,
        transit_grant=value.value.transit, workload_grant=value.value.workload,
        transit_key=HealthSigningKey(value.value.publics[0], value.value.resolutions[0]),
        workload_key=HealthSigningKey(value.value.publics[1], value.value.resolutions[1]),
        destination=destination, local_destination=local)
    values.update(changes)
    return await reader.observe(**values)


def socket_relay(value, receiver_origin):
    """Public ingress is in-process; the relay's outgoing HTTP is a real socket."""
    routes = GatewayHealthRelayConfiguration(value.value.gateway_target, (
        GatewayHealthTargetBinding("workload-management", value.value.target,
            value.value.declaration, receiver_origin),))
    artifact = gateway_health_relay_configuration_artifact(routes)
    node = value.desired.graph.nodes[value.value.gateway.value]
    artifacts = tuple(artifact if item.artifact_id == artifact.artifact_id else item
        for item in node.configuration_artifacts)
    node = replace(node, configuration_artifacts=artifacts)
    value.desired = validate_graph(replace(value.desired.graph,
        nodes={**value.desired.graph.nodes, node.node_id:node}))
    value.desired.require_valid()
    value.plan = core.compile_graph_activity_plan(value.current, value.desired)
    assert value.plan.ready_for_execution
    activity, = (item for item in value.plan.activities if type(item.operation) is core.ObserveNodeHealth)
    value.activity_id, value.operation = activity.activity_id, activity.operation
    relay = GatewayHealthRelay(routes, gateway_health_transit_verifier_from_artifact(value.artifacts[0]),
        clock=lambda:value.now)
    gateway = create_app(health_relay=relay,
        control_configuration=decode_gateway_control_configuration(value.artifacts[2].content.encode()),
        clock=lambda:value.now)
    value.gateway_transport = Transport(httpx.ASGITransport(app=gateway))
    return gateway
