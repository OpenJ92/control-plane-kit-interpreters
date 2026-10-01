"""Real selected product/plan/signing fixtures; no approval or lifecycle emulator."""
from dataclasses import replace

import httpx
import control_plane_kit_core as core
from control_plane_kit_core.algebra import BlockSockets, BlockSpec, ProviderSocket
from control_plane_kit_core.capabilities import CapabilityName
from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
from control_plane_kit_core.operations.run_identity import RunId
from control_plane_kit_core.planning import ActivityId, ActivityPlan, PlannedActivity
from control_plane_kit_core.runtime_effects import RuntimeEffectSource
from control_plane_kit_core.topology import DeploymentGraph, Node, RuntimeRecord, validate_graph
from control_plane_kit_core.topology.graph import Endpoint, LiteralAddress
from control_plane_kit_core.types import BlockFamily, Protocol, RuntimeKind
from control_plane_kit_servers_cpk_local_gateway.control_configuration import (
    gateway_control_configuration_artifact, gateway_control_declaration,
    decode_gateway_control_configuration,
)
from control_plane_kit_servers_cpk_local_gateway.health_relay import GatewayHealthRelay
from control_plane_kit_servers_cpk_local_gateway.health_relay_configuration import (
    GatewayHealthRelayConfiguration, GatewayHealthTargetBinding,
    gateway_health_relay_configuration_artifact, gateway_health_source_runtime_contract,
)
from control_plane_kit_servers_cpk_local_gateway.health_transit_verification import gateway_health_transit_verifier_from_artifact
from control_plane_kit_servers_cpk_local_gateway.server import create_app
from control_plane_kit_interpreters.probes import health_transport
from control_plane_kit_interpreters.probes.health_signing import (
    Ed25519HealthCredentialPairSigner, HealthSigningContext, HealthSigningKey,
)
from health_signing_fixtures import RecordingResolver
from health_transport_fixtures import World, Transport
from receiver_configuration_fixtures import gateway_artifact, receiver_configuration, receiver_artifact


class ManagedWorld(World):
    def __init__(self, kind=core.NodeHealthReadKind.READINESS, runtime_kind=RuntimeKind.DOCKER):
        super().__init__(kind)
        if kind is core.NodeHealthReadKind.LIVENESS:
            self.resign(declaration=replace(self.value.declaration,
                surface=replace(self.value.declaration.surface, health_reads=(kind,))))
        # Independent caller authority; resigning a foreign request below does
        # not silently rewrite this accepted projection supplied to the observer.
        self.authority_context = self.value.authority_context
        self.install_receivers()
        self.current, self.desired = self.graphs(runtime_kind)
        self.plan = core.compile_graph_activity_plan(self.current, self.desired)
        if not self.plan.ready_for_execution:
            raise AssertionError("actual managed fixture must compile without review blockers")
        activity, = (item for item in self.plan.activities if type(item.operation) is core.ObserveNodeHealth)
        self.activity_id, self.operation = activity.activity_id, activity.operation
        self.source = RuntimeEffectSource(workspace_id="workspace-a", request_id="request-a",
            run_id=RunId("run-a"), plan_id="plan-a", base_graph_id="base-revision",
            desired_graph_id="revision-a", intent_event_id="event-a")
        core.resolve_management_observation(self.operation, self.current, self.desired,
            expected_operation=self.plan.activity(self.activity_id).operation)

    def resign(self, *, target=None, runtime=None, declaration=None, gateway=None,
               gateway_target=None, authority_context=None,
               request_id=None, attempt_id="attempt-a", kind=None):
        value = self.value
        value.target = value.target if target is None else target
        if runtime is not None:
            value.target = replace(value.target, runtime_id=runtime)
        value.runtime = value.target.runtime_id
        value.declaration = value.declaration if declaration is None else declaration
        value.gateway = value.gateway if gateway is None else gateway
        value.gateway_target = (replace(value.gateway_target, workspace_id=value.target.workspace_id,
            runtime_id=value.runtime, node_id=value.gateway) if gateway_target is None else gateway_target)
        value.authority_context = value.authority_context if authority_context is None else authority_context
        value.request = replace(value.request, target=value.target, authority_context=value.authority_context,
            declaration_identity=value.declaration.identity(),
            request_id=value.request.request_id if request_id is None else request_id,
            kind=value.request.kind if kind is None else kind)
        fields = dict(target=value.target, authority_context=value.authority_context,
            declaration_identity=value.declaration.identity(), request_digest=value.request.canonical_digest(),
            request_id=value.request.request_id, kind=value.request.kind)
        value.transit = replace(value.transit, gateway_target=value.gateway_target, attempt_id=attempt_id, **fields)
        value.workload = replace(value.workload, audience=core.receiver_node_control_audience(value.target), **fields)
        value.resolutions = tuple(replace(item, workspace_id=value.target.workspace_id.value,
            operation_id=attempt_id)
            for item in value.resolutions)
        self.context = HealthSigningContext(value.request, attempt_id, value.gateway_target,
            value.declaration, "transit-issuer", "workload-issuer")
        self.pair = Ed25519HealthCredentialPairSigner(RecordingResolver(value), lambda:self.now).sign(
            self.context, transit_grant=value.transit, workload_grant=value.workload,
            transit_key=HealthSigningKey(value.publics[0], value.resolutions[0]),
            workload_key=HealthSigningKey(value.publics[1], value.resolutions[1]))

    def install_receivers(self):
        value = self.value
        own = receiver_configuration(value.gateway_target, gateway_control_declaration(), value.publics[1])
        configuration = GatewayHealthRelayConfiguration(value.gateway_target,
            (GatewayHealthTargetBinding("workload-management", value.target,
                value.declaration, "http://workload-a:8087"),))
        self.artifacts = (gateway_artifact(value), gateway_health_relay_configuration_artifact(configuration),
            gateway_control_configuration_artifact(own))
        self.contract = gateway_health_source_runtime_contract(*self.artifacts)
        self.workload_transport = Transport(httpx.ASGITransport(app=self.workload_app()))
        relay = GatewayHealthRelay(configuration, gateway_health_transit_verifier_from_artifact(self.artifacts[0]),
            clock=lambda:self.now, transport=self.workload_transport)
        self.gateway_app = create_app(health_relay=relay, control_configuration=own, clock=lambda:self.now)
        self.gateway_transport = Transport(httpx.ASGITransport(app=self.gateway_app))

    def graphs(self, runtime_kind):
        value, contract = self.value, self.contract
        gateway = Node(value.gateway.value, BlockFamily.APPLICATION,
            BlockSpec(value.gateway.value, capabilities=contract.capabilities, verification=contract.verification,
                control_surfaces=contract.control_surfaces, gateway_transit=contract.gateway_transit),
            "container-server", value.runtime.value, contract.sockets,
            configuration_artifacts=contract.configuration_artifacts,
            public_environment=contract.public_environment,
            endpoints={port.provider_socket:Endpoint(LiteralAddress(f"http://gateway-a:{port.container_port}"),
                Protocol.HTTP) for port in contract.provider_ports})
        workload_configuration = receiver_configuration(value.target, value.declaration, value.publics[1])
        workload_artifact = receiver_artifact(workload_configuration)
        workload = Node(value.target.node_id.value, BlockFamily.APPLICATION,
            BlockSpec(value.target.node_id.value, capabilities=(CapabilityName.HEALTH_CHECKABLE, CapabilityName.NODE_CONTROLLABLE),
                control_surfaces=(value.declaration.surface,)), "container-server", value.runtime.value,
            BlockSockets(providers=(ProviderSocket("control", Protocol.HTTP),)),
            configuration_artifacts=(workload_artifact,),
            public_environment=(PublicStaticEnvironmentBinding("CPK_WRAPPER_CONFIGURATION_FILE",
                workload_artifact.target_path),),
            endpoints={"control":Endpoint(LiteralAddress("http://workload-a:8087"), Protocol.HTTP)})
        connector = Node("connector-a", BlockFamily.APPLICATION, BlockSpec("connector-a"),
            "container-server", value.runtime.value, BlockSockets())
        nodes = {item.node_id:item for item in (gateway, workload, connector)}
        graph = DeploymentGraph("managed-health", nodes=nodes,
            runtimes={value.runtime.value:RuntimeRecord(value.runtime.value, runtime_kind, tuple(nodes),
                management=core.RuntimeManagement(value.gateway.value, self.ingress.ingress_id))},
            public_ingresses=(self.ingress,))
        current, desired = validate_graph(DeploymentGraph("managed-health")), validate_graph(graph)
        current.require_valid()
        desired.require_valid()
        return current, desired

    def base_side(self):
        # Explicit plan-held base-side operation supported by the real resolver;
        # the initial-deployment compiler above emits desired-side obligations.
        self.current = self.desired
        self.operation = replace(self.operation, target=replace(self.operation.target,
            graph_side=core.PlanGraphSide.BASE_GRAPH))
        self.activity_id = ActivityId("base-health")
        self.plan = ActivityPlan((PlannedActivity(self.activity_id, self.operation),))
        self.source = replace(self.source, base_graph_id="revision-a", desired_graph_id="other-revision")
        core.resolve_management_observation(self.operation, self.current, self.desired,
            expected_operation=self.plan.activity(self.activity_id).operation)

    async def observe(self, module, *, client=None, **changes):
        values = dict(operation=self.operation, plan=self.plan, activity_id=self.activity_id,
            source=self.source, current=self.current, desired=self.desired, context=self.context,
            authority_context=self.authority_context,
            pair=self.pair, transit_grant=self.value.transit, workload_grant=self.value.workload,
            destination=self.destination(health_transport))
        values.update(changes)
        return await module.DockerManagedHealthObserver(client or self.client(health_transport)).observe(**values)


class BootstrapWorld(ManagedWorld):
    """Actual compiled stage and same-app relay/self SDK; no durable admission."""
    def __init__(self, stage, runtime_kind=RuntimeKind.DOCKER):
        super().__init__(runtime_kind=runtime_kind)
        own = decode_gateway_control_configuration(self.artifacts[2].content.encode())
        self.resign(target=own.target, declaration=own.declaration,
            request_id="request-" + stage.value, attempt_id="attempt-" + stage.value)
        binding = GatewayHealthTargetBinding("arbitrary-self-alias", own.target,
            own.declaration, "http://gateway-a:8000")
        configuration = GatewayHealthRelayConfiguration(own.target, (binding,))
        self.artifacts = (self.artifacts[0], gateway_health_relay_configuration_artifact(configuration), self.artifacts[2])
        self.contract = gateway_health_source_runtime_contract(*self.artifacts)
        gateway = self.desired.graph.node(own.target.node_id.value)
        gateway = replace(gateway, configuration_artifacts=self.contract.configuration_artifacts)
        self.desired = validate_graph(replace(self.desired.graph,
            nodes={**self.desired.graph.nodes, gateway.node_id:gateway}))
        self.desired.require_valid()
        self.plan = core.compile_graph_activity_plan(self.current, self.desired)
        if not self.plan.ready_for_execution:
            raise AssertionError("actual bootstrap fixture must compile without review blockers")
        activity, = (item for item in self.plan.activities if type(item.operation) is core.ObserveManagementBootstrap
                     and item.operation.stage is stage)
        self.activity_id, self.operation = activity.activity_id, activity.operation
        core.resolve_management_observation(self.operation, self.current, self.desired,
            expected_operation=self.plan.activity(self.activity_id).operation)
        # The internal transport is wired only after constructing the same app.
        # It never calls a substitute workload server or fabricates a response.
        self.workload_transport = Transport(None)
        relay = GatewayHealthRelay(configuration, gateway_health_transit_verifier_from_artifact(self.artifacts[0]),
            clock=lambda:self.now, transport=self.workload_transport)
        self.gateway_app = create_app(health_relay=relay, control_configuration=own, clock=lambda:self.now)
        self.workload_transport.inner = httpx.ASGITransport(app=self.gateway_app)
        self.gateway_transport = Transport(httpx.ASGITransport(app=self.gateway_app))

    def destination(self, module):
        return replace(super().destination(module), target_id="arbitrary-self-alias")
