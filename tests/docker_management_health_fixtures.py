"""Real selected product/plan/signing fixtures; no approval or lifecycle emulator."""
from dataclasses import replace

import httpx
import control_plane_kit_core as core
from control_plane_kit_core.algebra import BlockSockets, BlockSpec, ProviderSocket
from control_plane_kit_core.capabilities import CapabilityName
from control_plane_kit_core.operations.run_identity import RunId
from control_plane_kit_core.planning import ActivityId, ActivityPlan, PlannedActivity
from control_plane_kit_core.runtime_effects import RuntimeEffectSource
from control_plane_kit_core.topology import DeploymentGraph, Node, RuntimeRecord, validate_graph
from control_plane_kit_core.topology.graph import Endpoint, LiteralAddress
from control_plane_kit_core.types import BlockFamily, Protocol, RuntimeKind
from control_plane_kit_server_sdk.verifier_keys import (
    WorkloadNodeControlSurfaceReadVerifierKeySet, WorkloadNodeHealthReadVerifierKeySet,
)
from control_plane_kit_servers_cpk_local_gateway.control_configuration import (
    GatewayControlConfiguration, gateway_control_configuration_artifact, gateway_control_declaration,
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
from health_signing_fixtures import key, RecordingResolver
from health_transport_fixtures import World, Transport
from receiver_configuration_fixtures import gateway_artifact


class ManagedWorld(World):
    def __init__(self, kind=core.NodeHealthReadKind.READINESS, runtime_kind=RuntimeKind.DOCKER):
        super().__init__(kind)
        if kind is core.NodeHealthReadKind.LIVENESS:
            self.resign(declaration=replace(self.value.declaration,
                surface=replace(self.value.declaration.surface, health_reads=(kind,))))
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

    def resign(self, *, target=None, runtime=None, declaration=None, gateway=None):
        value = self.value
        value.target = value.target if target is None else target
        value.runtime = value.runtime if runtime is None else runtime
        value.declaration = value.declaration if declaration is None else declaration
        value.gateway = value.gateway if gateway is None else gateway
        value.request = replace(value.request, target=value.target, runtime_id=value.runtime,
            declaration_identity=value.declaration.identity())
        fields = dict(target=value.target, runtime_id=value.runtime,
            declaration_identity=value.declaration.identity(), request_digest=value.request.canonical_digest())
        value.transit = replace(value.transit, gateway_node_id=value.gateway, **fields)
        value.workload = replace(value.workload, audience=core.workload_node_control_audience(value.target), **fields)
        value.resolutions = tuple(replace(item, workspace_id=value.target.workspace_id.value)
            for item in value.resolutions)
        self.context = HealthSigningContext(value.request, "attempt-a", value.gateway,
            value.declaration, "transit-issuer", "workload-issuer")
        self.pair = Ed25519HealthCredentialPairSigner(RecordingResolver(value), lambda:self.now).sign(
            self.context, transit_grant=value.transit, workload_grant=value.workload,
            transit_key=HealthSigningKey(value.publics[0], value.resolutions[0]),
            workload_key=HealthSigningKey(value.publics[1], value.resolutions[1]))

    def install_receivers(self):
        value = self.value
        own_target = replace(value.target, node_id=value.gateway)
        own = GatewayControlConfiguration(target=own_target, runtime_id=value.runtime,
            declaration=gateway_control_declaration(), surface_issuer="surface-issuer",
            surface_keys=WorkloadNodeControlSurfaceReadVerifierKeySet(
                core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ, (key("own-surface")[1],)),
            health_issuer="workload-issuer", health_keys=WorkloadNodeHealthReadVerifierKeySet(
                core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ, (value.publics[1],)))
        configuration = GatewayHealthRelayConfiguration(value.target.workspace_id, value.gateway, value.runtime,
            (GatewayHealthTargetBinding("workload-management", value.target, value.runtime,
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
            BlockSpec("gateway", capabilities=contract.capabilities, verification=contract.verification,
                control_surfaces=contract.control_surfaces, gateway_transit=contract.gateway_transit),
            "container-server", value.runtime.value, contract.sockets,
            configuration_artifacts=contract.configuration_artifacts,
            endpoints={port.provider_socket:Endpoint(LiteralAddress(f"http://gateway-a:{port.container_port}"),
                Protocol.HTTP) for port in contract.provider_ports})
        workload = Node(value.target.node_id.value, BlockFamily.APPLICATION,
            BlockSpec("workload", capabilities=(CapabilityName.HEALTH_CHECKABLE, CapabilityName.NODE_CONTROLLABLE),
                control_surfaces=(value.declaration.surface,)), "container-server", value.runtime.value,
            BlockSockets(providers=(ProviderSocket("control", Protocol.HTTP),)),
            endpoints={"control":Endpoint(LiteralAddress("http://workload-a:8087"), Protocol.HTTP)})
        connector = Node("connector-a", BlockFamily.APPLICATION, BlockSpec("connector"),
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
            pair=self.pair, transit_grant=self.value.transit, workload_grant=self.value.workload,
            destination=self.destination(health_transport))
        values.update(changes)
        return await module.DockerManagedHealthObserver(client or self.client(health_transport)).observe(**values)
