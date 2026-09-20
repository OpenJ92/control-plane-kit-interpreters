"""Pinned workload selection followed by one original signed gateway dispatch.

Construction is not admission. The caller owns accepted-record provenance,
current authority, installed relay alias selection and durable result folding.
"""
from dataclasses import dataclass
from enum import StrEnum

from control_plane_kit_core.node_control import (
    NodeControlGraphReference, NodeControlGraphReferenceRole, NodeControlTarget,
    WorkloadNodeControlSurfaceDeclaration, WorkloadNodeControlSurfaceDeclarationProfile,
)
from control_plane_kit_core.node_health_reads import DelegatedWorkloadNodeHealthReadGrant
from control_plane_kit_core.node_health_transit import DelegatedGatewayNodeHealthReadTransitGrant
from control_plane_kit_core.planning import (
    ActivityId, ActivityOperation, ActivityPlan, ObserveNodeHealth, PlanGraphSide,
    resolve_management_observation,
)
from control_plane_kit_core.runtime_effects import RuntimeEffectSource
from control_plane_kit_core.topology import ValidatedGraph
from control_plane_kit_core.types import RuntimeKind

from control_plane_kit_interpreters.probes.health_signing import HealthSigningContext, SignedHealthCredentialPair
from control_plane_kit_interpreters.probes.health_transport import (
    GatewayHealthTransportResult, SelectedManagementGateway, SignedGatewayHealthClient,
)


class DockerHealthObservationRefusalCode(StrEnum):
    UNSUPPORTED_OPERATION = "unsupported-operation"
    INVALID_SELECTION = "invalid-selection"
    UNSUPPORTED_RUNTIME = "unsupported-runtime"


@dataclass(frozen=True, slots=True)
class DockerHealthObservationRefused:
    code: DockerHealthObservationRefusalCode

    def __post_init__(self):
        if type(self.code) is not DockerHealthObservationRefusalCode:
            raise ValueError("Docker health observation refusal is invalid")


DockerHealthObservationResult = GatewayHealthTransportResult | DockerHealthObservationRefused


@dataclass(frozen=True, slots=True, repr=False)
class DockerManagedHealthObserver:
    client: SignedGatewayHealthClient

    def __post_init__(self):
        if type(self.client) is not SignedGatewayHealthClient:
            raise TypeError("Docker health observation requires the signed gateway client")

    async def observe(
        self, operation: ActivityOperation, *, plan: ActivityPlan, activity_id: ActivityId,
        source: RuntimeEffectSource, current: ValidatedGraph, desired: ValidatedGraph,
        context: HealthSigningContext, pair: SignedHealthCredentialPair,
        transit_grant: DelegatedGatewayNodeHealthReadTransitGrant,
        workload_grant: DelegatedWorkloadNodeHealthReadGrant,
        destination: SelectedManagementGateway,
    ) -> DockerHealthObservationResult:
        if type(operation) is not ObserveNodeHealth:
            return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.UNSUPPORTED_OPERATION)
        # A bootstrap request must return above before any protected input access.
        try:
            if (type(plan) is not ActivityPlan or type(activity_id) is not ActivityId
                    or type(source) is not RuntimeEffectSource
                    or type(context) is not HealthSigningContext
                    or type(destination) is not SelectedManagementGateway):
                raise ValueError
            source.__post_init__()
            expected = plan.activity(activity_id).operation
            resolved = resolve_management_observation(operation, current, desired,
                expected_operation=expected)
            runtime = resolved.selected_graph.graph.runtimes[operation.target.runtime_id]
            if runtime.kind is not RuntimeKind.DOCKER:
                return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.UNSUPPORTED_RUNTIME)
            roles = NodeControlGraphReferenceRole
            revision = (source.base_graph_id if operation.target.graph_side is PlanGraphSide.BASE_GRAPH
                else source.desired_graph_id)
            target = NodeControlTarget(
                NodeControlGraphReference(roles.WORKSPACE, source.workspace_id),
                NodeControlGraphReference(roles.GRAPH_REVISION, revision),
                NodeControlGraphReference(roles.NODE, resolved.workload_node.node_id),
                NodeControlGraphReference(roles.PROVIDER_SOCKET, operation.provider_socket_name))
            runtime_id = NodeControlGraphReference(roles.RUNTIME, operation.target.runtime_id)
            gateway = NodeControlGraphReference(roles.NODE, resolved.gateway_node.node_id)
            declaration = WorkloadNodeControlSurfaceDeclaration(resolved.workload_surface,
                WorkloadNodeControlSurfaceDeclarationProfile.V2)
            request = context.request
            if (request.target != target or request.runtime_id != runtime_id
                    or request.kind is not operation.health_kind
                    or request.declaration_identity != declaration.identity()
                    or context.declaration != declaration or context.gateway_node_id != gateway
                    or destination.ingress != resolved.ingress
                    or destination.gateway_node_id != gateway or destination.runtime_id != runtime_id
                    or destination.gateway_transit_provider_socket_name
                        != resolved.gateway_node.block_spec.gateway_transit.provider_socket_name):
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.INVALID_SELECTION)

        # #147 validates the complete original pair/window before DNS/HTTP, and
        # receivers authenticate it. No retry, renewal, signing or private fallback.
        return await self.client.dispatch(context, pair, destination,
            transit_grant=transit_grant, workload_grant=workload_grant)
