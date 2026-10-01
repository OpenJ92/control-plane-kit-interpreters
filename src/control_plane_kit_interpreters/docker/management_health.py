"""Pinned health selection followed by one original signed gateway dispatch.

Construction is not admission. The caller owns accepted-record provenance,
current authority, installed relay alias selection and durable result folding.
"""
from dataclasses import dataclass
from enum import StrEnum

from control_plane_kit_core.node_control import (
    NodeControlGraphReference, NodeControlGraphReferenceRole, NodeHealthReadKind,
)
from control_plane_kit_core.node_control_surface_reads import (
    WorkloadNodeControlSurfaceDeclaration, WorkloadNodeControlSurfaceDeclarationProfile,
)
from control_plane_kit_core.receiver_health_reads import DelegatedWorkloadReceiverHealthReadGrant
from control_plane_kit_core.receiver_health_transit import DelegatedGatewayReceiverHealthReadTransitGrant
from control_plane_kit_core.receiver_configuration import (
    ReceiverNodeControlConfigurationCodec, select_receiver_node_control_configuration_artifact,
)
from control_plane_kit_core.receiver_identity import NodeControlAuthorityContext, NodeControlAuthorityContextCodec
from control_plane_kit_core.planning import (
    ActivityId, ActivityOperation, ActivityPlan, ObserveNodeHealth, PlanGraphSide,
    ObserveManagementBootstrap, ManagementBootstrapStage,
    resolve_management_observation,
)
from control_plane_kit_core.runtime_effects import RuntimeEffectSource
from control_plane_kit_core.runtime_management import GatewayTransitProtocol
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
        authority_context: NodeControlAuthorityContext,
        context: HealthSigningContext, pair: SignedHealthCredentialPair,
        transit_grant: DelegatedGatewayReceiverHealthReadTransitGrant,
        workload_grant: DelegatedWorkloadReceiverHealthReadGrant,
        destination: SelectedManagementGateway,
    ) -> DockerHealthObservationResult:
        bootstrap = type(operation) is ObserveManagementBootstrap
        if (type(operation) is not ObserveNodeHealth and not (bootstrap and operation.stage in (
                ManagementBootstrapStage.AUTHENTICATED_MANAGEMENT_PATH,
                ManagementBootstrapStage.GATEWAY_INGRESS_READY))):
            return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.UNSUPPORTED_OPERATION)
        # Unsupported local/native/legacy requests never read protected inputs.
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
            # Operations supplies current authority independently of the signed
            # request and installed receiver. This adapter owns no projection store.
            authority = NodeControlAuthorityContextCodec().decode(
                NodeControlAuthorityContextCodec().encode(authority_context))
            if authority != authority_context or authority.authored_graph_id != revision:
                raise ValueError
            if bootstrap:
                node = resolved.gateway_node
                socket = resolved.gateway_readiness_socket
                health_kind = NodeHealthReadKind.READINESS
                surfaces = tuple(surface for surface in node.block_spec.control_surfaces
                    if surface.provider_socket_name.value == socket and health_kind in surface.health_reads)
                if len(surfaces) != 1:
                    raise ValueError
                surface, = surfaces
            else:
                node, surface = resolved.workload_node, resolved.workload_surface
                socket, health_kind = operation.provider_socket_name, operation.health_kind
            runtime_id = NodeControlGraphReference(roles.RUNTIME, operation.target.runtime_id)
            gateway = NodeControlGraphReference(roles.NODE, resolved.gateway_node.node_id)
            installed = _receiver(node, source.workspace_id, runtime_id, socket)
            gateway_surfaces = tuple(surface for surface in resolved.gateway_node.block_spec.control_surfaces
                if NodeHealthReadKind.READINESS in surface.health_reads)
            if len(gateway_surfaces) != 1:
                raise ValueError
            gateway_installed = _receiver(resolved.gateway_node, source.workspace_id,
                runtime_id, gateway_surfaces[0].provider_socket_name.value)
            declaration = WorkloadNodeControlSurfaceDeclaration(surface,
                WorkloadNodeControlSurfaceDeclarationProfile.V2)
            request = context.request
            transit = resolved.gateway_node.block_spec.gateway_transit
            if (request.target != installed.target or request.authority_context != authority
                    or request.kind is not health_kind
                    or request.declaration_identity != declaration.identity()
                    or installed.declaration != declaration or context.declaration != declaration
                    or context.gateway_target != gateway_installed.target
                    or destination.ingress != resolved.ingress
                    or destination.gateway_node_id != gateway or destination.runtime_id != runtime_id
                    or destination.gateway_transit_provider_socket_name != transit.provider_socket_name
                    or transit.protocol is not GatewayTransitProtocol.RECEIVER_HEALTH_READ_V2
                    or destination.gateway_transit_protocol is not transit.protocol):
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.INVALID_SELECTION)

        # #147 validates the complete original pair/window before DNS/HTTP, and
        # receivers authenticate it. No retry, renewal, signing or private fallback.
        return await self.client.dispatch(context, pair, destination,
            transit_grant=transit_grant, workload_grant=workload_grant)


def _receiver(node, workspace_id, runtime_id, socket):
    """Read the original selected artifact; never synthesize receiver identity."""
    artifact = select_receiver_node_control_configuration_artifact(
        artifacts=node.configuration_artifacts,
        environment=(*node.public_environment, *node.socket_environment),
        control_surfaces=node.block_spec.control_surfaces)
    configuration = ReceiverNodeControlConfigurationCodec().decode_bytes(artifact.content.encode("utf-8"))
    target = configuration.target
    if (target.workspace_id.value != workspace_id or target.runtime_id != runtime_id
            or target.node_id.value != node.node_id or target.provider_socket_name.value != socket):
        raise ValueError
    return configuration
