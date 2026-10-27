"""Admitted Core-valued health composition; no admission, stores or discovery."""
from dataclasses import dataclass, field

from control_plane_kit_core.planning import (
    ActivityPlan, ObserveManagementBootstrap, ObserveNodeHealth,
    ManagementBootstrapStage, WaitForHealthy, resolve_management_observation,
)
from control_plane_kit_core.runtime_effects import RuntimeEffectKind, RuntimeEffectRequest
from control_plane_kit_core.types import RuntimeKind

from control_plane_kit_interpreters.probes.health_signing import Ed25519HealthCredentialPairSigner
from control_plane_kit_interpreters.invocations import control_errors, invoke_async
from control_plane_kit_interpreters.probes.health_transport import (
    SignedGatewayHealthClient, GatewayHealthTransportCode, GatewayHealthTransportResult,
    _destination,
)
from control_plane_kit_interpreters.probes.local_health import (
    LocalGatewayHealthClient, SelectedLocalGateway, _local_target,
)
from .management_health import (
    DockerManagedHealthObserver, DockerHealthObservationRefused,
    DockerHealthObservationRefusalCode, _selection_refusal,
)


def _supported(operation):
    return (type(operation) is ObserveNodeHealth
        or (type(operation) is ObserveManagementBootstrap and operation.stage in (
            ManagementBootstrapStage.GATEWAY_LOCAL_READY,
            ManagementBootstrapStage.AUTHENTICATED_MANAGEMENT_PATH,
            ManagementBootstrapStage.GATEWAY_INGRESS_READY)))


@dataclass(frozen=True, slots=True, repr=False)
class DockerManagedHealthReader:
    signer: Ed25519HealthCredentialPairSigner
    client: SignedGatewayHealthClient
    local_client: LocalGatewayHealthClient
    require_invocations: bool = field(default=False, kw_only=True)

    def __post_init__(self):
        if (type(self.signer) is not Ed25519HealthCredentialPairSigner
                or type(self.client) is not SignedGatewayHealthClient
                or type(self.local_client) is not LocalGatewayHealthClient
                or type(self.require_invocations) is not bool):
            raise TypeError("managed health composition is invalid")

    def select(self, *, plan, current, desired):
        """Complete supported health selection, not admission or endpoint provenance.

        A required native/legacy observation refuses the whole selection. The
        composition owner needs a separately qualified port for those stages.
        """
        try:
            if type(plan) is not ActivityPlan:
                return None
            selected = []
            for activity in plan.activities:
                operation = activity.operation
                if type(operation) is WaitForHealthy:
                    return None
                if type(operation) not in (ObserveManagementBootstrap, ObserveNodeHealth):
                    continue
                if not _supported(operation):
                    return None
                resolved = resolve_management_observation(operation, current, desired,
                    expected_operation=plan.activity(activity.activity_id).operation)
                if resolved.selected_graph.graph.runtimes[operation.target.runtime_id].kind is not RuntimeKind.DOCKER:
                    return None
                selected.append(activity.activity_id)
            return tuple(selected)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return None

    async def observe(self, request, *, plan, current, desired, authority_context, context,
                      transit_grant, workload_grant, transit_key, workload_key,
                      destination=None, local_destination=None, invocations=None):
        controls = control_errors(invocations, required=self.require_invocations)
        # Unsupported stages cannot touch signing material or endpoint inputs.
        if type(request) is not RuntimeEffectRequest:
            return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.INVALID_SELECTION)
        if not _supported(request.operation):
            return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.UNSUPPORTED_OPERATION)
        try:
            request.__post_init__()
            if request.kind is not RuntimeEffectKind.REALIZE_ACTIVITY or request.runtime_kind is not RuntimeKind.DOCKER:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.INVALID_SELECTION)
        local = (type(request.operation) is ObserveManagementBootstrap
            and request.operation.stage is ManagementBootstrapStage.GATEWAY_LOCAL_READY)
        values = dict(plan=plan, activity_id=request.activity_id, source=request.source,
            current=current, desired=desired, authority_context=authority_context,
            context=context, destination=destination)
        refused = _selection_refusal(request.operation, **values, allow_local=local)
        if refused is not None:
            return refused
        if local:
            try:
                if destination is not None:
                    raise ValueError
                _local_target(context, local_destination)
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
                return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.INVALID_SELECTION)
        else:
            try:
                if local_destination is not None:
                    raise ValueError
                _destination(destination, context)
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
                return DockerHealthObservationRefused(DockerHealthObservationRefusalCode.INVALID_SELECTION)
        try:
            pair = self.signer.sign(context, transit_grant=transit_grant, workload_grant=workload_grant,
                transit_key=transit_key, workload_key=workload_key, invocations=invocations)
        except controls:
            raise
        except Exception:
            return GatewayHealthTransportResult(GatewayHealthTransportCode.INVALID_CONTEXT)
        if local:
            return await invoke_async(invocations, "signed-health-transport",
                lambda: self.local_client.dispatch(context, pair, local_destination,
                    transit_grant=transit_grant, workload_grant=workload_grant))
        return await invoke_async(invocations, "signed-health-transport",
            lambda: DockerManagedHealthObserver(self.client).observe(request.operation,
                **values, pair=pair, transit_grant=transit_grant, workload_grant=workload_grant))
