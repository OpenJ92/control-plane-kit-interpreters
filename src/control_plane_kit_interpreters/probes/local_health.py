"""One protected gateway-local read at an independently qualified endpoint.

Local means reachable from this process, not from the Docker daemon. The caller
owns endpoint provenance/placement; this reader neither discovers nor publishes it.
"""
import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
import math

import httpx
from control_plane_kit_core.node_control import NodeHealthReadKind
from control_plane_kit_core.probe_intents import EndpointContext, LiteralEndpointMaterial, RuntimeEndpointObservation
from control_plane_kit_core.types import Protocol

from .health_signing import HealthSigningContext, _context
from .health_transport import (
    GatewayHealthTransportCode, GatewayHealthTransportResult, _inputs, _window, _result, _deadline,
)
from .security import ProbeAddressPolicy, authorize_probe_endpoint


@dataclass(frozen=True, slots=True, repr=False)
class SelectedLocalGateway:
    """Caller-owned endpoint selection and independent explicit address policy."""
    endpoint: RuntimeEndpointObservation
    policy: ProbeAddressPolicy

    def __post_init__(self):
        if type(self.endpoint) is not RuntimeEndpointObservation or type(self.policy) is not ProbeAddressPolicy:
            raise ValueError("local gateway selection is invalid")


def _local_target(context: HealthSigningContext, selected: SelectedLocalGateway):
    context = _context(context)
    if type(selected) is not SelectedLocalGateway:
        raise ValueError("local gateway selection is invalid")
    selected.__post_init__()
    selected.policy.__post_init__()
    endpoint, request = selected.endpoint, context.request
    endpoint.__post_init__()
    if (request.kind is not NodeHealthReadKind.READINESS or request.target != context.gateway_target
            or endpoint.subject_id != request.target.node_id.value
            or endpoint.socket_name != request.target.provider_socket_name.value
            or endpoint.graph_id != request.authority_context.authored_graph_id
            or endpoint.protocol is not Protocol.HTTP
            or endpoint.context is not EndpointContext.RUNTIME_PRIVATE
            or type(endpoint.address) is not LiteralEndpointMaterial):
        raise ValueError("local gateway selection is invalid")
    # This branch is pure: exact private authority, no DNS or secret resolution.
    return authorize_probe_endpoint(endpoint, selected.policy)


@dataclass(frozen=True, slots=True, repr=False)
class LocalGatewayHealthClient:
    clock: Callable[[], int]
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)
    timeout_seconds: float = 5

    def __post_init__(self):
        if (not callable(self.clock) or type(self.timeout_seconds) not in (int, float)
                or not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 5
                or (self.transport is not None and not isinstance(self.transport, httpx.AsyncBaseTransport))):
            raise ValueError("local health transport configuration is invalid")

    async def dispatch(self, context, pair, destination, *, transit_grant, workload_grant):
        try:
            context, transit, workload = _inputs(context, pair, transit_grant, workload_grant, self.clock)
            target = _local_target(context, destination)
        except Exception:
            return GatewayHealthTransportResult(GatewayHealthTransportCode.INVALID_CONTEXT)
        deadline = asyncio.get_running_loop().time() + self.timeout_seconds
        try:
            async with asyncio.timeout_at(deadline):
                async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout_seconds,
                        verify=True, follow_redirects=False, trust_env=False) as client:
                    request = client.build_request("GET", target.request_url("/__control/health/readiness"),
                        headers={"Authorization":"Bearer " + pair.workload_credential.decode("ascii"),
                            "Accept":"application/json", "Accept-Encoding":"identity"})
                    try:
                        _window(self.clock, transit, workload)
                    except Exception:
                        return GatewayHealthTransportResult(GatewayHealthTransportCode.INVALID_CONTEXT)
                    _deadline(deadline)
                    response = await client.send(request, stream=True)
                    try:
                        result = await _result(response, context)
                        _deadline(deadline)
                        return result
                    finally:
                        await response.aclose()
        except (TimeoutError, httpx.TimeoutException):
            return GatewayHealthTransportResult(GatewayHealthTransportCode.TIMED_OUT)
        except Exception:
            # No URL, secret or peer payload crosses this boundary. Cancellation
            # propagates while both context managers close their owned resources.
            return GatewayHealthTransportResult(GatewayHealthTransportCode.TRANSPORT_FAILED)
