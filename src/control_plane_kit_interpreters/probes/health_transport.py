"""One bounded health read through an independently selected named gateway.

The caller supplies post-transaction authority/selection and the genuine signer
output. Structural congruence is not signature admission or current permission.
Receivers own signature checks; Operations owns intent, uncertainty and history.
"""
from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
import json
import math
import re
import socket
from typing import Protocol as TypingProtocol

import httpx
from control_plane_kit_core.node_control import NodeControlGraphReference, NodeControlGraphReferenceRole, workload_node_control_audience
from control_plane_kit_core.node_health_reads import (
    DelegatedWorkloadNodeHealthReadGrant, DelegatedWorkloadNodeHealthReadGrantCodec,
    verify_workload_node_health_read_grant,
)
from control_plane_kit_core.node_health_transit import (
    DelegatedGatewayNodeHealthReadTransitGrant, DelegatedGatewayNodeHealthReadTransitGrantCodec,
    verify_gateway_node_health_read_transit_grant,
)
from control_plane_kit_core.node_health_read_results import (
    MAX_NODE_HEALTH_READ_RESULT_BYTES, NodeHealthReadResult, NodeHealthReadResultCodec,
)
from control_plane_kit_core.probe_intents import EndpointContext, LiteralEndpointMaterial, RuntimeEndpointObservation
from control_plane_kit_core.public_ingress import NamedPublicIngress, NamedPublicIngressCodec, PublicIngressExposure
from control_plane_kit_core.types import Protocol

from .health_signing import HealthSigningContext, SignedHealthCredentialPair, _canonical, _context, _now
from .security import ProbeAddressPolicy, authorize_probe_endpoint

_TARGET_ID = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")


class GatewayHealthTransportCode(StrEnum):
    RECEIVED = "received"
    INVALID_CONTEXT = "invalid-context"
    DESTINATION_REJECTED = "destination-rejected"
    GATEWAY_REJECTED = "gateway-rejected"
    TIMED_OUT = "timed-out"
    TRANSPORT_FAILED = "transport-failed"
    MALFORMED_RESPONSE = "malformed-response"
    OVERSIZED_RESPONSE = "oversized-response"


@dataclass(frozen=True, slots=True)
class GatewayHealthTransportResult:
    code: GatewayHealthTransportCode
    result: NodeHealthReadResult | None = field(default=None, repr=False)

    def __post_init__(self):
        if (type(self.code) is not GatewayHealthTransportCode
                or (self.code is GatewayHealthTransportCode.RECEIVED and type(self.result) is not NodeHealthReadResult)
                or (self.code is not GatewayHealthTransportCode.RECEIVED and self.result is not None)):
            raise ValueError("health transport result is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class SelectedManagementGateway:
    """Caller projection of selected topology/configuration, never authority.

    The caller binds target_id to the selected relay's exact workload binding.
    The client validates this projection against independent request context.
    """
    ingress: NamedPublicIngress
    gateway_node_id: NodeControlGraphReference
    gateway_transit_provider_socket_name: str
    runtime_id: NodeControlGraphReference
    target_id: str


class AsyncPublicAddressResolver(TypingProtocol):
    async def resolve(self, hostname: str) -> tuple[str, ...]: ...


class _SystemResolver:
    async def resolve(self, hostname):
        # Cancellation stops this await, not necessarily the OS resolver thread.
        # No credential-bearing HTTP runs in that thread or after cancellation.
        answers = await asyncio.get_running_loop().getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        if len(answers) > 128:
            raise ValueError
        return tuple(answer[4][0] for answer in answers)


@dataclass(frozen=True, slots=True)
class _ResolvedAnswers:
    answers: tuple[str, ...]

    def resolve(self, hostname):
        return self.answers


@dataclass(frozen=True, slots=True, repr=False)
class SignedGatewayHealthClient:
    clock: Callable[[], int]
    public_resolver: AsyncPublicAddressResolver | None = field(default=None, repr=False)
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)
    timeout_seconds: float = 5

    def __post_init__(self):
        if (not callable(self.clock) or type(self.timeout_seconds) not in (int, float)
                or not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 5
                or (self.public_resolver is not None and not callable(getattr(self.public_resolver, "resolve", None)))
                or (self.transport is not None and not isinstance(self.transport, httpx.AsyncBaseTransport))):
            raise ValueError("health transport configuration is invalid")

    async def dispatch(self, context: HealthSigningContext, pair: SignedHealthCredentialPair,
                       destination: SelectedManagementGateway, *,
                       transit_grant: DelegatedGatewayNodeHealthReadTransitGrant,
                       workload_grant: DelegatedWorkloadNodeHealthReadGrant) -> GatewayHealthTransportResult:
        try:
            context, transit, workload = _inputs(context, pair, transit_grant, workload_grant, self.clock)
        except Exception:
            return _failure(GatewayHealthTransportCode.INVALID_CONTEXT)
        try:
            selected = _destination(destination, context)
        except Exception:
            return _failure(GatewayHealthTransportCode.DESTINATION_REJECTED)
        deadline = asyncio.get_running_loop().time() + self.timeout_seconds
        try:
            async with asyncio.timeout_at(deadline):
                try:
                    resolver = self.public_resolver or _SystemResolver()
                    answers = await resolver.resolve(selected.ingress.hostname)
                    if (type(answers) is not tuple or not 1 <= len(answers) <= 128
                            or any(type(value) is not str or len(value) > 45 for value in answers)):
                        raise ValueError
                    endpoint = RuntimeEndpointObservation(selected.gateway_node_id.value,
                        selected.gateway_transit_provider_socket_name, context.request.target.graph_revision.value,
                        Protocol.HTTP, EndpointContext.PUBLIC,
                        LiteralEndpointMaterial(f"https://{selected.ingress.hostname}:443"))
                    target = authorize_probe_endpoint(endpoint,
                        ProbeAddressPolicy(public_hosts=frozenset({selected.ingress.hostname})),
                        public_resolver=_ResolvedAnswers(answers))
                except TimeoutError:
                    raise
                except Exception:
                    return _failure(GatewayHealthTransportCode.DESTINATION_REJECTED)
                _deadline(deadline)
                body = _wire({"profile":"cpk-gateway-health-relay-request.v1", "target_id":selected.target_id,
                    "attempt_id":context.attempt_id, "request":context.request.descriptor(),
                    "workload_credential":pair.workload_credential.decode("ascii")})
                if len(body) > 16384:
                    return _failure(GatewayHealthTransportCode.INVALID_CONTEXT)
                async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout_seconds,
                        verify=True, follow_redirects=False, trust_env=False) as client:
                    outbound = client.build_request("POST", target.request_url("/cpk/health/" + context.request.kind.value),
                        headers={"Authorization":"Bearer " + pair.transit_credential.decode("ascii"),
                            "Host":target.host_header, "Accept":"application/json",
                            "Accept-Encoding":"identity", "Content-Type":"application/json"}, content=body)
                    outbound.extensions["sni_hostname"] = target.sni_hostname
                    # Recheck original time after DNS/client construction, at send.
                    try:
                        _window(self.clock, transit, workload)
                    except Exception:
                        return _failure(GatewayHealthTransportCode.INVALID_CONTEXT)
                    _deadline(deadline)
                    response = await client.send(outbound, stream=True)
                    try:
                        result = await _result(response, context)
                        _deadline(deadline)
                        return result
                    finally:
                        await response.aclose()
        except (TimeoutError, httpx.TimeoutException):
            return _failure(GatewayHealthTransportCode.TIMED_OUT)
        except Exception:
            # Opaque transport errors can contain URLs, tokens and peer payloads.
            # Return no exception object or chain. CancelledError propagates.
            return _failure(GatewayHealthTransportCode.TRANSPORT_FAILED)


def _failure(code):
    return GatewayHealthTransportResult(code)


def _deadline(deadline):
    if asyncio.get_running_loop().time() >= deadline:
        raise TimeoutError


def _window(clock, transit, workload):
    now = _now(clock)
    if not all(grant.not_before <= now < grant.expires_at for grant in (transit, workload)):
        raise ValueError
    return now


def _inputs(context, pair, transit, workload, clock):
    context = _context(context)
    transit = _canonical(transit, DelegatedGatewayNodeHealthReadTransitGrant, DelegatedGatewayNodeHealthReadTransitGrantCodec())
    workload = _canonical(workload, DelegatedWorkloadNodeHealthReadGrant, DelegatedWorkloadNodeHealthReadGrantCodec())
    if (type(pair) is not SignedHealthCredentialPair or type(pair.request) is not type(context.request)
            or pair.request != context.request or (transit.issued_at, transit.not_before, transit.expires_at)
                != (workload.issued_at, workload.not_before, workload.expires_at)):
        raise ValueError
    expected = dict(expected_target=context.request.target, expected_runtime_id=context.request.runtime_id,
        expected_declaration=context.declaration, expected_kind=context.request.kind, now=_window(clock, transit, workload))
    if not verify_gateway_node_health_read_transit_grant(transit, context.request,
            expected_issuer=context.transit_issuer, expected_key_id=transit.key_id,
            expected_attempt_id=context.attempt_id, expected_gateway_node_id=context.gateway_node_id,
            **expected).is_accepted:
        raise ValueError
    if not verify_workload_node_health_read_grant(workload, context.request,
            expected_issuer=context.workload_issuer, expected_key_id=workload.key_id,
            expected_audience=workload_node_control_audience(context.request.target), **expected).is_accepted:
        raise ValueError
    _credential(pair.transit_credential, transit, "CPK-GATEWAY-NODE-HEALTH-READ-TRANSIT+JWT", "gateway_node_health_read_transit")
    _credential(pair.workload_credential, workload, "CPK-WORKLOAD-NODE-HEALTH-READ+JWT", "workload_node_health_read")
    return context, transit, workload


def _destination(value, context):
    if type(value) is not SelectedManagementGateway or type(value.ingress) is not NamedPublicIngress:
        raise ValueError
    ingress = NamedPublicIngressCodec().decode(value.ingress.descriptor())
    if (ingress != value.ingress or ingress.exposure is not PublicIngressExposure.HTTPS
            or type(value.gateway_node_id) is not NodeControlGraphReference
            or value.gateway_node_id.role is not NodeControlGraphReferenceRole.NODE
            or value.gateway_node_id != context.gateway_node_id
            or type(value.runtime_id) is not NodeControlGraphReference
            or value.runtime_id != context.request.runtime_id
            or type(value.gateway_transit_provider_socket_name) is not str
            or ingress.target.node_id != value.gateway_node_id.value
            or ingress.target.provider_socket != value.gateway_transit_provider_socket_name
            or type(value.target_id) is not str or _TARGET_ID.fullmatch(value.target_id) is None):
        raise ValueError
    return SelectedManagementGateway(ingress, value.gateway_node_id,
        value.gateway_transit_provider_socket_name, value.runtime_id, value.target_id)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError


def _json(raw):
    text = raw.decode("utf-8")
    depth, quoted, escaped = 0, False, False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > 8:
                raise ValueError
        elif character in "]}":
            depth -= 1
    return json.loads(text, object_pairs_hook=_unique, parse_constant=_nonfinite)


def _credential(token, grant, token_type, claim):
    """Bounded structural equality to original authority; no crypto admission."""
    if type(token) is not bytes or not 1 <= len(token) <= 12288:
        raise ValueError
    segments = token.split(b".")
    if len(segments) != 3:
        raise ValueError
    decoded = []
    for segment, cap in zip(segments, (1024, 8192, 86), strict=True):
        if not segment or len(segment) > cap or re.fullmatch(rb"[A-Za-z0-9_-]+", segment) is None:
            raise ValueError
        raw = base64.b64decode(segment + b"=" * (-len(segment) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(raw).rstrip(b"=") != segment:
            raise ValueError
        decoded.append(raw)
    if len(decoded[2]) != 64:
        raise ValueError
    header, claims = _json(decoded[0]), _json(decoded[1])
    expected_header = {"alg":"EdDSA", "typ":token_type, "kid":grant.key_id}
    expected_claims = dict(iss=grant.issuer, aud=grant.audience, iat=grant.issued_at,
        nbf=grant.not_before, exp=grant.expires_at, jti=grant.jti, **{claim:grant.descriptor()})
    # Canonical JSON comparison preserves numeric/boolean type distinctions.
    if _wire(header) != _wire(expected_header) or _wire(claims) != _wire(expected_claims):
        raise ValueError


async def _result(response, context):
    status = response.status_code
    if status in (400, 401, 403, 413):
        return _failure(GatewayHealthTransportCode.GATEWAY_REJECTED)
    if status == 504:
        return _failure(GatewayHealthTransportCode.TIMED_OUT)
    if status >= 500:
        return _failure(GatewayHealthTransportCode.TRANSPORT_FAILED)
    if status != 200 or response.headers.get("content-encoding", "identity") != "identity":
        return _failure(GatewayHealthTransportCode.MALFORMED_RESPONSE)
    body = bytearray()
    if response.is_stream_consumed:
        # Injectable in-memory transports may supply an already buffered body.
        if len(response.content) > MAX_NODE_HEALTH_READ_RESULT_BYTES:
            return _failure(GatewayHealthTransportCode.OVERSIZED_RESPONSE)
        body.extend(response.content)
    else:
        async for chunk in response.aiter_raw():
            if len(body) + len(chunk) > MAX_NODE_HEALTH_READ_RESULT_BYTES:
                return _failure(GatewayHealthTransportCode.OVERSIZED_RESPONSE)
            body.extend(chunk)
    try:
        result = NodeHealthReadResultCodec(context.request, context.declaration).decode(_json(bytes(body)))
        return GatewayHealthTransportResult(GatewayHealthTransportCode.RECEIVED, result)
    except (ValueError, TypeError, KeyError, RecursionError):
        return _failure(GatewayHealthTransportCode.MALFORMED_RESPONSE)
