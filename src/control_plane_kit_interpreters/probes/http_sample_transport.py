"""One supplied signed sample exchange; not signing, admission or registration.

The caller supplies independent original context and post-admission credentials.
Structural agreement does not prove their provenance or authenticate signatures;
the gateway and SDK own signature admission. No private transport fallback exists.
"""
from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
import json
import math
import re

import httpx
import rfc8785

from control_plane_kit_core.delegation_keys import DelegationKeyPurpose
from control_plane_kit_core.http_verification_samples import (
    HttpVerificationSampleRequest, HttpVerificationSampleRequestCodec,
    HttpVerificationSampleGrant, HttpVerificationSampleGrantCodec,
    HttpVerificationSampleResult, HttpVerificationSampleResultCodec,
)
from control_plane_kit_core.probe_intents import EndpointContext, RuntimeEndpointObservation, LiteralEndpointMaterial
from control_plane_kit_core.public_ingress import NamedPublicIngress, NamedPublicIngressCodec, PublicIngressExposure
from control_plane_kit_core.receiver_identity import NodeControlReceiverTarget, NodeControlReceiverTargetCodec, receiver_node_control_audience
from control_plane_kit_core.receiver_management_routes import ReceiverManagementRouteBinding
from control_plane_kit_core.types import Protocol
from control_plane_kit_core.verification import HttpCheck
from control_plane_kit_interpreters.probes.health_transport import _SystemResolver, _ResolvedAnswers
from control_plane_kit_interpreters.probes.security import ProbeAddressPolicy, authorize_probe_endpoint

_ROUTE = "/cpk/verification/http"
_PROFILE = "cpk-gateway-http-verification-sample-request.v1"
_ROLES = (
    (DelegationKeyPurpose.GATEWAY_HTTP_VERIFICATION_SAMPLE_TRANSIT,
        "CPK-GATEWAY-HTTP-VERIFICATION-SAMPLE-TRANSIT+JWT", "gateway_http_verification_sample_transit"),
    (DelegationKeyPurpose.WORKLOAD_HTTP_VERIFICATION_SAMPLE,
        "CPK-WORKLOAD-HTTP-VERIFICATION-SAMPLE+JWT", "workload_http_verification_sample"),
)
_CLAIMS = dict(iss="issuer", aud="audience", iat="issued_at", nbf="not_before", exp="expires_at", jti="jti")


class HttpSampleTransportCode(StrEnum):
    RECEIVED = "received"
    INVALID_CONTEXT = "invalid-context"
    DESTINATION_REJECTED = "destination-rejected"
    RELAY_REJECTED = "relay-rejected"
    RESULT_REJECTED = "result-rejected"
    TIMED_OUT = "timed-out"
    TRANSPORT_FAILED = "transport-failed"


@dataclass(frozen=True, slots=True, repr=False)
class HttpSampleTransportResult:
    code: HttpSampleTransportCode
    result: HttpVerificationSampleResult | None = None


@dataclass(frozen=True, slots=True, repr=False)
class SignedHttpSampleCredentials:
    transit: bytes
    workload: bytes
    transit_grant: HttpVerificationSampleGrant
    workload_grant: HttpVerificationSampleGrant


@dataclass(frozen=True, slots=True, repr=False)
class SelectedHttpSampleGateway:
    """Supplied selection only; no production transit declaration is advertised."""

    ingress: NamedPublicIngress
    gateway_target: NodeControlReceiverTarget
    route: ReceiverManagementRouteBinding
    transit_provider_socket_name: str


def _require(condition):
    if condition is not True:
        raise ValueError


def _unique(pairs):
    value = {}
    for name, item in pairs:
        _require(name not in value)
        value[name] = item
    return value


def _invalid_constant(_value):
    raise ValueError


def _token(token, grant, typ, claim):
    _require(type(token) is bytes and 1 <= len(token) <= 16384)
    parts = token.split(b".")
    _require(len(parts) == 3)
    decoded = []
    for part, maximum in zip(parts, (1024, 15104, 128)):
        _require(1 <= len(part) <= maximum and re.fullmatch(rb"[A-Za-z0-9_-]+", part) is not None)
        raw = base64.urlsafe_b64decode(part + b"=" * (-len(part) % 4))
        _require(base64.urlsafe_b64encode(raw).rstrip(b"=") == part)
        decoded.append(raw)
    _require(len(decoded[2]) == 64)
    header, payload = (json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
        parse_constant=_invalid_constant) for raw in decoded[:2])
    _require(type(header) is dict and header == dict(alg="EdDSA", typ=typ, kid=grant.key_id)
        and type(payload) is dict and set(payload) == set(_CLAIMS) | {claim})
    _require(HttpVerificationSampleGrantCodec().decode(payload[claim]) == grant)
    for outer, inner in _CLAIMS.items():
        expected = getattr(grant, inner)
        _require(type(payload[outer]) is type(expected) and payload[outer] == expected)


def _now(clock):
    now = clock()
    _require(type(now) in (int, float) and math.isfinite(now) and 0 <= now <= 2**53 - 1)
    return now


def _window(now, credentials):
    for grant in (credentials.transit_grant, credentials.workload_grant):
        _require(grant.not_before <= now < grant.expires_at)


def _inputs(request, check, credentials):
    _require(type(request) is HttpVerificationSampleRequest and type(check) is HttpCheck
        and type(credentials) is SignedHttpSampleCredentials)
    _require(HttpVerificationSampleRequestCodec().decode_canonical_bytes(request.canonical_bytes()) == request)
    codec = HttpVerificationSampleResultCodec(request, check)
    for (purpose, typ, claim), token, grant in zip(_ROLES,
            (credentials.transit, credentials.workload), (credentials.transit_grant, credentials.workload_grant)):
        _require(type(grant) is HttpVerificationSampleGrant
            and HttpVerificationSampleGrantCodec().decode_canonical_bytes(grant.canonical_bytes()) == grant
            and grant.request == request and grant.purpose is purpose)
        _token(token, grant, typ, claim)
    return codec


def _destination(destination, request, credentials):
    _require(type(destination) is SelectedHttpSampleGateway and type(destination.ingress) is NamedPublicIngress
        and type(destination.route) is ReceiverManagementRouteBinding)
    ingress = NamedPublicIngressCodec().decode(destination.ingress.descriptor())
    gateway = destination.gateway_target
    NodeControlReceiverTargetCodec().encode(gateway)
    route = destination.route
    _require(replace(route) == route and ingress.exposure is PublicIngressExposure.HTTPS
        and gateway == request.gateway_target and route.target == request.target
        and route.target.runtime_id == gateway.runtime_id and route.target.workspace_id == gateway.workspace_id
        and route.declaration.identity().value == request.declaration_identity
        and route.target_id == request.route_id
        and ingress.target.node_id == gateway.node_id.value
        and ingress.target.provider_socket == destination.transit_provider_socket_name)
    _require(credentials.transit_grant.audience == f"gateway:{gateway.workspace_id.value}:{gateway.node_id.value}"
        and credentials.workload_grant.audience == receiver_node_control_audience(route.target))
    return ingress


def _bounded_headers(headers):
    _require(len(headers.raw) <= 64 and sum(len(k) + len(v) for k, v in headers.raw) <= 32768)


async def _result(response, codec):
    if response.status_code != 200:
        # Status/error bodies and peer diagnostics never become health evidence.
        return HttpSampleTransportResult(HttpSampleTransportCode.RELAY_REJECTED)
    try:
        _bounded_headers(response.headers)
        _require(response.headers.get("content-encoding", "identity") == "identity"
            and response.headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json")
        body = bytearray()
        if response.is_stream_consumed:
            _require(len(response.content) <= 2048)
            body.extend(response.content)
        else:
            async for chunk in response.aiter_raw():
                _require(len(body) + len(chunk) <= 2048)
                body.extend(chunk)
        return HttpSampleTransportResult(HttpSampleTransportCode.RECEIVED, codec.decode_canonical_bytes(bytes(body)))
    except Exception:
        return HttpSampleTransportResult(HttpSampleTransportCode.RESULT_REJECTED)


@dataclass(frozen=True, slots=True, repr=False)
class SignedGatewayHttpSampleClient:
    clock: Callable[[], int | float]
    public_resolver: object | None = field(default=None, repr=False)
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)
    timeout_seconds: float = 5

    def __post_init__(self):
        _require(callable(self.clock) and type(self.timeout_seconds) in (int, float)
            and math.isfinite(self.timeout_seconds) and 0 < self.timeout_seconds <= 5
            and (self.public_resolver is None or callable(getattr(self.public_resolver, "resolve", None)))
            and (self.transport is None or isinstance(self.transport, httpx.AsyncBaseTransport)))

    async def dispatch(self, *, request, check, destination, credentials):
        """One already-admitted sample only; never retries, resolves or signs."""
        try:
            codec = _inputs(request, check, credentials)
            now = _now(self.clock)
            _window(now, credentials)
        except Exception:
            return HttpSampleTransportResult(HttpSampleTransportCode.INVALID_CONTEXT)
        try:
            ingress = _destination(destination, request, credentials)
        except Exception:
            return HttpSampleTransportResult(HttpSampleTransportCode.DESTINATION_REJECTED)
        remaining = min(credentials.transit_grant.expires_at, credentials.workload_grant.expires_at) - now
        deadline = asyncio.get_running_loop().time() + min(self.timeout_seconds, check.policy.timeout_seconds, remaining)
        try:
            async with asyncio.timeout_at(deadline):
                resolver = self.public_resolver or _SystemResolver()
                answers = await resolver.resolve(ingress.hostname)
                _require(type(answers) is tuple and 1 <= len(answers) <= 128
                    and all(type(answer) is str and len(answer) <= 45 for answer in answers))
                gateway = destination.gateway_target
                endpoint = RuntimeEndpointObservation(gateway.node_id.value,
                    destination.transit_provider_socket_name, request.authority_context.authored_graph_id,
                    Protocol.HTTP, EndpointContext.PUBLIC, LiteralEndpointMaterial(f"https://{ingress.hostname}:443"))
                target = authorize_probe_endpoint(endpoint, ProbeAddressPolicy(public_hosts=frozenset({ingress.hostname})),
                    public_resolver=_ResolvedAnswers(answers))
                body = rfc8785.dumps(dict(profile=_PROFILE, target_id=request.route_id,
                    request=request.descriptor(), workload_credential=credentials.workload.decode("ascii")))
                _require(len(body) <= 32768)
                async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout_seconds,
                        verify=True, follow_redirects=False, trust_env=False) as client:
                    outbound = client.build_request("POST", target.request_url(_ROUTE),
                        headers={"Authorization":"Bearer " + credentials.transit.decode("ascii"),
                            "Host":target.host_header, "Accept":"application/json", "Accept-Encoding":"identity",
                            "Content-Type":"application/json"}, content=body)
                    outbound.extensions["sni_hostname"] = target.sni_hostname
                    _bounded_headers(outbound.headers)
                    _window(_now(self.clock), credentials)
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError
                    response = await client.send(outbound, stream=True)
                    try:
                        return await _result(response, codec)
                    finally:
                        await response.aclose()
        except (TimeoutError, httpx.TimeoutException):
            return HttpSampleTransportResult(HttpSampleTransportCode.TIMED_OUT)
        except Exception:
            # Network/client failures may contain credential-bearing peer text.
            # Cancellation propagates; no outer refusal fabricates a Core result.
            return HttpSampleTransportResult(HttpSampleTransportCode.TRANSPORT_FAILED)


__all__ = ["HttpSampleTransportCode", "HttpSampleTransportResult", "SignedHttpSampleCredentials",
    "SelectedHttpSampleGateway", "SignedGatewayHttpSampleClient"]
