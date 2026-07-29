"""Signed, bounded transport for delegated runtime-island gateway probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import json
from types import MappingProxyType
from typing import Mapping

import httpx
import jwt

from control_plane_kit_core.gateway_delegation import (
    DelegatedGatewayProbeGrant,
    GatewayProbeRequest,
)
from control_plane_kit_core.probe_intents import (
    EndpointContext,
    RuntimeEndpointObservation,
)
from control_plane_kit_core.secrets import (
    SecretReference,
    SecretResolver,
    require_resolved_secret,
)
from control_plane_kit_core.types import Protocol

from control_plane_kit_interpreters.probes.security import (
    ProbeAddressPolicy,
    authorize_probe_endpoint,
)


_AUTHORIZATION_SCHEME = "CPK-Gateway"
_TOKEN_TYPE = "CPK-GATEWAY-PROBE+JWT"
_MAXIMUM_RESPONSE_BYTES = 65_536
_MAXIMUM_TIMEOUT_SECONDS = 30.0


class GatewayProbeClientCode(StrEnum):
    SUCCEEDED = "probe-succeeded"
    REJECTED = "gateway-rejected"
    TIMED_OUT = "gateway-timeout"
    TRANSPORT_FAILED = "gateway-transport-failed"
    MALFORMED_RESPONSE = "gateway-response-malformed"
    OVERSIZED_RESPONSE = "gateway-response-too-large"


class GatewayProbeClientError(RuntimeError):
    """Bounded client failure that never exposes endpoint or capability material."""


@dataclass(frozen=True)
class GatewayProbeClientResult:
    code: GatewayProbeClientCode
    evidence: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.code, GatewayProbeClientCode):
            raise TypeError("gateway probe client code must be closed")
        copied = dict(self.evidence)
        if any(
            not isinstance(key, str)
            or not isinstance(value, (str, int))
            or isinstance(value, bool)
            for key, value in copied.items()
        ):
            raise TypeError("gateway probe client evidence must be bounded scalars")
        object.__setattr__(
            self,
            "evidence",
            MappingProxyType(dict(sorted(copied.items()))),
        )


@dataclass(frozen=True, repr=False)
class Ed25519GatewayProbeSigner:
    private_key_reference: SecretReference
    secret_resolver: SecretResolver = field(repr=False, compare=False)

    def sign(
        self,
        grant: DelegatedGatewayProbeGrant,
        request: GatewayProbeRequest,
    ) -> str:
        _require_exact_grant(grant, request)
        try:
            private_key = require_resolved_secret(
                self.secret_resolver,
                self.private_key_reference,
            )
            return jwt.encode(
                {
                    "iss": grant.issuer,
                    "aud": grant.audience,
                    "iat": grant.issued_at,
                    "exp": grant.expires_at,
                    "jti": grant.jti,
                    "gateway_probe": grant.descriptor(),
                },
                private_key.reveal(),
                algorithm="EdDSA",
                headers={
                    "kid": grant.key_id,
                    "typ": _TOKEN_TYPE,
                },
            )
        except GatewayProbeClientError:
            raise
        except Exception:
            raise GatewayProbeClientError(
                "gateway capability signing failed"
            ) from None

    def __repr__(self) -> str:
        return "Ed25519GatewayProbeSigner(<redacted>)"


@dataclass(frozen=True, repr=False)
class SignedGatewayProbeClient:
    signer: Ed25519GatewayProbeSigner = field(repr=False)
    address_policy: ProbeAddressPolicy
    public_resolver: object | None = field(default=None, repr=False)
    transport: httpx.BaseTransport | None = field(default=None, repr=False)
    maximum_response_bytes: int = 16_384
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not isinstance(self.signer, Ed25519GatewayProbeSigner):
            raise TypeError("gateway probe client requires Ed25519 signer")
        if not isinstance(self.address_policy, ProbeAddressPolicy):
            raise TypeError("gateway probe client requires probe address policy")
        if (
            type(self.maximum_response_bytes) is not int
            or self.maximum_response_bytes < 1
            or self.maximum_response_bytes > _MAXIMUM_RESPONSE_BYTES
        ):
            raise ValueError("gateway response limit is outside supported bounds")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > _MAXIMUM_TIMEOUT_SECONDS
        ):
            raise ValueError("gateway timeout is outside supported bounds")

    def dispatch(
        self,
        grant: DelegatedGatewayProbeGrant,
        request: GatewayProbeRequest,
        endpoint: RuntimeEndpointObservation,
    ) -> GatewayProbeClientResult:
        _require_exact_grant(grant, request)
        _require_gateway_endpoint(grant, endpoint)
        target = authorize_probe_endpoint(
            endpoint,
            self.address_policy,
            public_resolver=self.public_resolver,
        )
        token = self.signer.sign(grant, request)
        timeout = httpx.Timeout(
            self.timeout_seconds,
            connect=min(self.timeout_seconds, 5.0),
            read=self.timeout_seconds,
            write=self.timeout_seconds,
            pool=min(self.timeout_seconds, 5.0),
        )
        headers = {
            "Accept": "application/json",
            "Authorization": f"{_AUTHORIZATION_SCHEME} {token}",
            "Content-Type": "application/json",
        }
        if target.host_header is not None:
            headers["Host"] = target.host_header
        try:
            with httpx.Client(
                transport=self.transport,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                outbound = client.build_request(
                    "POST",
                    target.request_url("/cpk/probes"),
                    headers=headers,
                    content=json.dumps(
                        request.descriptor(),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("ascii"),
                )
                if target.sni_hostname is not None:
                    outbound.extensions["sni_hostname"] = target.sni_hostname
                response = client.send(outbound, stream=True)
                try:
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > self.maximum_response_bytes:
                            return GatewayProbeClientResult(
                                GatewayProbeClientCode.OVERSIZED_RESPONSE
                            )
                finally:
                    response.close()
        except httpx.TimeoutException:
            return GatewayProbeClientResult(GatewayProbeClientCode.TIMED_OUT)
        except httpx.HTTPError:
            return GatewayProbeClientResult(GatewayProbeClientCode.TRANSPORT_FAILED)

        if 300 <= response.status_code < 400:
            return GatewayProbeClientResult(
                GatewayProbeClientCode.MALFORMED_RESPONSE
            )
        if response.status_code in (401, 403, 409):
            return GatewayProbeClientResult(
                GatewayProbeClientCode.REJECTED,
                {"http_status": response.status_code},
            )
        if not 200 <= response.status_code < 300:
            return GatewayProbeClientResult(
                GatewayProbeClientCode.TRANSPORT_FAILED,
                {"http_status": response.status_code},
            )
        return _decode_result(bytes(content), request)

    def __repr__(self) -> str:
        return "SignedGatewayProbeClient(<redacted>)"


def _require_exact_grant(
    grant: DelegatedGatewayProbeGrant,
    request: GatewayProbeRequest,
) -> None:
    if (
        not isinstance(grant, DelegatedGatewayProbeGrant)
        or not isinstance(request, GatewayProbeRequest)
        or grant.probe_kind is not request.kind
        or grant.target_id != request.target_id
        or grant.request_digest != request.canonical_digest()
    ):
        raise GatewayProbeClientError(
            "gateway capability does not authorize the probe request"
        )


def _require_gateway_endpoint(
    grant: DelegatedGatewayProbeGrant,
    endpoint: RuntimeEndpointObservation,
) -> None:
    if (
        not isinstance(endpoint, RuntimeEndpointObservation)
        or endpoint.subject_id != grant.gateway_node_id
        or endpoint.socket_name != "control"
        or endpoint.protocol is not Protocol.HTTP
        or endpoint.context
        not in (EndpointContext.RUNTIME_PRIVATE, EndpointContext.PUBLIC)
    ):
        raise GatewayProbeClientError(
            "gateway endpoint observation does not match delegated authority"
        )


def _decode_result(
    content: bytes,
    request: GatewayProbeRequest,
) -> GatewayProbeClientResult:
    try:
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return GatewayProbeClientResult(GatewayProbeClientCode.MALFORMED_RESPONSE)
    if not isinstance(raw, dict):
        return GatewayProbeClientResult(GatewayProbeClientCode.MALFORMED_RESPONSE)
    expected_keys = {"outcome", "target_id", "probe"}
    if request.kind.value == "http-status":
        expected_keys.update({"status", "body_size"})
    if set(raw) != expected_keys:
        return GatewayProbeClientResult(GatewayProbeClientCode.MALFORMED_RESPONSE)
    if (
        raw.get("outcome") not in ("passed", "failed")
        or raw.get("target_id") != request.target_id.value
        or raw.get("probe") != request.kind.value
    ):
        return GatewayProbeClientResult(GatewayProbeClientCode.MALFORMED_RESPONSE)
    evidence: dict[str, object] = {
        "outcome": raw["outcome"],
        "target_id": raw["target_id"],
        "probe": raw["probe"],
    }
    if request.kind.value == "http-status":
        status = raw.get("status")
        body_size = raw.get("body_size")
        if (
            type(status) is not int
            or status < 100
            or status > 599
            or type(body_size) is not int
            or body_size < 0
            or body_size > _MAXIMUM_RESPONSE_BYTES
        ):
            return GatewayProbeClientResult(
                GatewayProbeClientCode.MALFORMED_RESPONSE
            )
        evidence["http_status"] = status
        evidence["body_size"] = body_size
    return GatewayProbeClientResult(
        GatewayProbeClientCode.SUCCEEDED,
        evidence,
    )
