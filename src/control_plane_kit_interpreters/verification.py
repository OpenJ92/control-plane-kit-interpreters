"""Bounded concrete interpreters for semantic verification checks."""

from __future__ import annotations

from dataclasses import dataclass, field
import socket
from typing import Protocol

import httpx

from control_plane_kit_core.probe_intents import RuntimeEndpointObservation
from control_plane_kit_core.verification import (
    HttpCheck,
    HttpVerificationEvidence,
    PostgresQueryCheck,
    RedisCheck,
    RedisVerificationEvidence,
    VerificationCapability,
    VerificationCheck,
    VerificationCompleted,
    VerificationEvidence,
    VerificationIdentity,
    VerificationOutcome,
    VerificationResult,
    VerificationUnsupported,
)

from control_plane_kit_interpreters.probes.security import (
    AuthorizedProbeTarget,
    ProbeAddressPolicy,
    ProbeEndpointSecretResolver,
    ProbePublicAddressResolver,
    ProbeSecurityError,
    authorize_probe_endpoint,
)


@dataclass(frozen=True)
class VerificationCheckMaterial:
    """Graph-correlated verification input supplied by operations."""

    node_id: str
    graph_id: str
    check: VerificationCheck
    endpoint: RuntimeEndpointObservation

    def __post_init__(self) -> None:
        for value, label in (
            (self.node_id, "verification node"),
            (self.graph_id, "verification graph"),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label} identity must not be empty")
        if not isinstance(self.check, (HttpCheck, PostgresQueryCheck, RedisCheck)):
            raise TypeError("verification material requires supported check values")
        if not isinstance(self.endpoint, RuntimeEndpointObservation):
            raise TypeError("verification material endpoint must be typed")
        if self.endpoint.subject_id != self.node_id or self.endpoint.graph_id != self.graph_id:
            raise ValueError("verification endpoint identity must match material")
        if self.endpoint.socket_name != self.check.provider_socket:
            raise ValueError("verification endpoint socket must match check")


def verification_identity(material: VerificationCheckMaterial) -> VerificationIdentity:
    if not isinstance(material, VerificationCheckMaterial):
        raise TypeError("verification identity requires VerificationCheckMaterial")
    return VerificationIdentity(
        material.node_id,
        material.graph_id,
        material.check.check_id,
    )


class RedisPingTransport(Protocol):
    def ping(
        self,
        host: str,
        port: int,
        *,
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> bytes: ...


@dataclass(frozen=True)
class SocketRedisPingTransport:
    """Perform exactly one bounded RESP PING exchange."""

    def ping(
        self,
        host: str,
        port: int,
        *,
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> bytes:
        connection = socket.create_connection(
            (host, port),
            timeout=timeout_seconds,
        )
        try:
            connection.settimeout(timeout_seconds)
            connection.sendall(b"*1\r\n$4\r\nPING\r\n")
            response = bytearray()
            while not response.endswith(b"\r\n"):
                chunk = connection.recv(
                    min(4096, maximum_response_bytes + 1 - len(response))
                )
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > maximum_response_bytes:
                    break
            return bytes(response)
        finally:
            connection.close()


class PostgresSelectOneTransport(Protocol):
    def select_one(
        self,
        target: AuthorizedProbeTarget,
        *,
        timeout_seconds: float,
    ) -> bool: ...


@dataclass(frozen=True)
class HttpVerificationInterpreter:
    """Execute bounded redirect-free HTTP semantic checks."""

    policy: ProbeAddressPolicy
    secret_resolver: ProbeEndpointSecretResolver | None = None
    public_resolver: ProbePublicAddressResolver | None = None
    transport: httpx.BaseTransport | None = None

    @property
    def capabilities(self) -> frozenset[VerificationCapability]:
        return frozenset((VerificationCapability.HTTP,))

    def execute(self, material: VerificationCheckMaterial) -> VerificationResult:
        if not isinstance(material.check, HttpCheck):
            return VerificationUnsupported(
                verification_identity(material),
                VerificationCapability.HTTP,
            )
        check = material.check
        try:
            target = authorize_probe_endpoint(
                material.endpoint,
                self.policy,
                secret_resolver=self.secret_resolver,
                public_resolver=self.public_resolver,
            )
        except ProbeSecurityError:
            return _observation(
                material,
                VerificationCapability.HTTP,
                VerificationOutcome.REJECTED,
                1,
            )

        last = _observation(
            material,
            VerificationCapability.HTTP,
            VerificationOutcome.FAILED,
            1,
        )
        for attempt in range(1, check.policy.maximum_attempts + 1):
            last = self._attempt(material, target, attempt)
            if last.outcome is VerificationOutcome.PASSED:
                return last
        return last

    def _attempt(
        self,
        material: VerificationCheckMaterial,
        target: AuthorizedProbeTarget,
        attempt: int,
    ) -> VerificationCompleted:
        check = material.check
        assert isinstance(check, HttpCheck)
        timeout = httpx.Timeout(check.policy.timeout_seconds)
        try:
            with httpx.Client(
                transport=self.transport,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                request = client.build_request(
                    "GET",
                    target.request_url(check.path),
                    headers={"Accept": "application/json"},
                )
                if target.host_header is not None:
                    request.headers["Host"] = target.host_header
                if target.sni_hostname is not None:
                    request.extensions["sni_hostname"] = target.sni_hostname
                response = client.send(request, stream=True)
                try:
                    size = 0
                    overflow = False
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > check.policy.maximum_evidence_bytes:
                            overflow = True
                            break
                finally:
                    response.close()
            evidence = HttpVerificationEvidence(
                response.status_code,
                min(size, check.policy.maximum_evidence_bytes),
            )
            if overflow or 300 <= response.status_code < 400:
                outcome = VerificationOutcome.MALFORMED
            elif response.status_code in check.expected_statuses:
                outcome = VerificationOutcome.PASSED
            else:
                outcome = VerificationOutcome.FAILED
            return _observation(
                material,
                VerificationCapability.HTTP,
                outcome,
                attempt,
                evidence,
            )
        except httpx.TimeoutException:
            outcome = VerificationOutcome.TIMED_OUT
        except httpx.RemoteProtocolError:
            outcome = VerificationOutcome.MALFORMED
        except httpx.HTTPError:
            outcome = VerificationOutcome.FAILED
        return _observation(
            material,
            VerificationCapability.HTTP,
            outcome,
            attempt,
        )


@dataclass(frozen=True)
class RedisVerificationInterpreter:
    """Execute the closed Redis PING verification operation."""

    policy: ProbeAddressPolicy
    secret_resolver: ProbeEndpointSecretResolver | None = None
    public_resolver: ProbePublicAddressResolver | None = None
    transport: RedisPingTransport = field(default_factory=SocketRedisPingTransport)

    @property
    def capabilities(self) -> frozenset[VerificationCapability]:
        return frozenset((VerificationCapability.REDIS,))

    def execute(self, material: VerificationCheckMaterial) -> VerificationResult:
        if not isinstance(material.check, RedisCheck):
            return VerificationUnsupported(
                verification_identity(material),
                VerificationCapability.REDIS,
            )
        check = material.check
        try:
            target = authorize_probe_endpoint(
                material.endpoint,
                self.policy,
                secret_resolver=self.secret_resolver,
                public_resolver=self.public_resolver,
            )
        except ProbeSecurityError:
            return _observation(
                material,
                VerificationCapability.REDIS,
                VerificationOutcome.REJECTED,
                1,
            )

        last = _observation(
            material,
            VerificationCapability.REDIS,
            VerificationOutcome.FAILED,
            1,
        )
        for attempt in range(1, check.policy.maximum_attempts + 1):
            try:
                response = self.transport.ping(
                    target.connect_host,
                    target.port,
                    timeout_seconds=check.policy.timeout_seconds,
                    maximum_response_bytes=check.policy.maximum_evidence_bytes,
                )
                evidence = RedisVerificationEvidence(
                    min(len(response), check.policy.maximum_evidence_bytes)
                )
                if len(response) > check.policy.maximum_evidence_bytes:
                    outcome = VerificationOutcome.MALFORMED
                elif response == b"+PONG\r\n":
                    outcome = VerificationOutcome.PASSED
                else:
                    outcome = VerificationOutcome.FAILED
                last = _observation(
                    material,
                    VerificationCapability.REDIS,
                    outcome,
                    attempt,
                    evidence,
                )
            except (TimeoutError, socket.timeout):
                last = _observation(
                    material,
                    VerificationCapability.REDIS,
                    VerificationOutcome.TIMED_OUT,
                    attempt,
                )
            except OSError:
                last = _observation(
                    material,
                    VerificationCapability.REDIS,
                    VerificationOutcome.FAILED,
                    attempt,
                )
            if last.outcome is VerificationOutcome.PASSED:
                return last
        return last


@dataclass(frozen=True)
class PostgresVerificationInterpreter:
    """Execute semantic Postgres readiness through an injected query transport."""

    policy: ProbeAddressPolicy
    transport: PostgresSelectOneTransport
    secret_resolver: ProbeEndpointSecretResolver | None = None
    public_resolver: ProbePublicAddressResolver | None = None

    @property
    def capabilities(self) -> frozenset[VerificationCapability]:
        return frozenset((VerificationCapability.POSTGRES,))

    def execute(self, material: VerificationCheckMaterial) -> VerificationResult:
        if not isinstance(material.check, PostgresQueryCheck):
            return VerificationUnsupported(
                verification_identity(material),
                VerificationCapability.POSTGRES,
            )
        check = material.check
        try:
            target = authorize_probe_endpoint(
                material.endpoint,
                self.policy,
                secret_resolver=self.secret_resolver,
                public_resolver=self.public_resolver,
            )
        except ProbeSecurityError:
            return _observation(
                material,
                VerificationCapability.POSTGRES,
                VerificationOutcome.REJECTED,
                1,
            )

        last = _observation(
            material,
            VerificationCapability.POSTGRES,
            VerificationOutcome.FAILED,
            1,
        )
        for attempt in range(1, check.policy.maximum_attempts + 1):
            try:
                outcome = (
                    VerificationOutcome.PASSED
                    if self.transport.select_one(
                        target,
                        timeout_seconds=check.policy.timeout_seconds,
                    )
                    else VerificationOutcome.FAILED
                )
            except (TimeoutError, socket.timeout):
                outcome = VerificationOutcome.TIMED_OUT
            except OSError:
                outcome = VerificationOutcome.FAILED
            last = _observation(
                material,
                VerificationCapability.POSTGRES,
                outcome,
                attempt,
            )
            if last.outcome is VerificationOutcome.PASSED:
                return last
        return last


def _observation(
    material: VerificationCheckMaterial,
    capability: VerificationCapability,
    outcome: VerificationOutcome,
    attempts: int,
    evidence: VerificationEvidence | None = None,
) -> VerificationCompleted:
    return VerificationCompleted(
        verification_identity(material),
        capability,
        outcome,
        attempts,
        evidence,
    )
