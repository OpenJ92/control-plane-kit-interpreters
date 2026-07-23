"""Concrete transport and application-health probe adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
import socket
from typing import Mapping, Protocol

import httpx

from control_plane_kit_core.probe_intents import (
    ApplicationHealthProbeIntent,
    ProbeObservation,
    ProbeOutcome,
    RuntimeEndpointObservation,
    TransportProbeIntent,
)
from control_plane_kit_core.types import Transport

from control_plane_kit_interpreters.probes.security import (
    ProbeAddressPolicy,
    ProbeEndpointSecretResolver,
    ProbePublicAddressResolver,
    ProbeSecurityError,
    authorize_probe_endpoint,
)


class UnsupportedTransportProbe(ValueError):
    """Raised when an adapter cannot interpret the requested transport."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        super().__init__(f"transport probe does not support {transport.value}")


class RuntimeEndpointProvider(Protocol):
    """Supply graph-correlated runtime endpoint evidence without stores."""

    def endpoint_for(
        self,
        subject_id: str,
        graph_id: str,
    ) -> RuntimeEndpointObservation: ...


@dataclass(frozen=True)
class StaticRuntimeEndpointProvider:
    """Small runtime registry for local deployments, tests, and examples."""

    endpoints: Mapping[tuple[str, str], RuntimeEndpointObservation]

    def endpoint_for(
        self,
        subject_id: str,
        graph_id: str,
    ) -> RuntimeEndpointObservation:
        try:
            endpoint = self.endpoints[(subject_id, graph_id)]
        except KeyError as error:
            raise KeyError("runtime endpoint observation is unavailable") from error
        if endpoint.subject_id != subject_id or endpoint.graph_id != graph_id:
            raise ValueError("runtime endpoint registry returned mismatched evidence")
        return endpoint


class SocketConnection(Protocol):
    def close(self) -> None: ...


class SocketConnector(Protocol):
    def connect(
        self,
        host: str,
        port: int,
        *,
        timeout_seconds: float,
    ) -> SocketConnection: ...


@dataclass(frozen=True)
class DefaultSocketConnector:
    def connect(
        self,
        host: str,
        port: int,
        *,
        timeout_seconds: float,
    ) -> SocketConnection:
        return socket.create_connection((host, port), timeout=timeout_seconds)


@dataclass(frozen=True)
class TcpTransportProbeAdapter:
    """Prove only TCP reachability; it makes no application-health claim."""

    policy: ProbeAddressPolicy
    connector: SocketConnector = field(default_factory=DefaultSocketConnector)
    secret_resolver: ProbeEndpointSecretResolver | None = None
    public_resolver: ProbePublicAddressResolver | None = None

    def observe(
        self,
        intent: TransportProbeIntent,
        *,
        timeout_seconds: float,
    ) -> ProbeObservation:
        if intent.endpoint.protocol.transport is not Transport.TCP:
            raise UnsupportedTransportProbe(intent.endpoint.protocol.transport)
        target = authorize_probe_endpoint(
            intent.endpoint,
            self.policy,
            secret_resolver=self.secret_resolver,
            public_resolver=self.public_resolver,
        )
        outcome = ProbeOutcome.UNKNOWN
        connection: SocketConnection | None = None
        try:
            connection = self.connector.connect(
                target.connect_host,
                target.port,
                timeout_seconds=timeout_seconds,
            )
            outcome = ProbeOutcome.REACHABLE
        except (ConnectionRefusedError, ConnectionResetError):
            outcome = ProbeOutcome.REFUSED
        except (TimeoutError, socket.timeout):
            outcome = ProbeOutcome.TIMED_OUT
        except OSError:
            outcome = ProbeOutcome.UNKNOWN
        finally:
            if connection is not None:
                connection.close()
        return ProbeObservation(
            intent.subject_id,
            intent.graph_id,
            intent.kind,
            outcome,
            endpoint_context=intent.endpoint.context,
        )


class DatagramExchangeClient(Protocol):
    """Perform one bounded request/response datagram exchange."""

    def exchange(
        self,
        host: str,
        port: int,
        payload: bytes,
        *,
        maximum_response_bytes: int,
        timeout_seconds: float,
    ) -> bytes: ...


@dataclass(frozen=True)
class DefaultDatagramExchangeClient:
    """Socket-backed bounded UDP request/response exchange."""

    def exchange(
        self,
        host: str,
        port: int,
        payload: bytes,
        *,
        maximum_response_bytes: int,
        timeout_seconds: float,
    ) -> bytes:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout_seconds)
            client.connect((host, port))
            client.send(payload)
            return client.recv(maximum_response_bytes + 1)


@dataclass(frozen=True)
class UdpTransportProbeAdapter:
    """Prove one bounded UDP exchange without claiming application health."""

    policy: ProbeAddressPolicy
    payload: bytes = b"\x00"
    maximum_response_bytes: int = 512
    client: DatagramExchangeClient = field(
        default_factory=DefaultDatagramExchangeClient
    )
    secret_resolver: ProbeEndpointSecretResolver | None = None
    public_resolver: ProbePublicAddressResolver | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.payload, bytes)
            or not self.payload
            or len(self.payload) > 512
        ):
            raise ValueError("UDP probe payload must contain between 1 and 512 bytes")
        if (
            type(self.maximum_response_bytes) is not int
            or self.maximum_response_bytes < 1
            or self.maximum_response_bytes > 65_536
        ):
            raise ValueError("UDP probe response bound must be between 1 and 65536 bytes")

    def observe(
        self,
        intent: TransportProbeIntent,
        *,
        timeout_seconds: float,
    ) -> ProbeObservation:
        if intent.endpoint.protocol.transport is not Transport.UDP:
            raise UnsupportedTransportProbe(intent.endpoint.protocol.transport)
        target = authorize_probe_endpoint(
            intent.endpoint,
            self.policy,
            secret_resolver=self.secret_resolver,
            public_resolver=self.public_resolver,
        )
        try:
            response = self.client.exchange(
                target.connect_host,
                target.port,
                self.payload,
                maximum_response_bytes=self.maximum_response_bytes,
                timeout_seconds=timeout_seconds,
            )
            outcome = (
                ProbeOutcome.REACHABLE
                if response and len(response) <= self.maximum_response_bytes
                else ProbeOutcome.UNKNOWN
            )
        except (ConnectionRefusedError, ConnectionResetError):
            outcome = ProbeOutcome.REFUSED
        except (TimeoutError, socket.timeout):
            outcome = ProbeOutcome.TIMED_OUT
        except OSError:
            outcome = ProbeOutcome.UNKNOWN
        return ProbeObservation(
            intent.subject_id,
            intent.graph_id,
            intent.kind,
            outcome,
            endpoint_context=intent.endpoint.context,
        )


@dataclass(frozen=True)
class TransportProbeRouter:
    """Dispatch transport probes solely from the typed transport factor."""

    tcp: object
    udp: object

    def observe(
        self,
        intent: TransportProbeIntent,
        *,
        timeout_seconds: float,
    ) -> ProbeObservation:
        match intent.endpoint.protocol.transport:
            case Transport.TCP:
                return self.tcp.observe(intent, timeout_seconds=timeout_seconds)
            case Transport.UDP:
                return self.udp.observe(intent, timeout_seconds=timeout_seconds)
        raise UnsupportedTransportProbe(intent.endpoint.protocol.transport)


@dataclass(frozen=True)
class HttpApplicationHealthProbeAdapter:
    """Perform one bounded redirect-free HTTP application-health request."""

    policy: ProbeAddressPolicy
    secret_resolver: ProbeEndpointSecretResolver | None = None
    public_resolver: ProbePublicAddressResolver | None = None
    transport: httpx.BaseTransport | None = None

    def observe(
        self,
        intent: ApplicationHealthProbeIntent,
        *,
        timeout_seconds: float,
    ) -> ProbeObservation:
        try:
            target = authorize_probe_endpoint(
                intent.endpoint,
                self.policy,
                secret_resolver=self.secret_resolver,
                public_resolver=self.public_resolver,
            )
            timeout = httpx.Timeout(
                timeout_seconds,
                connect=min(timeout_seconds, 5.0),
                read=timeout_seconds,
                write=timeout_seconds,
                pool=min(timeout_seconds, 5.0),
            )
            headers = {"Accept": "application/json"}
            if target.host_header is not None:
                headers["Host"] = target.host_header
            with httpx.Client(
                transport=self.transport,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                request = client.build_request(
                    "GET",
                    target.request_url(intent.health_path),
                    headers=headers,
                )
                if target.sni_hostname is not None:
                    request.extensions["sni_hostname"] = target.sni_hostname
                response = client.send(request, stream=True)
                try:
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > intent.policy.maximum_response_bytes:
                            return self._observation(intent, ProbeOutcome.MALFORMED)
                finally:
                    response.close()
            if 300 <= response.status_code < 400:
                return self._observation(intent, ProbeOutcome.MALFORMED)
            outcome = (
                ProbeOutcome.HEALTHY
                if response.status_code in intent.policy.http.status_codes
                else ProbeOutcome.UNHEALTHY
            )
            return self._observation(intent, outcome)
        except ProbeSecurityError:
            raise
        except httpx.TimeoutException:
            return self._observation(intent, ProbeOutcome.TIMED_OUT)
        except httpx.ConnectError as error:
            outcome = (
                ProbeOutcome.REFUSED
                if isinstance(error.__cause__, ConnectionRefusedError)
                else ProbeOutcome.UNKNOWN
            )
            return self._observation(intent, outcome)
        except httpx.RemoteProtocolError:
            return self._observation(intent, ProbeOutcome.MALFORMED)
        except httpx.HTTPError:
            return self._observation(intent, ProbeOutcome.UNKNOWN)

    @staticmethod
    def _observation(
        intent: ApplicationHealthProbeIntent,
        outcome: ProbeOutcome,
    ) -> ProbeObservation:
        return ProbeObservation(
            intent.subject_id,
            intent.graph_id,
            intent.kind,
            outcome,
            endpoint_context=intent.endpoint.context,
        )
