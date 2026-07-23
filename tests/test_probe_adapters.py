from __future__ import annotations

from dataclasses import dataclass, field
import socket
import unittest

import httpx

from control_plane_kit_core.probe_intents import (
    EndpointContext,
    EndpointDeclaration,
    LiteralEndpointMaterial,
    ProbeObservation,
    ProbeOutcome,
    ProbePolicy,
    ProbeSubject,
    RuntimeEndpointObservation,
    SecretEndpointMaterial,
    application_health_probe,
    transport_probe,
)
from control_plane_kit_core.types import Protocol

from control_plane_kit_interpreters.probes import (
    HttpApplicationHealthProbeAdapter,
    ProbeAddressPolicy,
    ProbeSecurityError,
    TcpTransportProbeAdapter,
    TransportProbeRouter,
    UdpTransportProbeAdapter,
    UnsupportedTransportProbe,
    authorize_probe_endpoint,
)


@dataclass(frozen=True)
class PublicResolver:
    addresses: tuple[str, ...]

    def resolve(self, hostname: str) -> tuple[str, ...]:
        return self.addresses


@dataclass
class EndpointResolver:
    value: str
    references: list[str] = field(default_factory=list)

    def resolve_endpoint(self, reference_id: str) -> str:
        self.references.append(reference_id)
        return self.value


@dataclass
class Connection:
    closed: bool = False

    def close(self) -> None:
        self.closed = True


@dataclass(frozen=True)
class Connector:
    outcome: str

    def connect(self, host: str, port: int, *, timeout_seconds: float) -> Connection:
        if self.outcome == "refused":
            raise ConnectionRefusedError
        if self.outcome == "timeout":
            raise socket.timeout
        if self.outcome == "unknown":
            raise OSError
        return Connection()


@dataclass(frozen=True)
class DatagramClient:
    outcome: str

    def exchange(
        self,
        host: str,
        port: int,
        payload: bytes,
        *,
        maximum_response_bytes: int,
        timeout_seconds: float,
    ) -> bytes:
        if self.outcome == "refused":
            raise ConnectionRefusedError
        if self.outcome == "timeout":
            raise TimeoutError
        if self.outcome == "oversized":
            return b"x" * (maximum_response_bytes + 1)
        return b"response"


class ProbeAdapterTests(unittest.TestCase):
    def test_address_policy_fails_closed_and_pins_public_dns(self) -> None:
        private_host = _endpoint(
            Protocol.HTTP,
            EndpointContext.HOST_LOCAL,
            "http://10.0.0.5:8000",
        )
        with self.assertRaises(ProbeSecurityError) as rejected:
            authorize_probe_endpoint(
                private_host,
                ProbeAddressPolicy(allow_host_local=True),
            )
        self.assertNotIn("10.0.0.5", str(rejected.exception))

        public = _endpoint(
            Protocol.HTTP,
            EndpointContext.PUBLIC,
            "https://api.example.test:443",
        )
        with self.assertRaises(ProbeSecurityError):
            authorize_probe_endpoint(
                public,
                ProbeAddressPolicy(public_hosts=frozenset({"api.example.test"})),
                public_resolver=PublicResolver(("127.0.0.1",)),
            )
        authorized = authorize_probe_endpoint(
            public,
            ProbeAddressPolicy(public_hosts=frozenset({"api.example.test"})),
            public_resolver=PublicResolver(("8.8.8.8",)),
        )
        self.assertEqual(authorized.connect_host, "8.8.8.8")
        self.assertEqual(authorized.sni_hostname, "api.example.test")
        self.assertNotIn("api.example.test", repr(authorized))

    def test_secret_endpoint_value_is_resolved_only_at_authorization(self) -> None:
        endpoint = RuntimeEndpointObservation(
            "api",
            "internal",
            "graph-a",
            Protocol.HTTP,
            EndpointContext.HOST_LOCAL,
            SecretEndpointMaterial("secret://runtime/api"),
        )
        resolver = EndpointResolver("http://127.0.0.1:18000")

        target = authorize_probe_endpoint(
            endpoint,
            ProbeAddressPolicy(allow_host_local=True),
            secret_resolver=resolver,
        )

        self.assertEqual(target.connect_host, "127.0.0.1")
        self.assertEqual(resolver.references, ["secret://runtime/api"])
        self.assertNotIn("127.0.0.1", repr(target))

    def test_http_probe_is_bounded_redirect_free_and_status_driven(self) -> None:
        policy = ProbeAddressPolicy(allow_host_local=True)
        intent = _health_intent()

        healthy = HttpApplicationHealthProbeAdapter(
            policy,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"ok")
            ),
        ).observe(intent, timeout_seconds=1)
        unhealthy = HttpApplicationHealthProbeAdapter(
            policy,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(503, content=b"not ready")
            ),
        ).observe(intent, timeout_seconds=1)
        redirect = HttpApplicationHealthProbeAdapter(
            policy,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    302,
                    headers={"location": "http://evil.test"},
                )
            ),
        ).observe(intent, timeout_seconds=1)
        oversized = HttpApplicationHealthProbeAdapter(
            policy,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"x" * 20_000)
            ),
        ).observe(intent, timeout_seconds=1)

        self.assertIs(healthy.outcome, ProbeOutcome.HEALTHY)
        self.assertIs(unhealthy.outcome, ProbeOutcome.UNHEALTHY)
        self.assertIs(redirect.outcome, ProbeOutcome.MALFORMED)
        self.assertIs(oversized.outcome, ProbeOutcome.MALFORMED)

    def test_tcp_probe_distinguishes_reachable_refused_and_timeout(self) -> None:
        policy = ProbeAddressPolicy(allow_host_local=True)
        intent = _transport_intent()

        reachable = TcpTransportProbeAdapter(
            policy,
            connector=Connector("reachable"),
        ).observe(intent, timeout_seconds=1)
        refused = TcpTransportProbeAdapter(
            policy,
            connector=Connector("refused"),
        ).observe(intent, timeout_seconds=1)
        timed_out = TcpTransportProbeAdapter(
            policy,
            connector=Connector("timeout"),
        ).observe(intent, timeout_seconds=1)

        self.assertIs(reachable.outcome, ProbeOutcome.REACHABLE)
        self.assertIs(refused.outcome, ProbeOutcome.REFUSED)
        self.assertIs(timed_out.outcome, ProbeOutcome.TIMED_OUT)

    def test_udp_probe_requires_a_bounded_response_exchange(self) -> None:
        policy = ProbeAddressPolicy(allow_host_local=True)
        intent = transport_probe(
            _subject(Protocol.UDP),
            _endpoint(Protocol.UDP, EndpointContext.HOST_LOCAL, "udp://127.0.0.1:18000"),
            ProbePolicy(),
        )

        reachable = UdpTransportProbeAdapter(
            policy,
            client=DatagramClient("reachable"),
        ).observe(intent, timeout_seconds=1)
        refused = UdpTransportProbeAdapter(
            policy,
            client=DatagramClient("refused"),
        ).observe(intent, timeout_seconds=1)
        timed_out = UdpTransportProbeAdapter(
            policy,
            client=DatagramClient("timeout"),
        ).observe(intent, timeout_seconds=1)
        oversized = UdpTransportProbeAdapter(
            policy,
            client=DatagramClient("oversized"),
        ).observe(intent, timeout_seconds=1)

        self.assertIs(reachable.outcome, ProbeOutcome.REACHABLE)
        self.assertIs(refused.outcome, ProbeOutcome.REFUSED)
        self.assertIs(timed_out.outcome, ProbeOutcome.TIMED_OUT)
        self.assertIs(oversized.outcome, ProbeOutcome.UNKNOWN)

    def test_transport_router_dispatches_only_from_typed_transport(self) -> None:
        policy = ProbeAddressPolicy(allow_host_local=True)
        router = TransportProbeRouter(
            TcpTransportProbeAdapter(policy, connector=Connector("reachable")),
            UdpTransportProbeAdapter(policy, client=DatagramClient("reachable")),
        )

        tcp = router.observe(_transport_intent(), timeout_seconds=1)
        udp = router.observe(
            transport_probe(
                _subject(Protocol.UDP),
                _endpoint(
                    Protocol.UDP,
                    EndpointContext.HOST_LOCAL,
                    "udp://127.0.0.1:18000",
                ),
                ProbePolicy(),
            ),
            timeout_seconds=1,
        )

        self.assertIs(tcp.outcome, ProbeOutcome.REACHABLE)
        self.assertIs(udp.outcome, ProbeOutcome.REACHABLE)

    def test_transport_adapters_reject_unsupported_transport_explicitly(self) -> None:
        policy = ProbeAddressPolicy(allow_host_local=True)
        udp_intent = transport_probe(
            _subject(Protocol.UDP),
            _endpoint(Protocol.UDP, EndpointContext.HOST_LOCAL, "udp://127.0.0.1:18000"),
            ProbePolicy(),
        )

        with self.assertRaises(UnsupportedTransportProbe):
            TcpTransportProbeAdapter(policy).observe(
                udp_intent,
                timeout_seconds=1,
            )


def _subject(protocol: Protocol = Protocol.HTTP) -> ProbeSubject:
    return ProbeSubject(
        "api",
        (EndpointDeclaration("internal", protocol),),
        "/health" if protocol is Protocol.HTTP else None,
    )


def _endpoint(
    protocol: Protocol = Protocol.HTTP,
    context: EndpointContext = EndpointContext.HOST_LOCAL,
    value: str = "http://127.0.0.1:18000",
) -> RuntimeEndpointObservation:
    return RuntimeEndpointObservation(
        "api",
        "internal",
        "graph-a",
        protocol,
        context,
        LiteralEndpointMaterial(value),
    )


def _transport_intent():
    return transport_probe(_subject(), _endpoint(), ProbePolicy())


def _health_intent():
    return application_health_probe(_subject(), _endpoint(), ProbePolicy())


if __name__ == "__main__":
    unittest.main()
