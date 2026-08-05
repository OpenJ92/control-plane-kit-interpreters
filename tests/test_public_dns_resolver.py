from __future__ import annotations

from collections.abc import Callable
import unittest
from unittest.mock import patch

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import httpx

from control_plane_kit_core.probe_intents import (
    EndpointContext,
    LiteralEndpointMaterial,
    RuntimeEndpointObservation,
)
from control_plane_kit_core.types import Protocol
from control_plane_kit_core.verification import (
    HttpCheck,
    VerificationOutcome,
    VerificationPolicy,
)
from control_plane_kit_interpreters.probes import ProbeAddressPolicy
from control_plane_kit_interpreters.probes.public_dns import (
    DnsOverHttpsPublicAddressResolver,
    PublicDnsResolutionCode,
    PublicDnsResolutionError,
    PublicDnsResolverPolicy,
)
from control_plane_kit_interpreters.verification import (
    HttpVerificationInterpreter,
    VerificationCheckMaterial,
)


HOSTNAME = "gateway-001.openj92.dev"
DOH_URL = "https://1.1.1.1/dns-query"


class PublicDnsResolverTests(unittest.TestCase):
    def test_resolves_bounded_a_and_aaaa_answers_without_duplicates(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return _dns_response(
                request,
                addresses=("1.1.1.1", "1.1.1.1", "2606:4700:4700::1111"),
            )

        resolver = _resolver(handler)

        self.assertEqual(
            resolver.resolve(HOSTNAME),
            ("1.1.1.1", "2606:4700:4700::1111"),
        )
        self.assertEqual(len(requests), 2)
        self.assertEqual(
            [_question_type(request) for request in requests],
            [dns.rdatatype.A, dns.rdatatype.AAAA],
        )
        self.assertTrue(
            all(
                request.headers["content-type"] == "application/dns-message"
                for request in requests
            )
        )

    def test_fresh_call_observes_address_after_prior_nxdomain(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return _dns_response(request, rcode=dns.rcode.NXDOMAIN)
            return _dns_response(request, addresses=("1.1.1.1",))

        resolver = _resolver(handler)

        self.assertEqual(resolver.resolve(HOSTNAME), ())
        self.assertEqual(resolver.resolve(HOSTNAME), ("1.1.1.1",))
        self.assertEqual(calls, 3)

    def test_malformed_oversized_timeout_and_invalid_status_fail_bounded(self) -> None:
        scenarios: tuple[
            tuple[Callable[[httpx.Request], httpx.Response], PublicDnsResolutionCode],
            ...,
        ] = (
            (
                lambda _request: httpx.Response(
                    200,
                    headers={"Content-Type": "application/dns-message"},
                    content=b"not-dns",
                ),
                PublicDnsResolutionCode.MALFORMED_RESPONSE,
            ),
            (
                lambda request: _dns_response(
                    request,
                    addresses=("1.1.1.1",),
                    padding_bytes=512,
                ),
                PublicDnsResolutionCode.RESPONSE_TOO_LARGE,
            ),
            (
                lambda _request: (_ for _ in ()).throw(httpx.ReadTimeout("late")),
                PublicDnsResolutionCode.TIMED_OUT,
            ),
            (
                lambda _request: httpx.Response(503),
                PublicDnsResolutionCode.REJECTED_RESPONSE,
            ),
        )

        for handler, expected_code in scenarios:
            with self.subTest(expected_code=expected_code):
                resolver = _resolver(
                    handler,
                    policy=PublicDnsResolverPolicy(maximum_response_bytes=256),
                )
                with self.assertRaises(PublicDnsResolutionError) as raised:
                    resolver.resolve(HOSTNAME)
                self.assertIs(raised.exception.code, expected_code)
                self.assertNotIn(HOSTNAME, str(raised.exception))
                self.assertNotIn(DOH_URL, repr(raised.exception))

    def test_record_limit_and_non_address_answers_fail_closed(self) -> None:
        resolver = _resolver(
            lambda request: _dns_response(
                request,
                addresses=("1.1.1.1", "8.8.8.8"),
            ),
            policy=PublicDnsResolverPolicy(maximum_records=1),
        )
        with self.assertRaises(PublicDnsResolutionError) as raised:
            resolver.resolve(HOSTNAME)
        self.assertIs(
            raised.exception.code,
            PublicDnsResolutionCode.MALFORMED_RESPONSE,
        )

    def test_configuration_is_https_bounded_and_redacted(self) -> None:
        for endpoint in (
            "http://1.1.1.1/dns-query",
            "https://user:password@1.1.1.1/dns-query",
            "https://1.1.1.1/dns-query?name=unsafe",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(PublicDnsResolutionError) as raised:
                    DnsOverHttpsPublicAddressResolver(endpoint)
                self.assertIs(
                    raised.exception.code,
                    PublicDnsResolutionCode.MALFORMED_CONFIGURATION,
                )
        self.assertNotIn(DOH_URL, repr(_resolver(lambda _request: httpx.Response(500))))


class ConcretePublicDnsVerificationTests(unittest.TestCase):
    def test_nxdomain_then_success_requeries_and_performs_one_target_http(self) -> None:
        dns_calls = 0
        target_requests: list[httpx.Request] = []

        def dns_handler(request: httpx.Request) -> httpx.Response:
            nonlocal dns_calls
            dns_calls += 1
            if dns_calls == 1:
                return _dns_response(request, rcode=dns.rcode.NXDOMAIN)
            return _dns_response(request, addresses=("1.1.1.1",))

        interpreter = HttpVerificationInterpreter(
            ProbeAddressPolicy(public_hosts=frozenset((HOSTNAME,))),
            public_resolver=_resolver(dns_handler),
            transport=httpx.MockTransport(
                lambda request: target_requests.append(request)
                or httpx.Response(200, content=b"ready")
            ),
        )

        with patch("control_plane_kit_interpreters.timing.time.sleep") as sleep:
            result = interpreter.execute(_material(attempts=2))

        self.assertIs(result.outcome, VerificationOutcome.PASSED)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(dns_calls, 3)
        self.assertEqual(len(target_requests), 1)
        self.assertEqual(target_requests[0].url.host, "1.1.1.1")
        self.assertEqual(target_requests[0].headers["host"], f"{HOSTNAME}:443")
        sleep.assert_called_once_with(0.01)

    def test_changed_dns_answer_is_reauthorized_and_repinned(self) -> None:
        resolution = 0
        target_requests: list[httpx.Request] = []
        statuses = iter((503, 200))

        def dns_handler(request: httpx.Request) -> httpx.Response:
            nonlocal resolution
            if _question_type(request) == dns.rdatatype.A:
                resolution += 1
            address = "1.1.1.1" if resolution == 1 else "8.8.8.8"
            return _dns_response(request, addresses=(address,))

        interpreter = HttpVerificationInterpreter(
            ProbeAddressPolicy(public_hosts=frozenset((HOSTNAME,))),
            public_resolver=_resolver(dns_handler),
            transport=httpx.MockTransport(
                lambda request: target_requests.append(request)
                or httpx.Response(next(statuses))
            ),
        )

        result = interpreter.execute(_material(attempts=2))

        self.assertIs(result.outcome, VerificationOutcome.PASSED)
        self.assertEqual(
            [request.url.host for request in target_requests],
            ["1.1.1.1", "8.8.8.8"],
        )

    def test_non_global_dns_answer_performs_zero_target_http(self) -> None:
        target_requests: list[httpx.Request] = []
        interpreter = HttpVerificationInterpreter(
            ProbeAddressPolicy(public_hosts=frozenset((HOSTNAME,))),
            public_resolver=_resolver(
                lambda request: _dns_response(
                    request,
                    addresses=("127.0.0.1",),
                )
            ),
            transport=httpx.MockTransport(
                lambda request: target_requests.append(request)
                or httpx.Response(200)
            ),
        )

        result = interpreter.execute(_material(attempts=3))

        self.assertIs(result.outcome, VerificationOutcome.REJECTED)
        self.assertEqual(result.attempts, 1)
        self.assertEqual(target_requests, [])


def _resolver(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    policy: PublicDnsResolverPolicy | None = None,
) -> DnsOverHttpsPublicAddressResolver:
    return DnsOverHttpsPublicAddressResolver(
        DOH_URL,
        policy=policy or PublicDnsResolverPolicy(),
        transport=httpx.MockTransport(handler),
    )


def _dns_response(
    request: httpx.Request,
    *,
    addresses: tuple[str, ...] = (),
    rcode: int = dns.rcode.NOERROR,
    padding_bytes: int = 0,
) -> httpx.Response:
    query = dns.message.from_wire(request.content)
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    if rcode == dns.rcode.NOERROR:
        question = query.question[0]
        selected = tuple(
            address
            for address in addresses
            if (":" in address) == (question.rdtype == dns.rdatatype.AAAA)
        )
        if selected:
            response.answer.append(
                dns.rrset.from_text(
                    question.name,
                    60,
                    "IN",
                    dns.rdatatype.to_text(question.rdtype),
                    *selected,
                )
            )
    return httpx.Response(
        200,
        headers={"Content-Type": "application/dns-message"},
        content=response.to_wire() + (b"x" * padding_bytes),
    )


def _question_type(request: httpx.Request) -> int:
    return dns.message.from_wire(request.content).question[0].rdtype


def _material(*, attempts: int) -> VerificationCheckMaterial:
    return VerificationCheckMaterial(
        HOSTNAME,
        "graph-public-dns",
        HttpCheck(
            check_id="ready",
            provider_socket="control",
            policy=VerificationPolicy(
                timeout_seconds=1.0,
                interval_seconds=0.01,
                maximum_attempts=attempts,
                maximum_evidence_bytes=64,
            ),
            path="/health/ready",
        ),
        RuntimeEndpointObservation(
            subject_id=HOSTNAME,
            socket_name="control",
            graph_id="graph-public-dns",
            protocol=Protocol.HTTP,
            context=EndpointContext.PUBLIC,
            address=LiteralEndpointMaterial(f"https://{HOSTNAME}:443"),
        ),
    )


if __name__ == "__main__":
    unittest.main()
