"""#147 laws: selected public transport, original pairs, truthful bounded results."""
import asyncio
import base64
from dataclasses import replace
import importlib
import importlib.util
import json
import unittest

import httpx
import control_plane_kit_core as core
from health_transport_fixtures import World, Resolver, Transport

MODULE = "control_plane_kit_interpreters.probes.health_transport"


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks=(), delay=0):
        self.chunks, self.delay = chunks, delay
        self.closed, self.read = False, False
        self.entered = asyncio.Event()

    async def __aiter__(self):
        self.read = True
        self.entered.set()
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            yield chunk

    async def aclose(self):
        self.closed = True


def corrupt_signature(token):
    head, body, signature = token.split(b".")
    raw = base64.urlsafe_b64decode(signature + b"==")
    changed = bytes((raw[0] ^ 1,)) + raw[1:]
    return b".".join((head, body, base64.urlsafe_b64encode(changed).rstrip(b"=")))


class HealthTransportPrerequisiteTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_signer_pair_is_admitted_by_selected_relay_and_sdk(self):
        value = World()
        async with httpx.AsyncClient(transport=value.gateway_transport, base_url="https://gateway.example.invalid") as client:
            response = await client.post("/cpk/health/liveness", headers={
                "Authorization":"Bearer " + value.pair.transit_credential.decode()}, json={
                "profile":"cpk-gateway-health-relay-request.v1", "target_id":"workload-management",
                "attempt_id":value.context.attempt_id, "request":value.pair.request.descriptor(),
                "workload_credential":value.pair.workload_credential.decode()})
        self.assertEqual(response.status_code, 200)
        result = core.NodeHealthReadResultCodec(value.value.request, value.value.declaration).decode(response.json())
        self.assertIs(result.outcome, core.NodeHealthReadOutcome.HEALTHY)
        self.assertEqual(value.callbacks, [core.NodeHealthReadKind.LIVENESS])
        self.assertEqual(str(value.workload_transport.requests[0].url), "http://workload-a:8087/__control/health/liveness")


class HealthTransportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec(MODULE), "#147 health transport interface is missing")
        self.module = importlib.import_module(MODULE)

    def failure(self, result, expected):
        self.assertEqual(result.code.value, expected)
        self.assertIsNone(result.result)
        self.assertNotIn("gateway.example", repr(result))
        self.assertNotIn("Bearer", repr(result))

    async def test_actual_receivers_preserve_both_kinds_and_all_four_semantic_outcomes(self):
        for kind in core.NodeHealthReadKind:
            for outcome in core.NodeHealthReadOutcome:
                with self.subTest(kind=kind, outcome=outcome):
                    value = World(kind)
                    value.outcome = outcome
                    result = await value.dispatch(self.module)
                    self.assertEqual(result.code.value, "received")
                    self.assertIs(result.result.outcome, outcome)
                    self.assertEqual(result.result.request, value.value.request)
                    self.assertEqual(result.result.declaration, value.value.declaration)
                    self.assertEqual(value.callbacks, [kind])
                    self.assertTrue(value.gateway_transport.closed)
                    self.assertTrue(value.workload_transport.closed)

    async def test_closed_envelope_selected_public_ip_original_host_and_sni(self):
        value = World()
        value.resolver.addresses = ("8.8.8.9", "8.8.8.8")
        result = await value.dispatch(self.module)
        self.assertEqual(result.code.value, "received")
        self.assertEqual(value.resolver.calls, [value.ingress.hostname])
        self.assertEqual(len(value.gateway_transport.requests), 1)
        request = value.gateway_transport.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(str(request.url), "https://8.8.8.8/cpk/health/liveness")
        self.assertEqual(request.headers["host"], "gateway.example.invalid:443")
        self.assertEqual(request.extensions["sni_hostname"], "gateway.example.invalid")
        self.assertEqual(request.headers["authorization"], "Bearer " + value.pair.transit_credential.decode())
        self.assertEqual(request.headers["accept-encoding"], "identity")
        self.assertNotIn("cookie", request.headers)
        self.assertEqual(json.loads(request.content), {
            "profile":"cpk-gateway-health-relay-request.v1", "target_id":"workload-management",
            "attempt_id":"attempt-a", "request":value.value.request.descriptor(),
            "workload_credential":value.pair.workload_credential.decode()})
        self.assertNotIn(value.pair.transit_credential.decode(), repr(result))

    async def test_mismatched_context_pair_and_original_grants_refuse_before_dns_or_http(self):
        value = World()
        cases = (
            {"pair":replace(value.pair, transit_credential=b"")},
            {"pair":replace(value.pair, workload_credential=b"")},
            {"pair":replace(value.pair, workload_credential=b"bad\r\nheader")},
            {"pair":replace(value.pair, request=replace(value.value.request, request_id="other"))},
            {"context":replace(value.context, attempt_id="another-attempt")},
            {"context":replace(value.context, gateway_node_id=replace(value.value.gateway, value="other-gateway"))},
            {"transit_grant":replace(value.value.transit, jti="other-transit")},
            {"workload_grant":replace(value.value.workload, jti="other-workload")},
            {"workload_grant":replace(value.value.workload, expires_at=199)},
        )
        for changed in cases:
            with self.subTest(changed=tuple(changed)):
                self.failure(await value.dispatch(self.module, **changed), "invalid-context")
        self.assertEqual(value.resolver.calls, [])
        self.assertEqual(value.gateway_transport.requests, [])

    async def test_selected_gateway_socket_runtime_and_host_refuse_without_fallback(self):
        value = World()
        selected = value.destination(self.module)
        cases = (
            replace(selected, gateway_node_id=replace(value.value.gateway, value="other-gateway")),
            replace(selected, gateway_transit_provider_socket_name="application"),
            replace(selected, runtime_id=replace(value.value.runtime, value="other-runtime")),
            replace(selected, target_id="../arbitrary-url"),
        )
        for destination in cases:
            with self.subTest(destination=repr(destination)):
                self.failure(await value.dispatch(self.module, destination=destination), "destination-rejected")
        self.assertEqual(value.gateway_transport.requests, [])
        self.assertEqual(value.resolver.calls, [])
        for addresses in ((), ("127.0.0.1",), ("169.254.169.254",), ("8.8.8.8", "10.0.0.1"),
                          ("not-an-address",), ("8.8.8.8",) * 129):
            with self.subTest(addresses=addresses[:2]):
                self.failure(await value.dispatch(self.module,
                    client=value.client(self.module, public_resolver=Resolver(addresses))), "destination-rejected")
        self.assertEqual(value.gateway_transport.requests, [])

    async def test_original_window_is_checked_again_after_dns_without_renewal(self):
        value = World()
        class ExpiringResolver:
            async def resolve(self, hostname):
                value.now = value.value.transit.expires_at
                return ("8.8.8.8",)
        self.failure(await value.dispatch(self.module, client=value.client(self.module,
            public_resolver=ExpiringResolver())), "invalid-context")
        self.assertEqual(value.gateway_transport.requests, [])
        value.now = value.value.transit.not_before - 1
        self.failure(await value.dispatch(self.module), "invalid-context")
        self.assertEqual(value.resolver.calls, [])

    async def test_receivers_own_signature_denials_and_distinct_effect_boundaries(self):
        for family, code, expected_outbound in (("transit_credential", "gateway-rejected", 0),
                                                ("workload_credential", "transport-failed", 1)):
            with self.subTest(family=family):
                value = World()
                pair = replace(value.pair, **{family:corrupt_signature(getattr(value.pair, family))})
                self.failure(await value.dispatch(self.module, pair=pair), code)
                self.assertEqual(len(value.workload_transport.requests), expected_outbound)
                self.assertEqual(value.callbacks, [])

    async def test_status_failures_do_not_read_peer_bodies_or_follow_redirects(self):
        for status, code in ((301,"malformed-response"), (401,"gateway-rejected"),
                (403,"gateway-rejected"), (400,"gateway-rejected"), (413,"gateway-rejected"),
                (500,"transport-failed"), (502,"transport-failed"), (504,"timed-out"),
                (204,"malformed-response")):
            with self.subTest(status=status):
                value, stream = World(), Stream((b"private peer body",))
                transport = Transport(httpx.MockTransport(lambda request: httpx.Response(status,
                    headers={"location":"https://elsewhere.invalid"}, stream=stream)))
                self.failure(await value.dispatch(self.module, client=value.client(self.module,
                    transport=transport)), code)
                self.assertEqual(len(transport.requests), 1)
                self.assertFalse(stream.read)
                self.assertTrue(stream.closed)
                self.assertTrue(transport.closed)

    async def test_raw_stream_bounds_encoding_and_strict_correlated_json(self):
        value = World()
        good = core.NodeHealthReadResult(value.value.request, value.value.declaration,
            core.NodeHealthReadOutcome.HEALTHY).canonical_bytes()
        wrong = json.loads(good)
        wrong["request_id"] = "another"
        cases = (
            ((b"x" * 447,), {}, "oversized-response"),
            ((b"x" * 300, b"y" * 147), {}, "oversized-response"),
            ((good,), {"content-encoding":"gzip"}, "malformed-response"),
            ((b"{" * 400,), {}, "malformed-response"),
            ((b'{"outcome":"healthy","outcome":"unknown"}',), {}, "malformed-response"),
            ((b'{"outcome":NaN}',), {}, "malformed-response"),
            ((json.dumps(wrong, separators=(",", ":")).encode(),), {}, "malformed-response"),
            ((b"{}",), {}, "malformed-response"),
        )
        for chunks, headers, expected in cases:
            with self.subTest(expected=expected, headers=headers):
                stream = Stream(chunks)
                transport = Transport(httpx.MockTransport(lambda request: httpx.Response(200,
                    headers=headers, stream=stream)))
                self.failure(await value.dispatch(self.module, client=value.client(self.module,
                    transport=transport)), expected)
                self.assertTrue(stream.closed)
                self.assertTrue(transport.closed)
                if headers:
                    self.assertFalse(stream.read)

    async def test_whole_deadline_covers_dns_headers_and_slow_body(self):
        value = World()
        class SlowResolver:
            async def resolve(self, hostname):
                await asyncio.sleep(1)
                return ("8.8.8.8",)
        self.failure(await value.dispatch(self.module, client=value.client(self.module,
            public_resolver=SlowResolver(), timeout_seconds=0.02)), "timed-out")
        self.assertEqual(value.gateway_transport.requests, [])
        async def slow_headers(request):
            await asyncio.sleep(1)
            return httpx.Response(200, content=b"{}")
        transport = Transport(httpx.MockTransport(slow_headers))
        self.failure(await value.dispatch(self.module, client=value.client(self.module,
            transport=transport, timeout_seconds=0.02)), "timed-out")
        self.assertTrue(transport.closed)
        stream = Stream((b"{", b"}") * 20, delay=0.01)
        transport = Transport(httpx.MockTransport(lambda request: httpx.Response(200, stream=stream)))
        self.failure(await value.dispatch(self.module, client=value.client(self.module,
            transport=transport, timeout_seconds=0.025)), "timed-out")
        self.assertTrue(stream.closed)
        self.assertTrue(transport.closed)
        self.assertEqual(len(transport.requests), 1)

    async def test_cancellation_closes_response_and_propagates_without_observation(self):
        value, stream = World(), Stream((b"{}",), delay=10)
        transport = Transport(httpx.MockTransport(lambda request: httpx.Response(200, stream=stream)))
        task = asyncio.create_task(value.dispatch(self.module, client=value.client(self.module, transport=transport)))
        await asyncio.wait_for(stream.entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(stream.closed)
        self.assertTrue(transport.closed)
        self.assertEqual(len(transport.requests), 1)

    async def test_transport_exceptions_are_redacted_without_chains_or_retry(self):
        value = World()
        async def failing(request):
            raise httpx.ConnectError("private endpoint " + value.pair.transit_credential.decode(), request=request)
        transport = Transport(httpx.MockTransport(failing))
        result = await value.dispatch(self.module, client=value.client(self.module, transport=transport))
        self.failure(result, "transport-failed")
        self.assertNotIn(value.pair.transit_credential.decode(), repr(result))
        self.assertEqual(len(transport.requests), 1)
        self.assertTrue(transport.closed)

    def test_timeout_configuration_is_finite_bounded_and_not_boolean(self):
        value = World()
        for timeout in (True, False, 0, -1, 5.1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                value.client(self.module, timeout_seconds=timeout)
