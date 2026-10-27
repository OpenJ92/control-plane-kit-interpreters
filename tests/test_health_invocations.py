"""Concrete health admission ordering; no Operations policy or history emulator."""
import asyncio
from dataclasses import replace
import inspect
import unittest

import httpx

from control_plane_kit_interpreters.docker import managed_health
from control_plane_kit_interpreters.probes import health_transport
from control_plane_kit_interpreters.probes.health_signing import (
    Ed25519HealthCredentialPairSigner, HealthCredentialSigningError,
    HealthSigningContext, HealthSigningKey,
)
from health_signing_fixtures import RecordingResolver, world
from health_transport_fixtures import Transport
from docker_management_health_fixtures import ManagedWorld
from managed_health_reader_fixtures import LocalWorld, local_destination, make_reader, read


class ControlError(Exception):
    pass


class Denied(ControlError):
    pass


class RecordingUncertain(ControlError):
    pass


class RecordingPort:
    """Opaque permits and injected faults only; admission decisions belong elsewhere."""
    control_error = ControlError

    def __init__(self, events, *, before=None, after=None):
        self.events, self.before, self.after = events, before, after
        self.permits = {}

    def admit(self, kind, *, authorization_id=None):
        self.events.append(("admit", kind, authorization_id))
        if self.before is not None:
            self.before(kind, authorization_id)
        permit = object()
        self.permits[permit] = (kind, authorization_id)
        return permit

    def record_outcome(self, permit, outcome):
        kind, authorization_id = self.permits[permit]
        self.events.append(("record", kind, authorization_id, outcome))
        if self.after is not None:
            self.after(kind, authorization_id, outcome)


class OrderedResolver(RecordingResolver):
    def __init__(self, value, events):
        super().__init__(value)
        self.events = events

    def resolve(self, grant):
        self.events.append(("resolve", grant.authorization_id))
        return super().resolve(grant)


class HealthSigningInvocationTests(unittest.TestCase):
    def setUp(self):
        self.value = world()
        self.events = []
        self.resolver = OrderedResolver(self.value, self.events)
        self.context = HealthSigningContext(self.value.request, "attempt-a", self.value.gateway_target,
            self.value.declaration, "transit-issuer", "workload-issuer")
        self.arguments = dict(transit_grant=self.value.transit, workload_grant=self.value.workload,
            transit_key=HealthSigningKey(self.value.publics[0], self.value.resolutions[0]),
            workload_key=HealthSigningKey(self.value.publics[1], self.value.resolutions[1]))
        self.signer = Ed25519HealthCredentialPairSigner(self.resolver, lambda: 150)

    def sign(self, port):
        self.assertIn("invocations", inspect.signature(self.signer.sign).parameters,
            "#226 signer does not yet consume the semantic invocation port")
        return self.signer.sign(self.context, **self.arguments, invocations=port)

    def test_each_exact_resolution_is_acknowledged_before_the_next(self):
        result = self.sign(RecordingPort(self.events))
        self.assertEqual(result.request, self.value.request)
        expected = []
        for grant in self.value.resolutions:
            expected.extend((("admit", "secret-resolution", grant.authorization_id),
                ("resolve", grant.authorization_id),
                ("record", "secret-resolution", grant.authorization_id, "returned")))
        self.assertEqual(self.events, expected)
        self.assertEqual(self.resolver.calls, list(self.value.resolutions))

    def test_second_resolution_denial_survives_signer_without_second_read(self):
        denied = Denied("closed-control")
        def before(kind, authorization_id):
            if authorization_id == self.value.resolutions[1].authorization_id:
                raise denied
        with self.assertRaises(Denied) as caught:
            self.sign(RecordingPort(self.events, before=before))
        self.assertIs(caught.exception, denied)
        self.assertEqual(self.resolver.calls, [self.value.resolutions[0]])
        self.assertEqual(self.events[-1], ("admit", "secret-resolution",
            self.value.resolutions[1].authorization_id))

    def test_acknowledgement_failure_after_first_read_prevents_second_admission(self):
        uncertain = RecordingUncertain("closed-control")
        def after(*_):
            raise uncertain
        with self.assertRaises(RecordingUncertain) as caught:
            self.sign(RecordingPort(self.events, after=after))
        self.assertIs(caught.exception, uncertain)
        self.assertEqual(self.resolver.calls, [self.value.resolutions[0]])
        self.assertEqual([event[0] for event in self.events], ["admit", "resolve", "record"])

    def test_provider_failure_keeps_fixed_redaction_and_stops_later_work(self):
        self.resolver.results[self.value.resolutions[0].reference] = RuntimeError("private-provider-sentinel")
        with self.assertRaises(HealthCredentialSigningError) as caught:
            self.sign(RecordingPort(self.events))
        self.assertEqual(str(caught.exception), "health credential signing failed")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(self.resolver.calls, [self.value.resolutions[0]])
        self.assertEqual(self.events[-1], ("record", "secret-resolution",
            self.value.resolutions[0].authorization_id, "unknown"))
        self.assertNotIn("private-provider-sentinel", repr(self.events))


class ManagedHealthInvocationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.value = LocalWorld()
        self.events = []
        self.transport = Transport(httpx.MockTransport(self.handle))
        self.reader, _ = make_reader(managed_health, self.value, transport=self.transport)
        self.keys = OrderedResolver(self.value.value, self.events)
        self.reader = replace(self.reader,
            signer=Ed25519HealthCredentialPairSigner(self.keys, lambda: self.value.now))

    def handle(self, request):
        self.events.append(("transport", request.method))
        return httpx.Response(503, json={"error": "unavailable"})

    def required_reader(self):
        self.assertIn("invocations", inspect.signature(self.reader.observe).parameters,
            "#226 reader does not yet consume the semantic invocation port")
        self.assertIn("require_invocations", inspect.signature(type(self.reader)).parameters,
            "#226 reader has no explicit mandatory invocation construction")
        return replace(self.reader, require_invocations=True)

    async def test_required_missing_or_malformed_port_refuses_before_any_capability(self):
        reader = self.required_reader()
        for port in (None, object()):
            with self.subTest(port_type=type(port).__name__):
                with self.assertRaises((TypeError, ValueError, RuntimeError)):
                    await read(reader, self.value, local=local_destination(managed_health, self.value),
                        invocations=port)
                self.assertEqual(self.keys.calls, [])
                self.assertEqual(self.transport.requests, [])
                self.assertEqual(self.events, [])

    async def test_optional_mode_does_not_ignore_a_malformed_supplied_port(self):
        self.required_reader()
        with self.assertRaises((TypeError, ValueError, RuntimeError)):
            await read(self.reader, self.value, local=local_destination(managed_health, self.value),
                invocations=object())
        self.assertEqual(self.keys.calls, [])
        self.assertEqual(self.transport.requests, [])

    async def test_reader_preserves_secret_and_final_denial_without_transport(self):
        reader = self.required_reader()
        for deny_kind in ("secret-resolution", "signed-health-transport"):
            with self.subTest(deny_kind=deny_kind):
                self.keys.calls.clear()
                self.events.clear()
                denied = Denied("closed-control")
                def before(kind, authorization_id):
                    if kind == deny_kind:
                        raise denied
                with self.assertRaises(Denied) as caught:
                    await read(reader, self.value, local=local_destination(managed_health, self.value),
                        invocations=RecordingPort(self.events, before=before))
                self.assertIs(caught.exception, denied)
                self.assertEqual(len(self.keys.calls), 0 if deny_kind == "secret-resolution" else 2)
                self.assertEqual(self.transport.requests, [])

    async def test_returned_transport_failure_is_acknowledged_after_async_cleanup(self):
        reader = self.required_reader()
        def after(kind, authorization_id, outcome):
            if kind == "signed-health-transport":
                self.assertTrue(self.transport.closed)
        result = await read(reader, self.value, local=local_destination(managed_health, self.value),
            invocations=RecordingPort(self.events, after=after))
        self.assertNotEqual(result.code.value, "received")
        self.assertEqual(self.keys.calls, list(self.value.value.resolutions))
        self.assertEqual(self.events[-3:], [("admit", "signed-health-transport", None),
            ("transport", "GET"), ("record", "signed-health-transport", None, "returned")])

    async def test_final_acknowledgement_control_is_not_redacted_as_transport_failure(self):
        reader = self.required_reader()
        uncertain = RecordingUncertain("closed-control")
        def after(kind, authorization_id, outcome):
            if kind == "signed-health-transport":
                raise uncertain
        with self.assertRaises(RecordingUncertain) as caught:
            await read(reader, self.value, local=local_destination(managed_health, self.value),
                invocations=RecordingPort(self.events, after=after))
        self.assertIs(caught.exception, uncertain)
        self.assertTrue(self.transport.closed)
        self.assertEqual(len(self.transport.requests), 1)

    async def test_cancelled_transport_closes_before_recording_unknown_and_propagates(self):
        reader = self.required_reader()
        entered = asyncio.Event()
        class WaitingTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                entered.set()
                await asyncio.Event().wait()
        transport = Transport(WaitingTransport())
        reader = replace(reader, local_client=replace(reader.local_client, transport=transport))
        def after(kind, authorization_id, outcome):
            if kind == "signed-health-transport":
                self.assertTrue(transport.closed)
        task = asyncio.create_task(read(reader, self.value,
            local=local_destination(managed_health, self.value),
            invocations=RecordingPort(self.events, after=after)))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(transport.closed)
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(self.events[-1], ("record", "signed-health-transport", None, "unknown"))

    async def test_public_final_denial_prevents_dns_and_http_after_exact_signing(self):
        value = ManagedWorld()
        reader, keys = make_reader(managed_health, value)
        self.assertIn("invocations", inspect.signature(reader.observe).parameters,
            "#226 reader does not yet consume the semantic invocation port")
        denied = Denied("closed-control")
        def before(kind, authorization_id):
            if kind == "signed-health-transport":
                raise denied
        with self.assertRaises(Denied) as caught:
            await read(reader, value, destination=value.destination(health_transport),
                invocations=RecordingPort([], before=before))
        self.assertIs(caught.exception, denied)
        self.assertEqual(keys.calls, list(value.value.resolutions))
        self.assertEqual(value.resolver.calls, [])
        self.assertEqual(value.gateway_transport.requests, [])
