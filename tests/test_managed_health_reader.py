"""I189 original selection, bounded real local socket and signed relay laws."""
import asyncio
from dataclasses import replace
import importlib
import importlib.util
import unittest

import httpx
import control_plane_kit_core as core
from control_plane_kit_core.planning import ActivityPlan
from control_plane_kit_core.probe_intents import LiteralEndpointMaterial
from control_plane_kit_core.types import Protocol, RuntimeKind
from control_plane_kit_interpreters.probes import health_transport
from control_plane_kit_interpreters.probes.security import ProbeAddressPolicy
from docker_management_health_fixtures import BootstrapWorld, ManagedWorld
from health_transport_fixtures import Transport
from managed_health_reader_fixtures import LocalWorld, serving, local_destination, make_reader, read, socket_relay
from test_health_transport import Stream

MODULE = "control_plane_kit_interpreters.docker.managed_health"


class ManagedHealthReaderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Existing Core compiler, selected gateway and signer must construct before
        # the target-red assertion; dependency failures cannot stand in for absence.
        self.value = LocalWorld()
        self.assertIsNotNone(importlib.util.find_spec(MODULE), "I189 managed health composition is missing")
        self.module = importlib.import_module(MODULE)

    def refusal(self, result, value, keys, transport=None):
        self.assertNotEqual(result.code.value, "received")
        self.assertEqual(keys.calls, [])
        self.assertEqual(value.resolver.calls, [])
        self.assertEqual(value.gateway_transport.requests, [])
        if transport is not None:
            self.assertEqual(transport.requests, [])
        self.assertNotIn("127.0.0.1", repr(result))
        self.assertNotIn("PRIVATE", repr(result))
        self.assertNotIn("Bearer", repr(result))

    async def test_real_gateway_socket_uses_original_signed_readiness_and_closes(self):
        value = self.value
        requests = []
        async def recorded_app(scope, receive, send):
            if scope["type"] == "http":
                requests.append((scope["method"], scope["raw_path"], dict(scope["headers"]).get(b"authorization")))
            await value.gateway_app(scope, receive, send)
        self.assertIs(value.gateway_app.state.gateway_local_health.readiness(), core.NodeHealthReadOutcome.UNHEALTHY)
        async with serving(recorded_app) as origin:
            reader, keys = make_reader(self.module, value)
            result = await read(reader, value, local=local_destination(self.module, value, origin))
            self.assertEqual(result.code.value, "received")
            self.assertEqual(result.result.request, value.context.request)
            self.assertIs(result.result.outcome, core.NodeHealthReadOutcome.HEALTHY)
            self.assertEqual(keys.calls, list(value.value.resolutions))
            self.assertEqual(value.gateway_transport.requests, [])
            self.assertEqual(value.resolver.calls, [])
            self.assertEqual(requests, [("GET", b"/__control/health/readiness",
                b"Bearer " + value.pair.workload_credential)])
        self.assertIs(value.gateway_app.state.gateway_local_health.readiness(), core.NodeHealthReadOutcome.UNHEALTHY)

    async def test_signed_relay_reaches_actual_receiver_socket_without_helper(self):
        value = ManagedWorld()
        async with serving(value.workload_application) as origin:
            gateway = socket_relay(value, origin)
            reader, keys = make_reader(self.module, value)
            async with gateway.router.lifespan_context(gateway):
                result = await read(reader, value, destination=value.destination(health_transport))
            self.assertEqual(result.code.value, "received")
            self.assertEqual(result.result.request, value.context.request)
            self.assertEqual(value.callbacks, [core.NodeHealthReadKind.READINESS])
            self.assertEqual(keys.calls, list(value.value.resolutions))
            self.assertEqual(len(value.gateway_transport.requests), 1)
            # The old fixture's in-process workload transport was never used.
            self.assertEqual(value.workload_transport.requests, [])

    async def test_local_endpoint_policy_and_selection_refuse_before_signing(self):
        value = self.value
        selected = local_destination(self.module, value)
        candidates = [None, replace(selected, policy=ProbeAddressPolicy())]
        for field, replacement in (("subject_id", "other"), ("socket_name", "other"),
                ("graph_id", "other")):
            candidates.append(replace(selected, endpoint=replace(selected.endpoint, **{field:replacement})))
        candidates.append(replace(selected, endpoint=replace(selected.endpoint,
            protocol=Protocol.TCP, address=LiteralEndpointMaterial("tcp://127.0.0.1:18000"))))
        for candidate in candidates:
            with self.subTest(candidate=repr(candidate)):
                transport = Transport(httpx.MockTransport(lambda request: httpx.Response(200, content=b"{}")))
                reader, keys = make_reader(self.module, value, transport=transport)
                self.refusal(await read(reader, value, local=candidate), value, keys, transport)
        for changes in (
                {"authority_context": replace(value.authority_context, authored_graph_id="other")},
                {"context": replace(value.context, request=replace(value.context.request,
                    target=replace(value.context.request.target, receiver_id="f" * 32)))},
                {"source": replace(value.source, desired_graph_id="other")}):
            reader, keys = make_reader(self.module, value)
            if "source" in changes:
                from control_plane_kit_core.runtime_effects import RuntimeEffectRequest, RuntimeEffectKind
                changes = {"request": RuntimeEffectRequest("event-a", RuntimeEffectKind.REALIZE_ACTIVITY,
                    RuntimeKind.DOCKER, changes["source"], value.activity_id, value.operation)}
            self.refusal(await read(reader, value, local=selected, **changes), value, keys)

    async def test_public_selection_mismatches_refuse_before_key_resolution(self):
        value = ManagedWorld()
        destination = value.destination(health_transport)
        for changes in (
                {"destination": replace(destination, runtime_id=replace(destination.runtime_id, value="other"))},
                {"destination": replace(destination, ingress=replace(destination.ingress, hostname="other.invalid"))},
                {"authority_context": replace(value.authority_context, authored_graph_id="other")},
                {"plan": ActivityPlan(())}):
            with self.subTest(fields=tuple(changes)):
                reader, keys = make_reader(self.module, value)
                self.refusal(await read(reader, value, **{"destination":destination, **changes}), value, keys)

    async def test_base_selection_preserves_original_revision_through_signing(self):
        value = ManagedWorld()
        value.base_side()
        reader, keys = make_reader(self.module, value)
        async with value.workload_lifespan():
            async with value.gateway_app.router.lifespan_context(value.gateway_app):
                result = await read(reader, value, destination=value.destination(health_transport))
        self.assertEqual(result.code.value, "received")
        self.assertEqual(result.result.request, value.context.request)
        self.assertEqual(result.result.request.authority_context.authored_graph_id, value.source.base_graph_id)
        self.assertEqual(keys.calls, list(value.value.resolutions))
        self.assertEqual(len(value.gateway_transport.requests), 1)

    async def test_complete_selection_never_advertises_unsupported_native_stage(self):
        value = self.value
        reader, keys = make_reader(self.module, value)
        self.assertIsNone(reader.select(plan=value.plan, current=value.current, desired=value.desired))
        # A selection-only plan of the supported observations, not a fabricated
        # executable deployment after dropping native dependencies.
        supported = ActivityPlan(tuple(replace(item, dependencies=()) for item in value.plan.activities
            if type(item.operation) in (core.ObserveManagementBootstrap, core.ObserveNodeHealth)
            and not (type(item.operation) is core.ObserveManagementBootstrap
                and item.operation.stage is core.ManagementBootstrapStage.CONNECTOR_CONNECTED)))
        selected = reader.select(plan=supported, current=value.current, desired=value.desired)
        self.assertEqual(selected, tuple(item.activity_id for item in supported.activities))
        native = BootstrapWorld(core.ManagementBootstrapStage.CONNECTOR_CONNECTED)
        reader, keys = make_reader(self.module, native)
        self.refusal(await read(reader, native), native, keys)

    async def test_original_expiry_and_foreign_grants_never_resolve_keys(self):
        value = self.value
        for changed in ("expired", "transit", "workload"):
            with self.subTest(changed=changed):
                value.now = value.value.transit.expires_at if changed == "expired" else 150
                reader, keys = make_reader(self.module, value)
                changes = {}
                if changed != "expired":
                    grant = getattr(value.value, changed)
                    changes[changed + "_grant"] = replace(grant, request_id="other")
                self.refusal(await read(reader, value, local=local_destination(self.module, value), **changes), value, keys)

    async def test_local_failures_are_bounded_nonsemantic_and_close_transport(self):
        cases = ((401, b"PRIVATE", {}, "gateway-rejected"),
            (302, b"PRIVATE", {"location":"http://foreign.invalid"}, "malformed-response"),
            (200, b"{}", {}, "malformed-response"),
            (200, b"x" * 20000, {}, "oversized-response"))
        for status, body, headers, expected in cases:
            with self.subTest(expected=expected, status=status):
                value = self.value
                transport = Transport(httpx.MockTransport(lambda request:
                    httpx.Response(status, content=body, headers=headers)))
                reader, keys = make_reader(self.module, value, transport=transport)
                result = await read(reader, value, local=local_destination(self.module, value))
                self.assertEqual(result.code.value, expected)
                self.assertIsNone(result.result)
                self.assertEqual(len(transport.requests), 1)
                self.assertTrue(transport.closed)
                self.assertNotIn("PRIVATE", repr(result))
                self.assertNotIn("127.0.0.1", repr(result))
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                value = self.value
                stream = Stream((b"{}",), delay=10)
                transport = Transport(httpx.MockTransport(lambda request:httpx.Response(200, stream=stream)))
                reader, _keys = make_reader(self.module, value, transport=transport, timeout=0.03 if not cancel else 5)
                task = asyncio.create_task(read(reader, value, local=local_destination(self.module, value)))
                try:
                    await asyncio.wait_for(stream.entered.wait(), 1)
                    if cancel:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        result = await task
                        self.assertEqual(result.code.value, "timed-out")
                finally:
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                self.assertTrue(stream.closed)
                self.assertTrue(transport.closed)
                self.assertEqual(len(transport.requests), 1)
