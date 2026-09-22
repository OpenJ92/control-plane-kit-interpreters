"""#162 selection-to-effect laws; bootstrap and production adoption stay separate."""
import asyncio
from dataclasses import replace
import importlib
import importlib.util
import unittest

import httpx
import control_plane_kit_core as core
from control_plane_kit_core.planning import ActivityId, ActivityPlan, PlannedActivity, NodeTarget, WaitForHealthy
from control_plane_kit_core.public_ingress import IngressAuthorityReference, PublicIngressLifecycle
from control_plane_kit_core.topology import validate_graph
from control_plane_kit_core.types import RuntimeKind
from control_plane_kit_interpreters.probes import health_transport
from docker_management_health_fixtures import BootstrapWorld, ManagedWorld
from health_transport_fixtures import Transport
from test_health_transport import Stream, corrupt_signature

MODULE = "control_plane_kit_interpreters.docker.management_health"


class DockerManagementHealthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Exercise actual selected product + compiler prerequisites even in red.
        self.value = ManagedWorld()
        self.assertIsNotNone(importlib.util.find_spec(MODULE), "#162 managed Docker health adapter is missing")
        self.module = importlib.import_module(MODULE)

    def refused(self, value, result, code="invalid-selection"):
        self.assertIs(type(result), self.module.DockerHealthObservationRefused)
        self.assertEqual(result.code.value, code)
        self.assertEqual(value.resolver.calls, [])
        self.assertEqual(value.gateway_transport.requests, [])
        self.assertEqual(value.workload_transport.requests, [])
        self.assertEqual(value.callbacks, [])
        for secret in (value.pair.transit_credential.decode(), value.pair.workload_credential.decode(),
                       "gateway.example", "PRIVATE-CANDIDATE"):
            self.assertNotIn(secret, repr(result))

    async def test_actual_compiler_signer_relay_sdk_preserve_selected_kind_and_four_outcomes(self):
        for kind in core.NodeHealthReadKind:
            for outcome in core.NodeHealthReadOutcome:
                with self.subTest(kind=kind, outcome=outcome):
                    value = ManagedWorld(kind)
                    value.outcome = outcome
                    node = value.desired.graph.nodes[value.value.gateway.value]
                    self.assertEqual(node.configuration_artifacts, value.contract.configuration_artifacts)
                    self.assertEqual(len(node.configuration_artifacts), 3)
                    self.assertEqual(node.block_spec.verification, value.contract.verification)
                    self.assertEqual(node.block_spec.control_surfaces, value.contract.control_surfaces)
                    self.assertEqual(value.operation.health_kind, kind)
                    async with value.gateway_app.router.lifespan_context(value.gateway_app):
                        result = await value.observe(self.module)
                    self.assertIs(type(result), health_transport.GatewayHealthTransportResult)
                    self.assertEqual(result.code.value, "received")
                    self.assertEqual(result.result.request, value.value.request)
                    self.assertEqual(result.result.declaration, value.value.declaration)
                    self.assertIs(result.result.outcome, outcome)
                    self.assertEqual(value.callbacks, [kind])
                    self.assertEqual(len(value.gateway_transport.requests), 1)
                    request = value.gateway_transport.requests[0]
                    self.assertEqual(request.headers["authorization"], "Bearer " + value.pair.transit_credential.decode())
                    self.assertEqual(len(value.workload_transport.requests), 1)
                    self.assertEqual(value.workload_transport.requests[0].headers["authorization"],
                        "Bearer " + value.pair.workload_credential.decode())

    async def test_base_and_desired_authored_revisions_stay_distinct_with_equal_graphs(self):
        for base in (False, True):
            with self.subTest(base=base):
                value = ManagedWorld()
                if base:
                    value.base_side()
                else:
                    value.current = value.desired
                wrong = replace(value.source, **({"base_graph_id":"other-revision"} if base
                    else {"desired_graph_id":"base-revision"}))
                self.refused(value, await value.observe(self.module, source=wrong))
                result = await value.observe(self.module)
                self.assertEqual(result.code.value, "received")
                self.assertEqual(result.result.request.target.graph_revision.value, "revision-a")
                self.assertEqual(len(value.gateway_transport.requests), 1)

    async def test_plan_graph_relation_and_complete_ingress_mismatches_refuse_before_io(self):
        value = self.value
        operation = value.operation
        candidates = [replace(operation, target=replace(operation.target, **{field:replacement}))
            for field, replacement in (("runtime_id","other"), ("graph_digest","f"*64),
                ("relation_digest","e"*64), ("graph_side",core.PlanGraphSide.BASE_GRAPH))]
        candidates += [replace(operation, node_id="missing"), replace(operation, provider_socket_name="data"),
            replace(operation, health_kind=core.NodeHealthReadKind.LIVENESS)]
        for candidate in candidates:
            with self.subTest(candidate=candidate.descriptor()):
                self.refused(value, await value.observe(self.module, operation=candidate))
        forged = candidates[2]
        forged_plan = ActivityPlan((PlannedActivity(value.activity_id, forged),))
        self.refused(value, await value.observe(self.module, operation=forged, plan=forged_plan))
        self.refused(value, await value.observe(self.module, activity_id=ActivityId("missing")))
        other_plan = ActivityPlan((PlannedActivity(value.activity_id, WaitForHealthy(NodeTarget(value.operation.node_id))),))
        self.refused(value, await value.observe(self.module, plan=other_plan))
        changed = validate_graph(replace(value.desired.graph, name="other-graph"))
        changed.require_valid()
        self.refused(value, await value.observe(self.module, desired=changed))
        destination = value.destination(health_transport)
        ingresses = (replace(value.ingress, hostname="other.example.invalid"),
            replace(value.ingress, connector_node_id="other-connector"),
            replace(value.ingress, authority_ref=IngressAuthorityReference("other-authority")),
            replace(value.ingress, lifecycle=PublicIngressLifecycle.RETAINED),
            replace(value.ingress, target=replace(value.ingress.target, provider_socket="other")))
        for ingress in ingresses:
            with self.subTest(ingress=ingress.descriptor()):
                self.refused(value, await value.observe(self.module, destination=replace(destination, ingress=ingress)))

    async def test_other_valid_signed_context_and_destination_cannot_override_selection(self):
        for field in ("workspace_id", "graph_revision", "node_id", "provider_socket_name", "runtime", "gateway", "declaration"):
            with self.subTest(field=field):
                value = ManagedWorld()
                if field == "runtime":
                    value.resign(runtime=replace(value.value.runtime, value="other-runtime"))
                elif field == "gateway":
                    value.resign(gateway=replace(value.value.gateway, value="other-gateway"))
                elif field == "declaration":
                    value.resign(declaration=replace(value.value.declaration,
                        surface=replace(value.value.declaration.surface, health_reads=(core.NodeHealthReadKind.READINESS,))))
                else:
                    target = replace(value.value.target, **{field:replace(getattr(value.value.target, field), value="other")})
                    declaration = value.value.declaration
                    if field == "provider_socket_name":
                        declaration = replace(declaration, surface=replace(declaration.surface,
                            provider_socket_name=target.provider_socket_name))
                    value.resign(target=target, declaration=declaration)
                self.refused(value, await value.observe(self.module))
        value = self.value
        destination = value.destination(health_transport)
        for changed in (replace(destination, gateway_node_id=replace(destination.gateway_node_id, value="other")),
                        replace(destination, runtime_id=replace(destination.runtime_id, value="other")),
                        replace(destination, gateway_transit_provider_socket_name="data")):
            self.refused(value, await value.observe(self.module, destination=changed))

    async def test_non_docker_and_missing_surface_never_use_private_fallback(self):
        value = ManagedWorld(runtime_kind=RuntimeKind.KUBERNETES)
        self.refused(value, await value.observe(self.module), "unsupported-runtime")
        value = self.value
        nodes = dict(value.desired.graph.nodes)
        node = nodes[value.operation.node_id]
        nodes[node.node_id] = replace(node, block_spec=replace(node.block_spec,
            capabilities=(), control_surfaces=()))
        desired = validate_graph(replace(value.desired.graph, nodes=nodes))
        desired.require_valid()
        self.refused(value, await value.observe(self.module, desired=desired))

    async def test_old_local_native_connected_and_legacy_refuse_before_credential_access(self):
        value = self.value
        class Unreadable:
            def __getattribute__(self, name):
                raise AssertionError("unsupported operation accessed protected input")
        inputs = {name:Unreadable() for name in ("source", "context", "pair", "transit_grant", "workload_grant", "destination")}
        operations = [core.ObserveManagementBootstrap(value.operation.target, stage)
            for stage in (core.ManagementBootstrapStage.GATEWAY_LOCAL_READY,
                          core.ManagementBootstrapStage.CONNECTOR_CONNECTED)]
        operations.append(WaitForHealthy(NodeTarget(value.operation.node_id)))
        for operation in operations:
            with self.subTest(operation=type(operation).__name__):
                self.refused(value, await value.observe(self.module, operation=operation, **inputs), "unsupported-operation")

    async def test_original_expiry_receiver_denial_and_post_send_timeout_remain_nonsemantic(self):
        value = self.value
        value.now = value.value.transit.expires_at
        result = await value.observe(self.module)
        self.assertIs(type(result), health_transport.GatewayHealthTransportResult)
        self.assertEqual(result.code.value, "invalid-context")
        self.assertIsNone(result.result)
        self.assertEqual(value.resolver.calls, [])
        self.assertEqual(value.gateway_transport.requests, [])
        value = ManagedWorld()
        value.pair = replace(value.pair, transit_credential=corrupt_signature(value.pair.transit_credential))
        result = await value.observe(self.module)
        self.assertEqual(result.code.value, "gateway-rejected")
        self.assertIsNone(result.result)
        self.assertEqual(len(value.gateway_transport.requests), 1)
        self.assertEqual(value.workload_transport.requests, [])
        self.assertEqual(value.callbacks, [])
        value = ManagedWorld()
        async def slow(request):
            await asyncio.sleep(1)
            return httpx.Response(200, content=b"{}")
        transport = Transport(httpx.MockTransport(slow))
        result = await value.observe(self.module, client=value.client(health_transport, transport=transport, timeout_seconds=0.02))
        self.assertEqual(result.code.value, "timed-out")
        self.assertIsNone(result.result)
        self.assertEqual(len(transport.requests), 1)
        self.assertTrue(transport.closed)

    async def test_cancellation_closes_actual_transport_and_refusals_are_redacted(self):
        value = self.value
        malformed_source = replace(value.source, workspace_id="PRIVATE-CANDIDATE")
        self.refused(value, await value.observe(self.module, source=malformed_source))
        stream = Stream((b"{}",), delay=10)
        transport = Transport(httpx.MockTransport(lambda request:httpx.Response(200, stream=stream)))
        task = asyncio.create_task(value.observe(self.module,
            client=value.client(health_transport, transport=transport)))
        await asyncio.wait_for(stream.entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(stream.closed)
        self.assertTrue(transport.closed)
        self.assertEqual(len(transport.requests), 1)


class DockerBootstrapHealthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.module = importlib.import_module(MODULE)
        self.stages = (core.ManagementBootstrapStage.AUTHENTICATED_MANAGEMENT_PATH,
                       core.ManagementBootstrapStage.GATEWAY_INGRESS_READY)

    refused = DockerManagementHealthTests.refused

    async def test_each_original_stage_uses_real_same_app_self_readiness(self):
        requests, attempts = set(), set()
        for stage in self.stages:
            for serving in (False, True):
                value = BootstrapWorld(stage)
                self.assertIs(value.operation.stage, stage)
                self.assertEqual(value.desired.graph.node(value.value.gateway.value).configuration_artifacts,
                                 value.contract.configuration_artifacts)
                if serving:
                    async with value.gateway_app.router.lifespan_context(value.gateway_app):
                        result = await value.observe(self.module)
                else:
                    result = await value.observe(self.module)
                self.assertIs(type(result), health_transport.GatewayHealthTransportResult)
                self.assertEqual(result.code.value, "received")
                self.assertEqual(result.result.request, value.value.request)
                self.assertEqual(result.result.declaration, value.value.declaration)
                self.assertIs(result.result.outcome, core.NodeHealthReadOutcome.HEALTHY if serving
                              else core.NodeHealthReadOutcome.UNHEALTHY)
                self.assertEqual(len(value.gateway_transport.requests), 1)
                self.assertEqual(len(value.workload_transport.requests), 1)
                self.assertEqual(value.workload_transport.requests[0].url.path, "/__control/health/readiness")
                self.assertEqual(value.workload_transport.requests[0].headers["authorization"],
                                 "Bearer " + value.pair.workload_credential.decode())
                self.assertEqual(value.callbacks, [])  # No substitute workload callback.
                requests.add(value.value.request.request_id)
                attempts.add(value.context.attempt_id)
        self.assertEqual(len(requests), 2)
        self.assertEqual(len(attempts), 2)

    async def test_original_stage_plan_pins_and_full_ingress_refuse_before_io(self):
        for stage in self.stages:
            value = BootstrapWorld(stage)
            for candidate in (replace(value.operation, stage=self.stages[1] if stage is self.stages[0] else self.stages[0]),
                *(replace(value.operation, target=replace(value.operation.target, **{name:changed})) for name,changed in
                  (("runtime_id","foreign"), ("graph_digest","f"*64), ("relation_digest","e"*64),
                   ("graph_side",core.PlanGraphSide.BASE_GRAPH)))):
                self.refused(value, await value.observe(self.module, operation=candidate))
            self.refused(value, await value.observe(self.module, activity_id=ActivityId("missing")))
            changed = validate_graph(replace(value.desired.graph, name="foreign"))
            changed.require_valid()
            self.refused(value, await value.observe(self.module, desired=changed))
            destination = value.destination(health_transport)
            for ingress in (replace(value.ingress, hostname="other.example.invalid"),
                replace(value.ingress, connector_node_id="foreign"),
                replace(value.ingress, authority_ref=IngressAuthorityReference("foreign")),
                replace(value.ingress, lifecycle=PublicIngressLifecycle.RETAINED),
                replace(value.ingress, target=replace(value.ingress.target, provider_socket="other"))):
                self.refused(value, await value.observe(self.module, destination=replace(destination, ingress=ingress)))

    async def test_authored_side_remains_independent_and_non_docker_refuses(self):
        for stage in self.stages:
            for base in (False, True):
                value = BootstrapWorld(stage)
                if base:
                    value.base_side()  # Selection fixture, not retained-stage admission.
                else:
                    value.current = value.desired
                wrong = replace(value.source, **({"base_graph_id":"foreign"} if base else {"desired_graph_id":"foreign"}))
                self.refused(value, await value.observe(self.module, source=wrong))
                result = await value.observe(self.module)
                self.assertEqual(result.code.value, "received")
            value = BootstrapWorld(stage, runtime_kind=RuntimeKind.KUBERNETES)
            self.refused(value, await value.observe(self.module), "unsupported-runtime")

    async def test_other_signed_own_context_cannot_override_graph_selection(self):
        for stage in self.stages:
            for field in ("workspace_id", "graph_revision", "node_id", "provider_socket_name", "runtime", "gateway", "declaration"):
                value = BootstrapWorld(stage)
                if field == "runtime":
                    value.resign(runtime=replace(value.value.runtime, value="foreign"))
                elif field == "gateway":
                    value.resign(gateway=replace(value.value.gateway, value="foreign"))
                elif field == "declaration":
                    value.resign(declaration=replace(value.value.declaration,
                        surface=replace(value.value.declaration.surface, health_reads=(core.NodeHealthReadKind.READINESS,))))
                else:
                    target = replace(value.value.target, **{field:replace(getattr(value.value.target, field), value="foreign")})
                    declaration = value.value.declaration
                    if field == "provider_socket_name":
                        declaration = replace(declaration, surface=replace(declaration.surface,
                            provider_socket_name=target.provider_socket_name))
                    value.resign(target=target, declaration=declaration)
                self.refused(value, await value.observe(self.module))
            value = BootstrapWorld(stage)
            destination = value.destination(health_transport)
            self.refused(value, await value.observe(self.module, destination=replace(destination,
                gateway_transit_provider_socket_name="wrong-transit")))

    async def test_cross_stage_bundle_parts_and_original_expiry_never_send(self):
        for stage, other in (self.stages, tuple(reversed(self.stages))):
            for field in ("pair", "transit_grant", "workload_grant", "context"):
                value, foreign = BootstrapWorld(stage), BootstrapWorld(other)
                changed = {"pair":foreign.pair, "transit_grant":foreign.value.transit,
                           "workload_grant":foreign.value.workload, "context":foreign.context}[field]
                result = await value.observe(self.module, **{field:changed})
                self.assertIs(type(result), health_transport.GatewayHealthTransportResult)
                self.assertEqual(result.code.value, "invalid-context")
                self.assertIsNone(result.result)
                self.assertEqual(value.resolver.calls, [])
                self.assertEqual(value.gateway_transport.requests, [])
            value = BootstrapWorld(stage)
            value.now = value.value.transit.expires_at
            result = await value.observe(self.module)
            self.assertEqual(result.code.value, "invalid-context")
            self.assertIsNone(result.result)
            self.assertEqual(value.gateway_transport.requests, [])

    async def test_receiver_denial_and_uninstalled_alias_remain_nonsemantic(self):
        for stage in self.stages:
            for family in ("transit", "workload", "alias"):
                value = BootstrapWorld(stage)
                changes = {}
                if family == "alias":
                    changes["destination"] = replace(value.destination(health_transport), target_id="uninstalled-alias")
                else:
                    credential = family + "_credential"
                    value.pair = replace(value.pair, **{credential:corrupt_signature(getattr(value.pair, credential))})
                result = await value.observe(self.module, **changes)
                self.assertIs(type(result), health_transport.GatewayHealthTransportResult)
                self.assertIsNone(result.result)
                self.assertNotEqual(result.code.value, "received")
                self.assertEqual(len(value.gateway_transport.requests), 1)
                self.assertEqual(len(value.workload_transport.requests), 1 if family == "workload" else 0)

    async def test_nonsemantic_response_timeout_and_cancellation_preserve_transport_contract(self):
        for stage in self.stages:
            value = BootstrapWorld(stage)
            transport = Transport(httpx.MockTransport(lambda request:httpx.Response(200, content=b"{}")))
            result = await value.observe(self.module, client=value.client(health_transport, transport=transport))
            self.assertIs(type(result), health_transport.GatewayHealthTransportResult)
            self.assertIsNone(result.result)
            self.assertNotEqual(result.code.value, "received")
            self.assertEqual(len(transport.requests), 1)
            self.assertTrue(transport.closed)
            value = BootstrapWorld(stage)
            stream = Stream((b"{}",), delay=10)
            transport = Transport(httpx.MockTransport(lambda request:httpx.Response(200, stream=stream)))
            task = asyncio.create_task(value.observe(self.module, client=value.client(health_transport, transport=transport)))
            await asyncio.wait_for(stream.entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(stream.closed)
            self.assertTrue(transport.closed)
            self.assertEqual(len(transport.requests), 1)
