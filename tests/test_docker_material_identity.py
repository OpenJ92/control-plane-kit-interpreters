from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
from control_plane_kit_core.planning import NodeTarget, ReconcileNode, StartNode, WaitForHealthy
from control_plane_kit_core.runtime_effect_observation import (
    RuntimeEffectObservationRequest, runtime_effect_intent_for_request,
    runtime_effect_intent_fingerprint,
)
from control_plane_kit_core.runtime_effects import EffectResultKind
from control_plane_kit_interpreters.docker import (
    DockerRuntimeEffectObserver, DockerRuntimeInterpreter, DockerSdkClient,
)
import control_plane_kit_interpreters.docker.runtime as runtime_module
from test_docker_runtime_interpreter import (
    _material, _product_with_health_check, _request, _workload_container_records,
    RuntimeHttpProbeResult,
)
from test_docker_runtime_effect_observer import _plain_node_request, _ReadClient
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule


_PREFIX = "org.openj92.cpk."


def _fixture(request=None):
    raw = FakeDockerClient()
    sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
    interpreter = DockerRuntimeInterpreter(sdk)
    request = _request(StartNode(NodeTarget("api"))) if request is None else request
    result = interpreter.execute(request)
    if result.kind is not EffectResultKind.SUCCEEDED:
        raise AssertionError("existing Start fixture did not establish owned material")
    return raw, sdk, interpreter, request, raw.containers.resources[result.evidence["container"]]


class DockerMaterialIdentityTests(unittest.TestCase):
    def test_active_reconcile_reuses_material_across_graph_and_plan_without_relabeling(self):
        for changed in ("graph", "plan", "both"):
            for running in (True, False):
                with self.subTest(changed=changed, running=running):
                    raw, sdk, interpreter, original, container = _fixture()
                    creation = dict(container.attrs["Config"]["Labels"])
                    container.attrs["State"]["Running"] = running
                    source = replace(original.source,
                        desired_graph_id="graph-b" if changed != "plan" else original.source.desired_graph_id,
                        plan_id="plan-b" if changed != "graph" else original.source.plan_id)
                    current = replace(original, source=source, effect_id="effect-b",
                                      operation=ReconcileNode(NodeTarget("api")))
                    self.assertNotEqual(
                        runtime_effect_intent_fingerprint(runtime_effect_intent_for_request(original)),
                        runtime_effect_intent_fingerprint(runtime_effect_intent_for_request(current)),
                    )
                    with patch.object(sdk, "remove_container", wraps=sdk.remove_container) as remove, patch.object(
                        sdk, "create_container", wraps=sdk.create_container,
                    ) as create:
                        result = interpreter.execute(current)
                    self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
                    self.assertEqual(result.evidence["action"], "reused" if running else "started")
                    self.assertEqual(result.effect_id, "effect-b")
                    self.assertTrue(result.observations)
                    self.assertEqual({item.graph_id for item in result.observations}, {source.desired_graph_id})
                    self.assertEqual(container.attrs["Config"]["Labels"], creation)
                    self.assertFalse(container.removed)
                    self.assertEqual(len(_workload_container_records(raw)), 1)
                    remove.assert_not_called()
                    create.assert_not_called()

    def test_start_keeps_exact_creation_graph_and_plan(self):
        for field in ("desired_graph_id", "plan_id"):
            with self.subTest(field=field):
                raw, sdk, interpreter, original, container = _fixture()
                current = replace(original, source=replace(original.source, **{field: "different"}))
                with patch.object(sdk, "start_container") as start, patch.object(sdk, "remove_container") as remove:
                    result = interpreter.execute(current)
                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertEqual(result.observations, ())
                start.assert_not_called()
                remove.assert_not_called()
                self.assertFalse(container.removed)
                self.assertEqual(len(_workload_container_records(raw)), 1)

    def test_reconcile_refuses_unsupported_material_profile_even_when_material_changed(self):
        for profile in (None, "obsolete", "", 7):
            for changed_material in (False, True):
                with self.subTest(profile=profile, changed_material=changed_material):
                    raw, sdk, interpreter, original, container = _fixture()
                    labels = dict(sdk.inspect_container(container.name).labels)
                    labels.pop(_PREFIX + "material-profile", None)
                    if profile is not None:
                        labels[_PREFIX + "material-profile"] = profile
                    inspection = replace(sdk.inspect_container(container.name), labels=labels)
                    current = replace(original, operation=ReconcileNode(NodeTarget("api")))
                    if changed_material:
                        current = replace(current, products=(replace(current.products[0],
                            public_environment=(PublicStaticEnvironmentBinding("PORT", "9090"),)),))
                    with patch.object(sdk, "inspect_container", return_value=inspection), patch.object(
                        runtime_module, "_resolve_product_secret_deliveries",
                        wraps=runtime_module._resolve_product_secret_deliveries,
                    ) as secrets, patch.object(runtime_module, "_image_pull_auth_config",
                        wraps=runtime_module._image_pull_auth_config,
                    ) as image_auth, patch.object(sdk, "remove_container", wraps=sdk.remove_container) as remove, patch.object(
                        sdk, "create_container", wraps=sdk.create_container,
                    ) as create, patch.object(sdk, "start_container", wraps=sdk.start_container) as start:
                        result = interpreter.execute(current)
                    self.assertIs(result.kind, EffectResultKind.FAILED)
                    self.assertEqual(result.observations, ())
                    secrets.assert_not_called()
                    image_auth.assert_not_called()
                    remove.assert_not_called()
                    create.assert_not_called()
                    start.assert_not_called()
                    self.assertFalse(container.removed)
                    self.assertEqual(len(_workload_container_records(raw)), 1)

    def test_reconcile_refuses_malformed_creation_coordinates_and_material_digest(self):
        for field in ("plan", "desired-graph", "fingerprint"):
            for malformed in (None, "", 9):
                with self.subTest(field=field, malformed=malformed):
                    raw, sdk, interpreter, original, container = _fixture()
                    labels = dict(sdk.inspect_container(container.name).labels)
                    labels.pop(_PREFIX + field)
                    if malformed is not None:
                        labels[_PREFIX + field] = malformed
                    inspection = replace(sdk.inspect_container(container.name), labels=labels)
                    current = replace(original, operation=ReconcileNode(NodeTarget("api")))
                    with patch.object(sdk, "inspect_container", return_value=inspection), patch.object(
                        sdk, "remove_container", wraps=sdk.remove_container,
                    ) as remove, patch.object(sdk, "create_container", wraps=sdk.create_container) as create:
                        result = interpreter.execute(current)
                    self.assertIs(result.kind, EffectResultKind.FAILED)
                    self.assertEqual(result.observations, ())
                    remove.assert_not_called()
                    create.assert_not_called()
                    self.assertFalse(container.removed)
                    self.assertEqual(len(_workload_container_records(raw)), 1)

    def test_cross_graph_reconcile_still_refuses_foreign_scope(self):
        for field in ("workspace", "runtime", "node"):
            with self.subTest(field=field):
                raw, sdk, interpreter, original, container = _fixture()
                container.attrs["Config"]["Labels"][_PREFIX + field] = "foreign"
                current = replace(original, operation=ReconcileNode(NodeTarget("api")),
                    source=replace(original.source, desired_graph_id="graph-b", plan_id="plan-b"))
                with patch.object(sdk, "start_container") as start, patch.object(sdk, "remove_container") as remove:
                    result = interpreter.execute(current)
                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertEqual(result.observations, ())
                start.assert_not_called()
                remove.assert_not_called()
                self.assertEqual(len(_workload_container_records(raw)), 1)

    def test_retrospective_reconcile_does_not_inherit_active_prior_graph_allowance(self):
        original = _plain_node_request(ReconcileNode)
        current = replace(original, source=replace(original.source, desired_graph_id="graph-b", plan_id="plan-b"))
        client = _ReadClient(current)
        # Isolate container correlation: the network already has current request evidence.
        client.container = _ReadClient(original).container
        before = repr((client.network, client.container))
        result = DockerRuntimeEffectObserver(client).observe(RuntimeEffectObservationRequest(current), None)
        self.assertEqual(result.descriptor()["kind"], "conflict")
        self.assertEqual(result.request_fingerprint,
            runtime_effect_intent_fingerprint(runtime_effect_intent_for_request(current)))
        self.assertEqual(result.observations, ())
        self.assertEqual(client.mutations, [])
        self.assertEqual(repr((client.network, client.container)), before)

    def test_native_health_keeps_graph_scope_but_not_plan_scope(self):
        for changed_graph in (False, True):
            with self.subTest(changed_graph=changed_graph):
                original = _request(StartNode(NodeTarget("api")),
                    products=(_material(_product_with_health_check()),))
                raw, sdk, interpreter, original, container = _fixture(original)
                current = replace(original, operation=WaitForHealthy(NodeTarget("api")),
                    source=replace(original.source, plan_id="plan-b",
                        desired_graph_id="graph-b" if changed_graph else original.source.desired_graph_id))
                with patch.object(sdk, "run_http_probe", return_value=RuntimeHttpProbeResult(200, 3, 0, "completed", None)) as probe:
                    result = interpreter.execute(current)
                self.assertIs(result.kind, EffectResultKind.FAILED if changed_graph else EffectResultKind.SUCCEEDED)
                if changed_graph:
                    probe.assert_not_called()
                    self.assertEqual(result.observations, ())
                else:
                    self.assertEqual(probe.call_count, 1)
                self.assertFalse(container.removed)
