"""#214: retained-image qualification and original installation proof laws."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import unittest

import control_plane_kit_core as core
from control_plane_kit_core.configuration import ConfigurationFileMode, ConfigurationMediaType
from control_plane_kit_core.planning import ActivityPlan, ObserveManagementBootstrap, ManagementBootstrapStage, ReconcileNode
from control_plane_kit_core.runtime_effects import RuntimeEffectKind
from control_plane_kit_core.secret_selections import UnselectedSecretUse
from control_plane_kit_core.topology import validate_graph
from control_plane_kit_interpreters.docker import connector_connection as module
from docker_connector_fixtures import RetainedWorld, CONTAINER_ID, sample
from managed_connector_fixtures import managed_world, observer, TARGET
from test_docker_connector_shape import shape_world, declared_snapshot
from test_docker_configuration_readback import archive_bytes


IMAGE_MODE = "retained_image_ingress_update"


def image_transition(world, *, reverse=False):
    """Compile actual public graph values; original connector installation is retained."""
    workload = world.current.graph.nodes["workload"]
    before = replace(workload, metadata={"product_identity": "fixture/workload/2" if reverse else "fixture/workload/1",
        "product_descriptor_digest": "a" * 64, "oci_image": "ghcr.io/fixture/workload@sha256:" + "a" * 64})
    after = replace(before, metadata={"product_identity": "fixture/workload/1" if reverse else "fixture/workload/2",
        "product_descriptor_digest": "b" * 64, "oci_image": "ghcr.io/fixture/workload@sha256:" + "b" * 64})
    world.current = validate_graph(world.current.graph.update_node(before))
    world.desired = validate_graph(world.current.graph.update_node(after))
    world.current.require_valid()
    world.desired.require_valid()
    world.plan = core.compile_retained_image_ingress_activity_plan(world.current, world.desired)
    if not world.plan.ready_for_execution or not world.plan.activities:
        raise AssertionError("actual retained-image fixture must compile a nonempty ready plan")
    activity, = (value for value in world.plan.activities
        if type(value.operation) is ObserveManagementBootstrap
        and value.operation.stage is ManagementBootstrapStage.CONNECTOR_CONNECTED)
    world.request = replace(world.request, activity_id=activity.activity_id, operation=activity.operation)
    return world


def image_world(*, managed=True, reverse=False):
    world = managed_world(retained=True, lazy=True) if managed else RetainedWorld(lazy=True)
    return image_transition(world, reverse=reverse)


def qualify(world, *, managed=True, **changes):
    def no_clock():
        raise AssertionError("pure qualification must not read time")
    options = dict(activity_id=world.request.activity_id, plan=world.plan, current=world.current,
        desired=world.desired, material=world.material, authority_ref=world.request.authority_ref)
    options.update(changes)
    return observer(world, managed=managed, clock=no_clock).qualify(**options)


def observe(world, *, managed=True, **changes):
    options = dict(request=world.request, plan=world.plan, current=world.current, desired=world.desired,
        installation_request=world.installation_request, installation_receipt=world.installation_receipt)
    options.update(changes)
    return observer(world, managed=managed).observe(**options)


class RetainedImageConnectorTests(unittest.TestCase):
    def assert_no_io(self, world):
        self.assertEqual(world.initializations + world.api.calls + getattr(world, "archive_calls", []), [])

    def test_full_and_declared_qualification_are_pure_for_both_launch_profiles(self):
        for managed in (False, True):
            for reverse in (False, True):
                with self.subTest(managed=managed, reverse=reverse):
                    if managed:
                        world = image_world(reverse=reverse)
                        document = world.document
                    else:
                        world, document = shape_world(RetainedWorld)
                        image_transition(world, reverse=reverse)
                    before = declared_snapshot(world, document)
                    mode = qualify(world, managed=managed)
                    self.assertEqual(getattr(mode, "value", None), IMAGE_MODE)
                    def no_clock():
                        raise AssertionError("shape qualification must not read time")
                    shape = observer(world, managed=managed, clock=no_clock).qualify_shape(
                        activity_id=world.request.activity_id, plan=world.plan, current=world.current,
                        desired=world.desired, product_document=document, authority_ref=world.request.authority_ref)
                    self.assertIs(shape, mode)
                    self.assertEqual(declared_snapshot(world, document), before)
                    self.assert_no_io(world)

    def test_original_installation_is_read_but_observation_returns_current_correlation(self):
        for managed in (False, True):
            for outcome in ("connected", "disconnected", "unknown"):
                with self.subTest(managed=managed, outcome=outcome):
                    world = image_world(managed=managed)
                    self.assertNotEqual(world.request.effect_id, world.installation_request.effect_id)
                    world.mutate("State", "Health", {"Status": "healthy", "Log": [sample(), sample(outcome)]})
                    result = observe(world, managed=managed)
                    self.assertEqual(result.outcome.value, outcome)
                    self.assertEqual((result.effect_id, result.activity_id),
                        (world.request.effect_id, world.request.activity_id.value))
                    self.assertEqual(world.api.calls, [("container", world.name),
                        ("image", world.material.product.image.execution_reference), ("container", CONTAINER_ID)])
                    if managed:
                        self.assertEqual(world.archive_calls, [("get", CONTAINER_ID), ("archive", TARGET)])
                        self.assertNotIn(world.artifact.content, repr(result))

    def test_only_complete_canonical_image_plan_is_qualified(self):
        for case in ("old-v1", "empty", "filtered", "dependencies", "foreign-graph", "coupled-content"):
            with self.subTest(case=case):
                world = image_world()
                if case == "old-v1":
                    world.plan = core.compile_managed_update_activity_plan(world.current, world.desired)
                    self.assertTrue(world.plan.ready_for_execution)
                elif case == "empty": world.plan = ActivityPlan(())
                elif case == "filtered":
                    world.plan = ActivityPlan(tuple(value for value in world.plan.activities
                        if value.activity_id == world.request.activity_id))
                elif case == "dependencies":
                    world.plan = ActivityPlan(tuple(replace(value, dependencies=())
                        if type(value.operation) is ReconcileNode else value for value in world.plan.activities))
                    self.assertTrue(world.plan.ready_for_execution)
                elif case == "foreign-graph": world.desired = world.current
                else:
                    node = world.desired.graph.nodes["workload"]
                    wrapper, application = node.configuration_artifacts
                    world.desired = validate_graph(world.desired.graph.update_node(replace(node,
                        configuration_artifacts=(wrapper, replace(application, content='{"mode":"other"}', source_digest=None)))))
                self.assertIsNone(qualify(world))
                self.assertEqual(observe(world).outcome.value, "refused")
                self.assert_no_io(world)

    def test_current_authority_and_exact_connector_material_remain_required(self):
        for case in ("authority", "token-version", "material-node", "image"):
            with self.subTest(case=case):
                world = image_world()
                changes = {}
                request = world.request
                if case == "authority":
                    changes["authority_ref"] = replace(request.authority_ref, reference_id="foreign")
                    request = replace(request, authority_ref=changes["authority_ref"])
                else:
                    material = world.material
                    if case == "token-version":
                        material = replace(material, secret_selections=(
                            UnselectedSecretUse(world.file.reference, world.file.intent),))
                    elif case == "material-node": material = replace(material, node_id="foreign")
                    else: material = replace(material, product=replace(material.product,
                        image=replace(material.product.image, digest="sha256:" + "f" * 64)))
                    changes["material"] = material
                    request = replace(request, products=(material,))
                self.assertIsNone(qualify(world, **changes))
                self.assertEqual(observe(world, request=request).outcome.value, "refused")
                self.assert_no_io(world)

    def test_missing_or_foreign_original_pair_refuses_before_sdk(self):
        for managed in (False, True):
            for case in ("request", "receipt", "request-fingerprint", "selection-fingerprint", "current-as-origin"):
                with self.subTest(managed=managed, case=case):
                    world = image_world(managed=managed)
                    changes = {}
                    if case == "request": changes["installation_request"] = None
                    elif case == "receipt": changes["installation_receipt"] = None
                    elif case == "current-as-origin": changes["installation_request"] = world.request
                    else: changes["installation_receipt"] = replace(world.installation_receipt,
                        **{case.replace("-", "_"): "f" * 64})
                    self.assertEqual(observe(world, managed=managed, **changes).outcome.value, "refused")
                    self.assert_no_io(world)

    def test_managed_image_requires_original_configuration_kind_and_exact_instance(self):
        for case in ("plain-kind", "missing-instance", "workspace_id", "runtime_id", "node_id",
                     "artifact_id", "target_path", "media_type", "file_mode", "content_digest"):
            with self.subTest(case=case):
                world = image_world()
                if case == "plain-kind":
                    world.installation_request = replace(world.installation_request,
                        kind=RuntimeEffectKind.REALIZE_ACTIVITY, configuration_instances=None)
                    world.install_receipt()
                else:
                    # Malformed supplied typed proof must fail closed, not acquire fresh semantics.
                    world.installation_request = deepcopy(world.installation_request)
                    if case == "missing-instance":
                        object.__setattr__(world.installation_request, "configuration_instances", None)
                    else:
                        reference, = world.installation_request.configuration_instances.instances
                        value = {"target_path": "/etc/foreign.json", "content_digest": "f" * 64,
                            "media_type": ConfigurationMediaType.TEXT,
                            "file_mode": ConfigurationFileMode.OWNER_READ_ONLY}.get(case, "foreign")
                        object.__setattr__(reference, case, value)
                result = observe(world)
                self.assertEqual(result.outcome.value, "refused")
                self.assertIsNone(result.effect_id)
                self.assert_no_io(world)

    def test_observed_wrong_volume_or_incarnation_is_unknown_without_archive_read(self):
        for case in ("volume", "incarnation"):
            with self.subTest(case=case):
                world = image_world()
                if case == "volume":
                    for container in world.containers:
                        container["HostConfig"]["Mounts"][1]["Source"] = "foreign-candidate"
                        container["Mounts"][1]["Name"] = "foreign-candidate"
                else: world.install_receipt(container_id="e" * 64)
                result = observe(world)
                self.assertEqual(result.outcome.value, "unknown")
                self.assertEqual(result.effect_id, world.request.effect_id)
                self.assertTrue(world.api.calls)
                self.assertEqual(world.archive_calls, [])

    def test_managed_content_freshness_final_drift_and_unavailability_never_attest(self):
        for case in ("body", "mode", "provider", "stale", "late-archive", "final-id"):
            with self.subTest(case=case):
                world = image_world()
                if case == "body": world.archive = archive_bytes(name="control.json", body=b"PRIVATE-CANDIDATE")
                elif case == "mode": world.archive = archive_bytes(name="control.json", body=world.artifact.content.encode(), mode=0o644)
                elif case == "provider": world.error = RuntimeError("PRIVATE-CANDIDATE")
                elif case == "stale": world.now += timedelta(seconds=11)
                elif case == "late-archive":
                    def advance(): world.now += timedelta(seconds=11)
                    world.archive_after_read = advance
                else: world.containers[1]["Id"] = "f" * 64
                result = observe(world)
                self.assertEqual(result.outcome.value, "unknown")
                self.assertEqual(result.effect_id, world.request.effect_id)
                self.assertNotIn("PRIVATE-CANDIDATE", repr(result))
                self.assertNotIn(world.artifact.content, repr(result))
                self.assertLessEqual(len(world.api.calls), 3)
