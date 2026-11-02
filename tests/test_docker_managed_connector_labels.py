"""#239: configuration-aware creation and native ownership must compose."""
from copy import deepcopy
from dataclasses import replace
import unittest

from control_plane_kit_core.planning import StartNode
from control_plane_kit_core.runtime_effects import EffectResultKind, RuntimeEffectKind
from control_plane_kit_core.runtime_effect_observation import runtime_effect_intent_for_request, runtime_effect_intent_fingerprint
from control_plane_kit_core.secret_installation import secret_material_selection_fingerprint
from control_plane_kit_interpreters.docker import connector_connection as module
from docker_connector_fixtures import World, CONTAINER_ID
from managed_connector_fixtures import managed_world, observe, SELECTION_LABEL, TARGET
from test_docker_retained_image_connector import image_transition
from test_docker_selected_secrets import request_for, selected_fixture


def world_for(mode):
    world = managed_world(retained=mode != "fresh")
    return image_transition(world) if mode == "image" else world


class ManagedConnectorLabelTests(unittest.TestCase):
    def test_configuration_start_emitted_labels_are_accepted_unchanged(self):
        world = managed_world()
        activity, = (item for item in world.plan.activities
            if type(item.operation) is StartNode and item.operation.target.node_id == "connector")
        request = replace(world.request, kind=RuntimeEffectKind.CONFIGURATION_ACTIVITY_V1,
            activity_id=activity.activity_id, operation=activity.operation,
            effect_id="event-start", source=replace(world.request.source, intent_event_id="event-start"),
            configuration_instances=world.configuration_selection)
        selection, = world.material.secret_selections
        grant = replace(request_for().secret_resolution_grants[0], selection=selection,
            workspace_id=request.source.workspace_id, operation_id=request.source.request_id,
            run_id=request.source.run_id.value, activity_id=request.activity_id.value, effect_id=request.effect_id,
            request_fingerprint=runtime_effect_intent_fingerprint(runtime_effect_intent_for_request(request)),
            selection_fingerprint=secret_material_selection_fingerprint(request))
        request = replace(request, secret_resolution_grants=(grant,))
        raw, sdk, interpreter, events, resolver = selected_fixture(request, user="65532:65532")
        started = interpreter.execute(request)
        self.assertIs(started.kind, EffectResultKind.SUCCEEDED, repr(started))
        # Capture actual create output, not a second implementation of label derivation.
        created = raw.containers.resources[started.evidence["container"]]
        for container in world.containers:
            container["Config"]["Labels"] = deepcopy(created.attrs["Config"]["Labels"])
        self.assertEqual(observe(world).outcome.value, "connected")
        self.assertEqual(world.archive_calls, [("get", CONTAINER_ID), ("archive", TARGET)])

    def test_managed_selection_is_required_and_canonical_in_every_mode(self):
        for mode in ("fresh", "content", "image"):
            for value in (None, "", "a" * 63, "A" * 64, "g" * 64):
                with self.subTest(mode=mode, value=value):
                    world = world_for(mode)
                    for container in world.containers:
                        labels = container["Config"]["Labels"]
                        if value is None:
                            del labels[SELECTION_LABEL]
                        else:
                            labels[SELECTION_LABEL] = value
                    self.assertEqual(observe(world).outcome.value, "unknown")
                    self.assertEqual(world.api.calls, [("container", world.name)])
                    self.assertEqual(world.archive_calls, [])

    def test_fresh_selection_is_candidate_but_retained_selection_must_match(self):
        for mode in ("fresh", "content", "image"):
            with self.subTest(mode=mode):
                world = world_for(mode)
                for container in world.containers:
                    container["Config"]["Labels"][SELECTION_LABEL] = "f" * 64
                self.assertEqual(observe(world).outcome.value, "connected" if mode == "fresh" else "unknown")
                if mode != "fresh":
                    self.assertEqual(world.api.calls, [("container", world.name)])
                    self.assertEqual(world.archive_calls, [])

    def test_configuration_label_does_not_excuse_other_ownership_changes(self):
        for mode in ("fresh", "content", "image"):
            for key, value in (("unexpected", "extra"), ("fingerprint", "e" * 64),
                               ("node", "foreign"), ("plan", "foreign")):
                with self.subTest(mode=mode, key=key):
                    world = world_for(mode)
                    for container in world.containers:
                        container["Config"]["Labels"]["org.openj92.cpk." + key] = value
                    self.assertEqual(observe(world).outcome.value, "unknown")
                    self.assertEqual(world.api.calls, [("container", world.name)])
                    self.assertEqual(world.archive_calls, [])

    def test_selection_only_drift_is_not_removed_from_final_snapshot(self):
        for mode in ("fresh", "content", "image"):
            with self.subTest(mode=mode):
                world = world_for(mode)
                world.containers[1]["Config"]["Labels"][SELECTION_LABEL] = "f" * 64
                self.assertEqual(observe(world).outcome.value, "unknown")
                self.assertEqual(world.archive_calls, [("get", CONTAINER_ID), ("archive", TARGET)])
                self.assertEqual(world.api.calls[-1], ("container", CONTAINER_ID))

    def test_default_native_profile_does_not_admit_configuration_label(self):
        world = World()
        for container in world.containers:
            container["Config"]["Labels"][SELECTION_LABEL] = "f" * 64
        self.assertEqual(world.observe(module).outcome.value, "unknown")
        self.assertEqual(world.api.calls, [("container", world.name)])
