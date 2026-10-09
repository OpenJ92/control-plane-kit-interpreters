"""I177-B2: original allocation selection, ordering, identity and uncertainty."""
from dataclasses import replace
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane_kit_core.configuration_invocation import (
    configuration_invocation_completion_for_result,
    configuration_invocation_correlation_for_request,
)
from control_plane_kit_core.planning import NodeTarget, ReconcileNode
from control_plane_kit_core.runtime_effect_observation import runtime_effect_result_fingerprint
from control_plane_kit_core.runtime_effects import EffectResultKind, RuntimeEffectKind
from control_plane_kit_core.runtime_authority import (
    RuntimeAuthorityAccessDelivery, RuntimeAuthorityAccessDeliveryKind, RuntimeAuthorityReference,
)
from control_plane_kit_interpreters.docker.sdk import DockerSdkConfigurationFileInspection
from configuration_replacement_fixtures import fixture, legacy_start, selected_request
from test_docker_sdk_client import FakeResource
from test_docker_runtime_interpreter import _local_socket_transport


class DockerConfigurationReplacementTests(unittest.TestCase):
    def succeeded(self, result):
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED, repr(result))
        runtime_effect_result_fingerprint(result)

    def completed(self, request, result):
        return configuration_invocation_completion_for_result(
            configuration_invocation_correlation_for_request(request), result)

    def old(self, raw, interpreter):
        result = legacy_start(interpreter)
        self.succeeded(result)
        return raw.containers.resources[result.evidence["container"]]

    def test_start_and_replay_install_exact_selection_with_correlated_completion(self):
        for with_authority in (False, True):
            with self.subTest(with_authority=with_authority):
                raw, sdk, interpreter, events = fixture()
                request = selected_request(count=2)
                execute = (lambda value: interpreter.execute_with_authority(value,
                    SimpleNamespace(runtime_kind="docker", authority_kind="local-docker-socket"))
                    if with_authority else interpreter.execute(value))
                first = execute(request)
                self.succeeded(first)
                first_id = first.evidence["configuration_attempt"]["container_id"]
                self.assertEqual(len(first_id), 64)
                self.assertIsNotNone(self.completed(request, first))
                replay = execute(request)
                self.succeeded(replay)
                self.assertEqual(replay.evidence["configuration_attempt"]["container_id"], first_id)
                self.assertEqual(len([item for item in events if item[:2] == ("create", "workload")]), 1)
                self.assertEqual(len(raw.volumes.created), 2)

    def test_all_selected_artifacts_are_verified_before_old_identity_removal(self):
        raw, sdk, interpreter, events = fixture()
        old = self.old(raw, interpreter)
        prior_archives = {name: dict(data) for name, data in raw.containers.volume_archives.items()}
        request = selected_request(reconcile=True, count=2, content='{"route":"new"}')
        verified = []
        inspect_file = sdk.inspect_configuration_file

        def staged(name):
            self.assertFalse(old.removed)
            value = inspect_file(name)
            if value is not None:
                verified.append(name)
            return value

        with patch.object(sdk, "inspect_configuration_file", side_effect=staged):
            result = interpreter.execute(request)
        self.succeeded(result)
        self.assertEqual(len(set(verified)), 2)
        self.assertTrue(old.removed)
        attempt = result.evidence["configuration_attempt"]
        self.assertEqual(attempt["old_container_id"], old.attrs["Id"])
        self.assertNotEqual(attempt["container_id"], old.attrs["Id"])
        self.assertEqual(attempt["staged_indices"], [0, 1])
        self.assertTrue(attempt["old_removed"])
        self.assertIn(("get", old.attrs["Id"]), events)
        for name, data in prior_archives.items():
            self.assertEqual(raw.containers.volume_archives[name], data)
        self.assertIsNotNone(self.completed(request, result))

    def test_last_artifact_failure_preserves_old_compute_and_reports_staged_residue(self):
        raw, sdk, interpreter, events = fixture()
        old = self.old(raw, interpreter)
        request = selected_request(reconcile=True, count=2)
        materialize = sdk.materialize_configuration_artifact

        def fail_last(name, artifact):
            if artifact.artifact_id == "config-1":
                raise TimeoutError("private provider response")
            return materialize(name, artifact)

        with patch.object(sdk, "materialize_configuration_artifact", side_effect=fail_last):
            result = interpreter.execute(request)
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertFalse(old.removed)
        self.assertEqual(result.evidence["configuration_attempt"]["staged_indices"], [0])
        self.assertIsNone(self.completed(request, result))
        self.assertNotIn("private provider response", repr(result))

    def test_same_bytes_new_allocation_replaces_but_same_selection_new_graph_reuses(self):
        raw, sdk, interpreter, events = fixture()
        first_request = selected_request()
        first = interpreter.execute(first_request)
        self.succeeded(first)
        request = selected_request(reconcile=True, generation="b")
        second = interpreter.execute(request)
        self.succeeded(second)
        first_id = first.evidence["configuration_attempt"]["container_id"]
        second_id = second.evidence["configuration_attempt"]["container_id"]
        self.assertNotEqual(first_id, second_id)
        changed = replace(request, source=replace(request.source, desired_graph_id="graph-next", plan_id="plan-next"))
        third = interpreter.execute(changed)
        self.succeeded(third)
        self.assertEqual(third.evidence["configuration_attempt"]["container_id"], second_id)
        self.assertEqual(len(raw.volumes.created), 2)
        self.assertNotEqual(self.completed(request, second).request_fingerprint,
                            self.completed(changed, third).request_fingerprint)

    def test_foreign_or_conflicting_selected_volume_is_not_rewritten(self):
        for changed in ("scope", "material"):
            with self.subTest(changed=changed):
                raw, sdk, interpreter, events = fixture()
                request = selected_request()
                first = interpreter.execute(request)
                self.succeeded(first)
                volume = next(iter(raw.volumes.resources.values()))
                if changed == "scope":
                    volume.attrs["Config"]["Labels"]["org.openj92.cpk.workspace"] = "foreign"
                    patcher = patch.object(sdk, "materialize_configuration_artifact", wraps=sdk.materialize_configuration_artifact)
                    with patcher as write:
                        result = interpreter.execute(request)
                        write.assert_not_called()
                else:
                    with patch.object(sdk, "inspect_configuration_file", return_value=
                        DockerSdkConfigurationFileInspection("0" * 64, 0o444, True)), patch.object(
                        sdk, "materialize_configuration_artifact", wraps=sdk.materialize_configuration_artifact,
                    ) as write:
                        result = interpreter.execute(request)
                        write.assert_not_called()
                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertIsNotNone(self.completed(request, result))

    def test_missing_created_identity_stops_without_name_fallback_or_completion(self):
        raw, sdk, interpreter, events = fixture()
        old = self.old(raw, interpreter)
        raw.containers.after_create = lambda resource: resource.attrs.pop("Id")
        request = selected_request(reconcile=True)
        result = interpreter.execute(request)
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertTrue(old.removed)
        self.assertIsNone(result.evidence["configuration_attempt"]["container_id"])
        self.assertEqual(result.evidence["configuration_attempt"]["phase"], "container-create")
        self.assertIsNone(self.completed(request, result))
        self.assertEqual(len([item for item in events if item[:2] == ("create", "workload")]), 2)
        new = raw.containers.created_containers[-1]
        self.assertFalse(new.started or new.removed)

    def test_installed_file_mismatch_cannot_become_success(self):
        raw, sdk, interpreter, events = fixture()
        request = selected_request()
        inspect_mount = sdk.inspect_configuration_mount

        def wrong(identity, mount):
            value = inspect_mount(identity, mount)
            return replace(value, file=replace(value.file, content_digest="0" * 64))

        with patch.object(sdk, "inspect_configuration_mount", side_effect=wrong):
            result = interpreter.execute(request)
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertTrue(result.evidence["configuration_attempt"]["container_id"])
        self.assertEqual(result.evidence["configuration_attempt"]["phase"], "installed-verification")
        self.assertIsNotNone(self.completed(request, result))

    def test_replacement_follows_created_identity_when_logical_name_changes(self):
        raw, sdk, interpreter, events = fixture()
        old = self.old(raw, interpreter)

        def reuse_name(resource):
            other = FakeResource(resource.name)
            other.attrs["Id"] = "f" * 64
            raw.containers.resources[resource.name] = other

        raw.containers.after_create = reuse_name
        request = selected_request(reconcile=True)
        result = interpreter.execute(request)
        self.succeeded(result)
        identity = result.evidence["configuration_attempt"]["container_id"]
        self.assertNotIn(identity, (old.attrs["Id"], "f" * 64))
        self.assertIn(("start", "workload", identity), events)
        self.assertTrue(any(item[:3] == ("read", "workload", identity) for item in events))
        self.assertFalse(raw.containers.resources[old.name].started)

    def test_stage_mode_conflict_is_terminal_but_preserves_old_compute(self):
        raw, sdk, interpreter, events = fixture()
        old = self.old(raw, interpreter)
        request = selected_request(reconcile=True)
        inspect_file = sdk.inspect_configuration_file

        def wrong_mode(name):
            value = inspect_file(name)
            return None if value is None else replace(value, mode=0o666)

        with patch.object(sdk, "inspect_configuration_file", side_effect=wrong_mode):
            result = interpreter.execute(request)
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertFalse(old.removed)
        self.assertIsNotNone(self.completed(request, result))

    def test_ambiguous_removal_does_not_create_or_complete(self):
        raw, sdk, interpreter, events = fixture()
        old = self.old(raw, interpreter)
        remove = sdk.remove_container

        def removed_but_unknown(identity):
            remove(identity)
            raise TimeoutError("private remove detail")

        request = selected_request(reconcile=True)
        with patch.object(sdk, "remove_container", side_effect=removed_but_unknown):
            result = interpreter.execute(request)
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertTrue(old.removed)
        self.assertEqual(result.evidence["configuration_attempt"]["phase"], "container-remove")
        self.assertIsNone(self.completed(request, result))
        self.assertEqual(len([item for item in events if item[:2] == ("create", "workload")]), 1)
        self.assertNotIn("private remove detail", repr(result))

    def test_unknown_helper_cleanup_preserves_old_compute_without_completion(self):
        raw, sdk, interpreter, events = fixture()
        old = self.old(raw, interpreter)
        helper = sdk._create_configuration_helper

        def uncertain_helper(*arguments, **kwargs):
            value = helper(*arguments, **kwargs)
            def failed_remove(**ignored):
                raise TimeoutError("private cleanup detail")
            value.remove = failed_remove
            return value

        request = selected_request(reconcile=True)
        with patch.object(sdk, "_create_configuration_helper", side_effect=uncertain_helper):
            result = interpreter.execute(request)
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertFalse(old.removed)
        self.assertIsNone(self.completed(request, result))
        self.assertNotIn("private cleanup detail", repr(result))

    def test_maximum_selection_has_bounded_whole_result_and_exact_completion(self):
        raw, sdk, interpreter, events = fixture()
        request = selected_request(count=32)
        selection = replace(request.configuration_instances, instances=tuple(
            replace(ref, allocation_id="a" * 124 + format(index, "04d"))
            for index, ref in enumerate(request.configuration_instances.instances)))
        request = replace(request, configuration_instances=selection)
        result = interpreter.execute(request)
        self.succeeded(result)
        self.assertEqual(result.evidence["configuration_attempt"]["staged_indices"], list(range(32)))
        self.assertIsNotNone(self.completed(request, result))
        self.assertLessEqual(len(json.dumps(result.descriptor(), separators=(",", ":")).encode()), 8192)

    def test_changed_material_retains_authority_delivery_refusal_before_staging(self):
        raw, sdk, interpreter, events = fixture()
        _local_socket_transport(raw)
        reference = RuntimeAuthorityReference("local-docker")
        delivery = RuntimeAuthorityAccessDelivery(reference,
            RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT)

        def privileged(request):
            return replace(request, authority_ref=reference, authority_deliveries=(delivery,),
                products=(replace(request.products[0], runtime_authority_deliveries=(delivery,)),))

        original = privileged(selected_request())
        legacy = replace(original, kind=RuntimeEffectKind.REALIZE_ACTIVITY, configuration_instances=None)
        with patch("control_plane_kit_interpreters.docker.runtime.os.stat",
                   return_value=SimpleNamespace(st_gid=987)):
            first = interpreter.execute(legacy)
            self.succeeded(first)
            old = raw.containers.resources[first.evidence["container"]]
            before = len(raw.volumes.created), len(raw.containers.created_containers)
            changed = privileged(selected_request(reconcile=True, generation="b", content='{"route":"new"}'))
            result = interpreter.execute(changed)
        self.assertIs(result.kind, EffectResultKind.UNSUPPORTED)
        self.assertEqual(result.failure.code, "docker.runtime-authority-change-unsupported")
        self.assertFalse(old.removed)
        self.assertEqual((len(raw.volumes.created), len(raw.containers.created_containers)), before)
