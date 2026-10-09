"""C new laws: exact deletion, in-use refusal and conserved partial results."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane_kit_core.runtime_effects import configuration_cleanup_outcomes, EffectResultKind
from control_plane_kit_core.runtime_effect_observation import runtime_effect_result_fingerprint
from control_plane_kit_core.runtime_authority import RuntimeEffectContractError
from control_plane_kit_core.planning import CleanupConfigurationInstances
from configuration_cleanup_fixtures import cleanup_fixture, cleanup_request, holder, conflict


class DockerConfigurationCleanupTests(unittest.TestCase):
    def rows(self, request, result):
        self.assertIn("configuration_cleanup", result.evidence, repr(result))
        rows = configuration_cleanup_outcomes(request, result).outcomes
        self.assertEqual(tuple(row.ref for row in rows), request.operation.instances)
        runtime_effect_result_fingerprint(result)
        return [(row.status.value, None if row.reason is None else row.reason.value) for row in rows]

    def test_direct_and_local_remove_only_exact_owned_volumes_then_report_absence(self):
        for local in (False, True):
            with self.subTest(local=local):
                raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture(2)
                neighbor = raw.volumes.create(name="unselected-retained", labels={"kind": "retained"})
                execute = (lambda: interpreter.execute_with_authority(request, SimpleNamespace(
                    runtime_kind="docker", authority_kind="local-docker-socket"))) if local else lambda: interpreter.execute(request)
                result = execute()
                self.assertEqual(self.rows(request, result), [("removed", None)] * 2)
                self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
                self.assertEqual([event for event in events if event[0] == "remove-volume"],
                    [("remove-volume", resource.name, False) for resource in resources])
                self.assertEqual(raw.volumes.resources, {neighbor.name: neighbor})
                self.assertEqual(self.rows(request, execute()), [("already-absent", None)] * 2)
                self.assertEqual(raw.containers.created_containers, [])

    def test_running_stopped_and_foreign_holders_are_retained(self):
        for state in ("running", "exited", "created"):
            with self.subTest(state=state):
                raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
                holders.append(holder(resources[0].name, state))
                result = interpreter.execute(request)
                self.assertEqual(self.rows(request, result), [("retained-in-use", "in-use")])
                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertFalse(any(event[0] == "remove-volume" for event in events))
                self.assertEqual(events, [("use-query", {"all": True, "limit": 1,
                    "filters": {"volume": resources[0].name}})])

    def test_foreign_secret_retained_and_conflicting_reference_labels_are_refused(self):
        changes = {"workspace": "foreign", "runtime": "foreign", "node": "foreign",
            "allocation": "foreign", "kind": "secret-volume", "volume.kind": "retained-data",
            "configuration.profile": "unknown", "configuration.reference": "f" * 64,
            "artifact.digest": "0" * 64}
        for key, value in changes.items():
            with self.subTest(key=key):
                raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
                resources[0].attrs["Labels"]["org.openj92.cpk." + key] = value
                self.assertEqual(self.rows(request, interpreter.execute(request)), [("refused", "ownership-mismatch")])
                self.assertEqual(events, [])
                self.assertIn(resources[0].name, raw.volumes.resources)

    def test_shared_driver_options_and_missing_incarnation_are_not_deleted(self):
        for change in ({"Driver": "nfs"}, {"Scope": "global"}, {"Options": {"type": "nfs"}},
                       {"ClusterVolume": {}}, {"CreatedAt": None}, {"Name": "other"}):
            with self.subTest(change=change):
                raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
                resources[0].attrs.update(change)
                rows = self.rows(request, interpreter.execute(request))
                self.assertIn(rows[0], [("refused", "provenance-unproven"), ("unknown", "provider-uncertain")])
                self.assertFalse(any(event[0] == "remove-volume" for event in events))

    def test_unknown_after_known_removal_conserves_remaining_not_attempted(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture(3)
        remove = resources[1].remove
        def uncertain(**kwargs):
            remove(**kwargs)
            raise TimeoutError("private provider detail")
        resources[1].remove = uncertain
        result = interpreter.execute(request)
        self.assertEqual(self.rows(request, result), [("removed", None),
            ("unknown", "provider-uncertain"), ("unknown", "not-attempted")])
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertIn(resources[2].name, raw.volumes.resources)
        self.assertEqual(len([event for event in events if event[0] == "remove-volume"]), 2)
        self.assertNotIn("private provider detail", repr(result))

    def test_deterministic_refusal_does_not_skip_independent_selected_candidate(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture(2)
        resources[0].attrs["Labels"]["org.openj92.cpk.node"] = "foreign"
        self.assertEqual(self.rows(request, interpreter.execute(request)),
            [("refused", "ownership-mismatch"), ("removed", None)])
        self.assertIn(resources[0].name, raw.volumes.resources)

    def test_changed_incarnation_or_residual_after_remove_stays_unknown_without_retry(self):
        for phase in ("recheck", "residual", "post-read"):
            with self.subTest(phase=phase):
                raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
                if phase == "recheck":
                    query = raw.api.containers
                    def changed(**kwargs):
                        resources[0].attrs["CreatedAt"] = "2026-10-09T00:01:00Z"
                        return query(**kwargs)
                    raw.api.containers = changed
                elif phase == "residual":
                    resources[0].remove = lambda **kwargs: events.append(("remove-volume", resources[0].name, kwargs))
                else:
                    remove = resources[0].remove
                    def removed(**kwargs):
                        remove(**kwargs)
                        raw.volumes.get_error = TimeoutError("private post-read")
                    resources[0].remove = removed
                result = interpreter.execute(request)
                self.assertEqual(self.rows(request, result), [("unknown", "provider-uncertain")])
                self.assertLessEqual(len([event for event in events if event[0] == "remove-volume"]), 1)
                self.assertNotIn("private post-read", repr(result))

    def test_raced_typed_in_use_conflict_is_retained_not_retried(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
        calls = []
        def in_use(**kwargs):
            calls.append(kwargs)
            raise conflict()
        resources[0].remove = in_use
        self.assertEqual(self.rows(request, interpreter.execute(request)), [("retained-in-use", "in-use")])
        self.assertEqual(calls, [{"force": False}])

    def test_unknown_use_evidence_blocks_this_and_later_deletion(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture(2)
        raw.api.containers = lambda **kwargs: None
        result = interpreter.execute(request)
        self.assertEqual(self.rows(request, result), [("unknown", "provider-uncertain"), ("unknown", "not-attempted")])
        self.assertFalse(any(event[0] == "remove-volume" for event in events))

    def test_per_call_tls_refuses_before_resolver_client_provider_or_close(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture(2)
        authority = SimpleNamespace(runtime_kind="docker", authority_kind="remote-docker-tls")
        with patch("control_plane_kit_interpreters.docker.runtime._client_for_runtime_authority") as binding, \
                patch.object(sdk, "close") as close, patch.object(raw.volumes, "get") as read:
            result = interpreter.execute_with_authority(request, authority)
        self.assertEqual(self.rows(request, result), [("refused", "authority-refused")] * 2)
        binding.assert_not_called()
        close.assert_not_called()
        read.assert_not_called()
        self.assertEqual(events, [])

    def test_maximum_admitted_material_is_conserved_and_oversized_is_rejected(self):
        request = cleanup_request(3)
        path = "/" + "/".join(["a" * 127] * 4)
        refs = tuple(replace(ref, allocation_id=f"{index:02d}" + "a" * 126,
            workspace_id="w" * 128, runtime_id="r" * 128, node_id="n" * 128,
            artifact_id="a" * 63, target_path=path) for index, ref in enumerate(request.operation.instances))
        request = replace(request, source=replace(request.source, workspace_id="w" * 128),
            operation=CleanupConfigurationInstances(refs))
        raw, sdk, interpreter, unused, resources, holders, events = cleanup_fixture()
        result = interpreter.execute(request)
        self.assertEqual(self.rows(request, result), [("already-absent", None)] * 3)
        with self.assertRaises(RuntimeEffectContractError):
            replace(request, operation=CleanupConfigurationInstances((*refs, replace(refs[0], allocation_id="z" * 128))))
        self.assertEqual(events, [])
