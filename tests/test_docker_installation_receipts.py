"""I186: installed success at the actual interpreter/SDK recording boundary."""
from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane_kit_core.configuration_installation import (
    ConfigurationInstallationDisposition as Disposition,
    configuration_installation_receipt_for_result,
)
from control_plane_kit_core.configuration_invocation import (
    configuration_invocation_completion_for_result,
    configuration_invocation_correlation_for_request,
)
from control_plane_kit_core.runtime_authority import RuntimeAuthorityReference
from control_plane_kit_core.runtime_effect_observation import runtime_effect_result_fingerprint
from control_plane_kit_core.runtime_effects import EffectResultKind
from configuration_replacement_fixtures import fixture, legacy_start, selected_request
from test_docker_runtime_interpreter import MappingSecretResolver, _remote_tls_runtime_authority
from test_docker_sdk_client import FakeResource


def expected_identity(container_id):
    # Independent fixed canonical preimage, not the production derivation helper.
    return sha256(b'{"container_id":"' + container_id.encode("ascii")
        + b'","profile":"docker-container-incarnation.v1","provider":"docker",'
          b'"resource_kind":"container"}').hexdigest()


class DockerInstallationReceiptTests(unittest.TestCase):
    def receipt(self, request, result):
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED, repr(result))
        context = configuration_invocation_correlation_for_request(request)
        self.assertIsNotNone(configuration_invocation_completion_for_result(context, result))
        receipt = configuration_installation_receipt_for_result(context, result)
        self.assertIsNotNone(receipt, "verified installation must carry its shared receipt")
        return receipt

    def test_created_replay_and_stopped_restart_attest_same_actual_incarnation(self):
        for authority in (False, True):
            with self.subTest(authority=authority):
                raw, sdk, interpreter, events = fixture()
                request = selected_request(count=2)
                def execute(value):
                    return interpreter.execute_with_authority(value, SimpleNamespace(
                        runtime_kind="docker", authority_kind="local-docker-socket")) if authority else interpreter.execute(value)
                first = execute(request)
                created = self.receipt(request, first)
                identity = first.evidence["configuration_attempt"]["container_id"]
                self.assertIs(created.disposition, Disposition.CREATED)
                self.assertIsNone(created.prior_realization_fingerprint)
                self.assertEqual(created.current_realization_fingerprint, expected_identity(identity))
                self.assertNotIn(identity, json.dumps(created.descriptor()))
                for stopped in (False, True):
                    if stopped:
                        sdk.stop_container(identity)
                    result = execute(request)
                    reused = self.receipt(request, result)
                    self.assertIs(reused.disposition, Disposition.REUSED)
                    self.assertEqual(reused.prior_realization_fingerprint, created.current_realization_fingerprint)
                    self.assertEqual(reused.current_realization_fingerprint, created.current_realization_fingerprint)
                self.assertEqual(len([event for event in events if event[:2] == ("create", "workload")]), 1)

    def test_replacement_and_changed_request_use_provider_identity_not_material_or_plan(self):
        raw, sdk, interpreter, events = fixture()
        request = selected_request(count=2)
        first_result = interpreter.execute(request)
        first = self.receipt(request, first_result)
        for generation, content in (("b", None), ("c", '{"route":"changed"}')):
            changed = selected_request(reconcile=True, generation=generation, count=2, content=content)
            result = interpreter.execute(changed)
            receipt = self.receipt(changed, result)
            attempt = result.evidence["configuration_attempt"]
            self.assertIs(receipt.disposition, Disposition.REPLACED)
            self.assertTrue(attempt["old_removed"])
            self.assertIsNone(sdk.inspect_container(attempt["old_container_id"]))
            self.assertEqual(receipt.prior_realization_fingerprint, first.current_realization_fingerprint)
            self.assertEqual(receipt.current_realization_fingerprint, expected_identity(attempt["container_id"]))
            self.assertNotEqual(receipt.current_realization_fingerprint, receipt.prior_realization_fingerprint)
            next_request = replace(changed, effect_id="effect-next", source=replace(changed.source,
                request_id="request-next", intent_event_id="effect-next",
                desired_graph_id="graph-next", plan_id="plan-next"))
            replay = self.receipt(next_request, interpreter.execute(next_request))
            self.assertIs(replay.disposition, Disposition.REUSED)
            self.assertEqual(replay.current_realization_fingerprint, receipt.current_realization_fingerprint)
            self.assertNotEqual(replay.request_fingerprint, receipt.request_fingerprint)
            first = receipt

    def test_replacement_receipt_follows_actual_created_id_when_name_is_reassigned(self):
        raw, sdk, interpreter, events = fixture()
        old = legacy_start(interpreter)
        self.assertIs(old.kind, EffectResultKind.SUCCEEDED)
        old_id = raw.containers.resources[old.evidence["container"]].attrs["Id"]
        def reused_name(resource):
            other = FakeResource(resource.name)
            other.attrs["Id"] = "f" * 64
            raw.containers.resources[resource.name] = other
        raw.containers.after_create = reused_name
        request = selected_request(reconcile=True)
        result = interpreter.execute(request)
        receipt = self.receipt(request, result)
        actual_id = result.evidence["configuration_attempt"]["container_id"]
        self.assertNotIn(actual_id, (old_id, "f" * 64))
        self.assertEqual(receipt.prior_realization_fingerprint, expected_identity(old_id))
        self.assertEqual(receipt.current_realization_fingerprint, expected_identity(actual_id))
        self.assertIn(("start", "workload", actual_id), events)

    def test_installed_material_and_unknown_readback_never_attest_success(self):
        mutations = {
            "bytes": lambda value: replace(value, file=replace(value.file, content_digest="0" * 64)),
            "mode": lambda value: replace(value, file=replace(value.file, mode=0o666)),
            "regular": lambda value: replace(value, file=replace(value.file, regular_file=False)),
            "volume": lambda value: replace(value, volume_name="different-volume"),
            "target": lambda value: replace(value, target_path="/different-path"),
            "subpath": lambda value: replace(value, subpath="other"),
            "writable": lambda value: replace(value, read_only=False),
            "identity": lambda value: replace(value, container_id="f" * 64),
            "absent": lambda value: None,
        }
        for case, mutate in mutations.items():
            with self.subTest(case=case):
                raw, sdk, interpreter, events = fixture()
                request = selected_request(count=2)
                observe = sdk.inspect_configuration_mount
                def changed(identity, mount):
                    value = observe(identity, mount)
                    return mutate(value) if mount.artifact.artifact_id == "config-1" else value
                with patch.object(sdk, "inspect_configuration_mount", side_effect=changed):
                    result = interpreter.execute(request)
                self.assertIs(result.kind, EffectResultKind.UNCERTAIN if case in ("identity", "absent") else EffectResultKind.FAILED)
                self.assertNotIn("configuration_installation_receipt", result.evidence)
                self.assertEqual(result.evidence["configuration_attempt"]["staged_indices"], [0, 1])
                runtime_effect_result_fingerprint(result)

    def test_partial_or_ambiguous_provider_effects_never_attest_installation(self):
        for method in ("materialize_configuration_artifact", "remove_container", "create_container", "start_container"):
            with self.subTest(method=method):
                raw, sdk, interpreter, events = fixture()
                self.assertIs(legacy_start(interpreter).kind, EffectResultKind.SUCCEEDED)
                request = selected_request(reconcile=True, count=2)
                original = getattr(sdk, method)
                def uncertain(*args, **kwargs):
                    value = original(*args, **kwargs)
                    if method != "materialize_configuration_artifact" or args[1].artifact_id == "config-1":
                        raise TimeoutError("private-provider-detail")
                    return value
                with patch.object(sdk, method, side_effect=uncertain):
                    result = interpreter.execute(request)
                self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                self.assertNotIn("configuration_installation_receipt", result.evidence)
                self.assertNotIn("configuration_invocation_completion", result.evidence)
                self.assertNotIn("private-provider-detail", repr(result))
                runtime_effect_result_fingerprint(result)

    def test_later_authority_close_error_removes_actual_installation_receipt(self):
        for fail_close in (False, True):
            with self.subTest(fail_close=fail_close):
                raw, sdk, interpreter, events = fixture()
                resolver = MappingSecretResolver(raw, {"secret://local/docker/ca": "fixture-ca",
                    "secret://local/docker/cert": "fixture-cert", "secret://local/docker/key": "fixture-key"})
                interpreter = replace(interpreter, secret_resolver=resolver)
                request = replace(selected_request(count=2), authority_ref=RuntimeAuthorityReference("remote-docker"))
                close = raw.close
                def close_client():
                    close()
                    if fail_close:
                        raise RuntimeError("private-close-detail")
                with patch.object(raw, "close", side_effect=close_client):
                    result = interpreter.execute_with_authority(request, _remote_tls_runtime_authority())
                self.assertEqual(raw.close_calls, 1)
                self.assertEqual(result.evidence["configuration_attempt"]["phase"], "installed-verification")
                if fail_close:
                    self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                    self.assertEqual(result.failure.code, "docker.runtime-authority-client-close-uncertain")
                    self.assertNotIn("configuration_installation_receipt", result.evidence)
                    self.assertNotIn("configuration_invocation_completion", result.evidence)
                    self.assertNotIn("private-close-detail", repr(result))
                    self.assertEqual(result.observations, ())
                else:
                    self.assertIs(self.receipt(request, result).disposition, Disposition.CREATED)

    def test_maximum_selection_receipt_and_whole_result_remain_bounded(self):
        raw, sdk, interpreter, events = fixture()
        request = selected_request(count=32)
        request = replace(request, configuration_instances=replace(request.configuration_instances,
            instances=tuple(replace(ref, allocation_id="a" * 124 + format(index, "04d"))
                for index, ref in enumerate(request.configuration_instances.instances))))
        result = interpreter.execute(request)
        self.assertIs(self.receipt(request, result).disposition, Disposition.CREATED)
        runtime_effect_result_fingerprint(result)
        self.assertLessEqual(len(json.dumps(result.descriptor(), separators=(",", ":")).encode()), 8192)

    def test_legacy_success_does_not_gain_configuration_installation_attestation(self):
        raw, sdk, interpreter, events = fixture()
        result = legacy_start(interpreter)
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertNotIn("configuration_installation_receipt", result.evidence)
