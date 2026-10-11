"""Bounded test-only reporting, never provider-success fabrication."""
from contextlib import redirect_stdout
from io import StringIO
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane_kit_core.runtime_effects import EffectResultKind
from control_plane_kit_core.configuration_installation import configuration_installation_receipt_for_result
from control_plane_kit_core.configuration_invocation import configuration_invocation_correlation_for_request
from configuration_replacement_fixtures import fixture, selected_request
from live_docker_installation import (
    _cleanup_diagnostic, _hardened_workload_kwargs, _runtime_diagnostic, _write_diagnostic,
)


class InstallationWitnessDiagnosticTests(unittest.TestCase):
    def test_reserved_fixture_label_is_refused_and_faithful_hardening_preserves_receipt(self):
        for inject_reserved_label in (True, False):
            with self.subTest(inject_reserved_label=inject_reserved_label):
                raw, sdk, interpreter, events = fixture()
                request = selected_request(count=2)
                original = sdk._container_create_kwargs
                def hardened(**arguments):
                    value = _hardened_workload_kwargs(original, arguments)
                    if inject_reserved_label:
                        value["labels"] = {**value["labels"], "org.openj92.cpk.test-run": "fixture-run"}
                    return value
                with patch.object(sdk, "_container_create_kwargs", side_effect=hardened):
                    result = interpreter.execute(request)
                receipt = configuration_installation_receipt_for_result(
                    configuration_invocation_correlation_for_request(request), result)
                if inject_reserved_label:
                    self.assertIs(result.kind, EffectResultKind.FAILED)
                    self.assertEqual(result.failure.code, "docker.container-ownership-conflict")
                    self.assertIsNone(receipt)
                else:
                    self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
                    self.assertIsNotNone(receipt)

    def test_real_recording_runtime_result_reports_step_and_bounded_failure(self):
        for fails in (False, True):
            with self.subTest(fails=fails):
                raw, sdk, interpreter, events = fixture()
                request = selected_request(count=2)
                if fails:
                    with patch.object(sdk, "start_container", side_effect=TimeoutError("private-response")):
                        result = interpreter.execute(request)
                else:
                    result = interpreter.execute(request)
                report = _runtime_diagnostic("created", result, dict(network=1, volume=2, reader=1, helper=6))
                self.assertEqual(report["step"], "created")
                self.assertEqual(report["staged_indices"], [0, 1])
                self.assertEqual(report["kind"], result.kind.value)
                self.assertEqual(report["receipt_present"], not fails)
                self.assertEqual(report["phase"], "container-start" if fails else "installed-verification")
                self.assertEqual(report["failure_code"], "docker.configuration-effect-uncertain" if fails else "unavailable")
                self.assertNotIn("private-response", json.dumps(report))

    def test_unknown_identifiers_payloads_and_invalid_counters_are_not_exposed(self):
        for code in ("docker.private-token", "secret-value", "é" * 1000, {"token": "private-value"}):
            with self.subTest(code_type=type(code).__name__):
                result = SimpleNamespace(kind="private-kind", failure=SimpleNamespace(code=code), evidence={
                    "configuration_attempt": {"phase": "private-phase", "attempted_indices": [True],
                        "staged_indices": list(range(33)), "old_removed": "private-value",
                        "unknown_created_resource": {"token": "private-value"}},
                    "configuration_installation_receipt": {"token": "private-value"},
                    "arbitrary": "private-value"})
                report = _runtime_diagnostic("private-step", result,
                    dict(network=True, volume=-1, reader="private-value", helper=15))
                self.assertEqual(report["failure_code"], "unavailable")
                self.assertEqual(report["kind"], "unavailable")
                self.assertEqual(report["phase"], "unavailable")
                self.assertEqual(report["attempted_indices"], "unavailable")
                self.assertEqual(report["staged_indices"], "unavailable")
                self.assertEqual(report["attempted_calls"], dict(network="unavailable", volume="unavailable",
                    reader="unavailable", helper="limit-exceeded"))
                self.assertNotIn("private", json.dumps(report))
                self.assertLess(len(json.dumps(report)), 1024)

    def test_cleanup_scope_keeps_acknowledgements_and_unknown_creates_distinct(self):
        resources = SimpleNamespace(entries=[("network", "private-id", None, None)],
            uncertain=[{"private-attempt": "private-coordinate"}])
        report = _cleanup_diagnostic("HOLD", resources)
        self.assertEqual(report["scope"], "existing-acknowledged-resource-predicate")
        self.assertEqual(report["recorded_candidates"], dict(network=1, volume=0, reader=0, helper=0))
        self.assertEqual(report["unresolved_creates"], 1)
        self.assertNotIn("private", json.dumps(report))

    def test_formatting_and_output_failure_do_not_escape_reporting(self):
        def unavailable():
            raise ValueError("private-formatting-detail")
        self.assertIs(_write_diagnostic(unavailable), False)
        with patch("builtins.print", side_effect=OSError("private-output-detail")):
            self.assertIs(_write_diagnostic(lambda: {"safe": True}), False)
        with redirect_stdout(StringIO()) as output:
            self.assertIs(_write_diagnostic(lambda: {"safe": True}), True)
        self.assertEqual(json.loads(output.getvalue()), {"safe": True})
