from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from package_integrity import inspect_package


VALID_TEST = """\
import unittest

class ExampleTests(unittest.TestCase):
    def test_value(self):
        self.assertEqual(1 + 1, 2)
"""


class PackageIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        (self.root / "src").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "test.sh").write_text("python -m unittest\n", encoding="utf-8")
        self.approvals = self.root / "tests" / "approved_skips.json"
        self.approvals.write_text("[]\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def inspect(self):
        return inspect_package(
            self.root,
            source_roots=(self.root / "src",),
            test_roots=(self.root / "tests",),
            gate_files=(self.root / "test.sh",),
            approved_skips_path=self.approvals,
        )

    def write_test(self, document: str, name: str = "test_example.py") -> None:
        (self.root / "tests" / name).write_text(document, encoding="utf-8")

    def assert_code(self, code: str) -> None:
        self.assertIn(code, {finding.code for finding in self.inspect().findings})

    def test_valid_unittest_package_is_accepted(self) -> None:
        self.write_test(VALID_TEST)
        self.assertTrue(self.inspect().valid)

    def test_hidden_collection_is_rejected(self) -> None:
        self.write_test(VALID_TEST, name="hidden.py")
        self.assert_code("hidden-test-file")

    def test_pytest_style_free_function_is_rejected_as_hidden(self) -> None:
        self.write_test("def test_hidden():\n    assert True\n")
        self.assert_code("hidden-test-function")

    def test_nested_test_case_is_rejected_as_hidden(self) -> None:
        self.write_test(
            "import unittest\n"
            "def factory():\n"
            "    class NestedTests(unittest.TestCase):\n"
            "        def test_hidden(self):\n"
            "            self.assertTrue(True)\n"
            "    return NestedTests\n"
        )
        self.assert_code("hidden-test-class")

    def test_aliased_test_case_in_hidden_file_is_rejected(self) -> None:
        self.write_test(
            VALID_TEST.replace(
                "import unittest", "from unittest import TestCase as Base"
            ).replace("unittest.TestCase", "Base"),
            name="hidden.py",
        )
        self.assert_code("hidden-test-file")

    def test_unconditional_skip_is_rejected(self) -> None:
        self.write_test(
            VALID_TEST.replace(
                "    def test_value", '    @unittest.skip("later")\n    def test_value'
            )
        )
        self.assert_code("unconditional-skip")

    def test_aliased_unconditional_skip_is_rejected(self) -> None:
        self.write_test(
            VALID_TEST.replace(
                "import unittest",
                "import unittest\nfrom unittest import skip as disabled",
            ).replace(
                "    def test_value", '    @disabled("later")\n    def test_value'
            )
        )
        self.assert_code("unconditional-skip")

    def test_unapproved_conditional_skip_is_rejected(self) -> None:
        self.write_test(
            VALID_TEST.replace(
                "    def test_value",
                '    @unittest.skipIf(condition(), "bounded reason")\n    def test_value',
            )
        )
        self.assert_code("unapproved-skip")

    def test_literal_skip_condition_is_rejected(self) -> None:
        self.write_test(
            VALID_TEST.replace(
                "    def test_value",
                '    @unittest.skipIf(False, "never active")\n    def test_value',
            )
        )
        self.assert_code("literal-skip-condition")

    def test_approved_dynamic_conditional_skip_is_accepted(self) -> None:
        identity = "tests/test_example.py::ExampleTests.test_value"
        self.approvals.write_text(
            json.dumps([{"identity": identity, "reason": "platform capability absent"}]),
            encoding="utf-8",
        )
        self.write_test(
            VALID_TEST.replace(
                "    def test_value",
                "    @unittest.skipIf(condition(), "
                "\"platform capability absent\")\n    def test_value",
            )
        )
        report = self.inspect()
        self.assertTrue(report.valid)
        self.assertEqual(report.approved_skip_identities, (identity,))

    def test_duplicate_skip_approval_is_rejected(self) -> None:
        entries = [
            {"identity": "tests/test_example.py::ExampleTests.test_value", "reason": "bounded"},
            {"identity": "tests/test_example.py::ExampleTests.test_value", "reason": "bounded"},
        ]
        self.approvals.write_text(json.dumps(entries), encoding="utf-8")
        self.write_test(VALID_TEST)
        self.assert_code("duplicate-skip-approval")

    def test_blank_skip_reason_is_rejected(self) -> None:
        self.approvals.write_text(
            json.dumps([{"identity": "example", "reason": ""}]),
            encoding="utf-8",
        )
        self.write_test(VALID_TEST)
        self.assert_code("invalid-skip-approval")

    def test_stale_skip_approval_is_rejected(self) -> None:
        self.approvals.write_text(
            json.dumps([{"identity": "missing", "reason": "bounded reason"}]),
            encoding="utf-8",
        )
        self.write_test(VALID_TEST)
        self.assert_code("stale-skip-approval")

    def test_pass_only_test_is_rejected(self) -> None:
        self.write_test(VALID_TEST.replace("self.assertEqual(1 + 1, 2)", "pass"))
        self.assert_code("placeholder-test")

    def test_ellipsis_only_test_is_rejected(self) -> None:
        self.write_test(VALID_TEST.replace("self.assertEqual(1 + 1, 2)", "..."))
        self.assert_code("placeholder-test")

    def test_swallowed_exception_is_rejected(self) -> None:
        self.write_test(
            VALID_TEST.replace(
                "self.assertEqual(1 + 1, 2)",
                "try:\n            raise ValueError('failure')\n        except ValueError:\n            pass",
            )
        )
        self.assert_code("swallowed-exception")

    def test_mutable_legacy_import_is_rejected(self) -> None:
        (self.root / "src" / "module.py").write_text(
            "import control_plane_kit\n", encoding="utf-8"
        )
        self.write_test(VALID_TEST)
        self.assert_code("mutable-legacy-import")

    def test_pytest_import_is_rejected(self) -> None:
        self.write_test("import pytest\n" + VALID_TEST)
        self.assert_code("pytest-import")

    def test_proof_changing_gate_option_is_rejected(self) -> None:
        self.root.joinpath("test.sh").write_text(
            'if [ "${CPK_SKIP_TESTS:-0}" = 1 ]; then exit 0; fi\n',
            encoding="utf-8",
        )
        self.write_test(VALID_TEST)
        self.assert_code("proof-changing-option")

    def test_empty_helper_class_and_empty_context_body_are_allowed(self) -> None:
        self.write_test(
            VALID_TEST
            + "\nclass MarkerError(Exception):\n    pass\n"
            + "\nwith open(__file__, encoding='utf-8'):\n    pass\n"
        )
        self.assertTrue(self.inspect().valid)

    def test_mocks_are_reported_without_becoming_findings(self) -> None:
        self.write_test("from unittest.mock import patch\n" + VALID_TEST)
        report = self.inspect()
        self.assertTrue(report.valid)
        self.assertEqual(report.mock_locations, ("tests/test_example.py:1",))


if __name__ == "__main__":
    unittest.main()
