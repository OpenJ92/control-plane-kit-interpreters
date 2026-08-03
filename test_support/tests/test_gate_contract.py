from __future__ import annotations

import os
from pathlib import Path
import unittest


class PackageGateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(
            os.environ.get("CPK_PACKAGE_ROOT", Path(__file__).resolve().parents[2])
        )
        cls.gate = cls.root / "test.sh"
        cls.source = cls.gate.read_text(encoding="utf-8")

    def test_gate_is_executable_and_anchors_itself_to_repository_root(self) -> None:
        self.assertTrue(os.access(self.gate, os.X_OK))
        self.assertIn('ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"', self.source)
        self.assertIn('cd "$ROOT"', self.source)

    def test_pinned_dependencies_are_the_default_proof(self) -> None:
        self.assertIn('DEPENDENCY_MODE="${CPK_INTERPRETERS_DEPENDENCY_MODE:-pinned}"', self.source)
        self.assertIn('CORE_REPO="${CPK_CORE_REPO:-}"', self.source)
        self.assertNotIn('CORE_REPO="${CPK_CORE_REPO:-../control-plane-kit}"', self.source)

    def test_local_core_override_requires_explicit_mode_and_repository(self) -> None:
        self.assertIn('local-core)', self.source)
        self.assertIn(
            'local-core mode requires CPK_CORE_REPO containing control-plane-kit-core',
            self.source,
        )
        self.assertIn(
            'CPK_CORE_REPO requires CPK_INTERPRETERS_DEPENDENCY_MODE=local-core',
            self.source,
        )

    def test_gate_runs_integrity_tests_scan_and_clean_import(self) -> None:
        self.assertIn('python -m unittest discover -s tests -v', self.source)
        self.assertIn('python /test-support/package_integrity.py', self.source)
        self.assertIn('control_plane_kit_interpreters', self.source)
        self.assertIn('unexpected eager import', self.source)


if __name__ == "__main__":
    unittest.main()
