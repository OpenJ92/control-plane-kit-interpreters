from __future__ import annotations

import subprocess
import sys
import unittest

import control_plane_kit_interpreters
from control_plane_kit_interpreters import INTERPRETER_SPINE
from control_plane_kit_interpreters.boundaries import INTERPRETERS_BOUNDARY


class InterpretersScaffoldTests(unittest.TestCase):
    def test_package_root_exports_only_lightweight_boundary_values(self) -> None:
        self.assertEqual(
            control_plane_kit_interpreters.__all__,
            [
                "INTERPRETER_SPINE",
                "InterpreterBoundary",
            ],
        )
        self.assertEqual(
            INTERPRETER_SPINE,
            (
                "cpk-server",
                "configured operations application",
                "ExecutionCoordinator",
                "RuntimeInterpreterDispatcher",
                "DockerRuntimeInterpreter",
                "Python Docker SDK",
            ),
        )

    def test_boundary_marker_denies_dispatch_and_server_process_ownership(self) -> None:
        self.assertEqual(
            INTERPRETERS_BOUNDARY.package,
            "control-plane-kit-interpreters",
        )
        self.assertTrue(INTERPRETERS_BOUNDARY.owns_concrete_effects)
        self.assertFalse(INTERPRETERS_BOUNDARY.owns_durable_dispatch)
        self.assertFalse(INTERPRETERS_BOUNDARY.owns_server_process)

    def test_base_import_does_not_eagerly_import_optional_runtime_packages(self) -> None:
        script = """
import sys
import control_plane_kit_interpreters

for name in (
    "docker",
    "fastapi",
    "psycopg",
    "control_plane_kit_operations",
    "control_plane_kit_servers_cpk_server",
):
    assert name not in sys.modules, name
"""

        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
