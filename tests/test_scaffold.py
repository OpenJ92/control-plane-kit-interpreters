from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys
import tomllib
import unittest

import control_plane_kit_interpreters
from control_plane_kit_interpreters import INTERPRETER_SPINE
from control_plane_kit_interpreters.boundaries import INTERPRETERS_BOUNDARY


REPO_ROOT = Path(__file__).parents[1]
CORE_REQUIREMENT = (
    "control-plane-kit-core @ "
    "https://github.com/OpenJ92/control-plane-kit/archive/"
    "e09c93ae40568f362b4b98e9faeecc180fc63009.zip"
    "#subdirectory=control-plane-kit-core"
)


def _normalized_requirement_name(requirement: str) -> str:
    name = re.split(r"\s*@\s*|[<>=!~]", requirement, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", name.split("[", maxsplit=1)[0]).lower()


class InterpretersScaffoldTests(unittest.TestCase):
    def test_package_uses_exact_accepted_core_coordinate_once(self) -> None:
        package = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        requirements = list(package["dependencies"])
        for optional_requirements in package["optional-dependencies"].values():
            requirements.extend(optional_requirements)

        core_requirements = [
            requirement
            for requirement in requirements
            if _normalized_requirement_name(requirement) == "control-plane-kit-core"
        ]
        self.assertEqual(core_requirements, [CORE_REQUIREMENT])

        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        test_gate = (REPO_ROOT / "test.sh").read_text(encoding="utf-8")
        self.assertIn('python -m pip install ".[test]"', dockerfile)
        self.assertNotIn("control-plane-kit/archive/", dockerfile)
        self.assertNotIn("control-plane-kit/archive/", test_gate)

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
