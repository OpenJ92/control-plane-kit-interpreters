from __future__ import annotations

import ast
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).parents[1]
SRC_ROOT = REPO_ROOT / "src" / "control_plane_kit_interpreters"


def imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".", maxsplit=1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", maxsplit=1)[0])
    return roots


class PackageBoundaryTests(unittest.TestCase):
    def test_source_does_not_import_server_process_or_operations_packages(self) -> None:
        forbidden = {
            "control_plane_kit_operations",
            "control_plane_kit_servers",
            "control_plane_kit_servers_cpk_server",
            "fastapi",
            "psycopg",
        }

        findings: list[str] = []
        for path in sorted(SRC_ROOT.rglob("*.py")):
            overlap = imported_roots(path) & forbidden
            for name in sorted(overlap):
                findings.append(f"{path.relative_to(REPO_ROOT)} imports {name}")

        self.assertEqual(findings, [])

    def test_package_root_does_not_import_docker_sdk(self) -> None:
        root_imports = imported_roots(SRC_ROOT / "__init__.py")

        self.assertNotIn("docker", root_imports)

    def test_product_specific_branches_are_absent_from_interpreters(self) -> None:
        product_names = {
            "hello",
            "multiplexer",
            "postgres_server",
            "http_active_router",
            "http_multiplexer",
            "coredns",
            "webhook",
            "cpk_server",
        }

        findings: list[str] = []
        for path in sorted(SRC_ROOT.rglob("*.py")):
            text = path.read_text(encoding="utf-8").lower()
            for product_name in sorted(product_names):
                if product_name in text:
                    findings.append(
                        f"{path.relative_to(REPO_ROOT)} mentions {product_name}"
                    )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
