from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Iterable, Sequence


INTEGRITY_CONTRACT_VERSION = "1"
MUTABLE_LEGACY_IMPORT = "control_plane_kit"
PROOF_CHANGING_NAME = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:SKIP|OPTIONAL|NO_BUILD|LOCAL_REBUILD|NO_TEST)[A-Z0-9_]*\b"
)
TEST_FILE_PATTERN = re.compile(r"^test.*\.py$")


@dataclass(frozen=True)
class ApprovedSkip:
    identity: str
    reason: str


@dataclass(frozen=True, order=True)
class IntegrityFinding:
    path: str
    line: int
    code: str
    message: str


@dataclass(frozen=True)
class IntegrityReport:
    findings: tuple[IntegrityFinding, ...]
    test_identities: tuple[str, ...]
    mock_locations: tuple[str, ...]
    approved_skip_identities: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.findings


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _dotted_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return None


def _is_test_case(node: ast.ClassDef, aliases: set[str]) -> bool:
    return any(
        (_dotted_name(base) or "").endswith("TestCase")
        or (_dotted_name(base) or "") in aliases
        for base in node.bases
    )


def _is_placeholder_body(body: Sequence[ast.stmt]) -> bool:
    statements = list(body)
    if statements and isinstance(statements[0], ast.Expr):
        value = statements[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            statements = statements[1:]
    return len(statements) == 1 and (
        isinstance(statements[0], ast.Pass)
        or (
            isinstance(statements[0], ast.Expr)
            and isinstance(statements[0].value, ast.Constant)
            and statements[0].value.value is Ellipsis
        )
    )


def _is_swallowed_handler(node: ast.ExceptHandler) -> bool:
    return len(node.body) == 1 and isinstance(node.body[0], ast.Pass)


def _literal(node: ast.AST) -> object:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return object()


def _skip_decorator(
    decorator: ast.expr,
    aliases: dict[str, str],
) -> tuple[str, ast.AST | None, str | None] | None:
    if isinstance(decorator, ast.Call):
        name = (_dotted_name(decorator.func) or "").rsplit(".", 1)[-1]
        name = aliases.get(name, name)
        if name == "skip" and decorator.args:
            reason = _literal(decorator.args[0])
            return name, None, reason if isinstance(reason, str) else None
        if name in {"skipIf", "skipUnless"} and len(decorator.args) >= 2:
            reason = _literal(decorator.args[1])
            return (
                name,
                decorator.args[0],
                reason if isinstance(reason, str) else None,
            )
    return None


def _read_approved_skips(path: Path | None) -> tuple[list[ApprovedSkip], list[IntegrityFinding]]:
    if path is None or not path.exists():
        return [], []
    relative = path.name
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [], [
            IntegrityFinding(relative, 1, "invalid-skip-approval", str(error))
        ]
    if not isinstance(document, list):
        return [], [
            IntegrityFinding(
                relative,
                1,
                "invalid-skip-approval",
                "approved skip document must be a JSON list",
            )
        ]

    approvals: list[ApprovedSkip] = []
    findings: list[IntegrityFinding] = []
    seen: set[str] = set()
    for index, item in enumerate(document, start=1):
        if not isinstance(item, dict):
            findings.append(
                IntegrityFinding(
                    relative,
                    index,
                    "invalid-skip-approval",
                    "approved skip entry must be an object",
                )
            )
            continue
        identity = item.get("identity")
        reason = item.get("reason")
        if not isinstance(identity, str) or not identity.strip():
            findings.append(
                IntegrityFinding(
                    relative,
                    index,
                    "invalid-skip-approval",
                    "approved skip identity must be non-blank",
                )
            )
            continue
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 240:
            findings.append(
                IntegrityFinding(
                    relative,
                    index,
                    "invalid-skip-approval",
                    "approved skip reason must contain 1-240 characters",
                )
            )
            continue
        if identity in seen:
            findings.append(
                IntegrityFinding(
                    relative,
                    index,
                    "duplicate-skip-approval",
                    identity,
                )
            )
            continue
        seen.add(identity)
        approvals.append(ApprovedSkip(identity=identity, reason=reason))
    return approvals, findings


def _python_files(roots: Iterable[Path]) -> list[Path]:
    return sorted(
        {
            path
            for root in roots
            if root.exists()
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts
        }
    )


def inspect_package(
    package_root: Path,
    *,
    source_roots: Sequence[Path],
    test_roots: Sequence[Path],
    gate_files: Sequence[Path],
    approved_skips_path: Path | None = None,
) -> IntegrityReport:
    package_root = package_root.resolve()
    approvals, findings = _read_approved_skips(approved_skips_path)
    approvals_by_identity = {approval.identity: approval for approval in approvals}
    encountered_approvals: set[str] = set()
    test_identities: list[str] = []
    mock_locations: set[str] = set()

    all_python = _python_files((*source_roots, *test_roots))
    resolved_test_roots = tuple(root.resolve() for root in test_roots)
    for path in all_python:
        relative = str(path.resolve().relative_to(package_root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError) as error:
            line = getattr(error, "lineno", None) or 1
            findings.append(
                IntegrityFinding(relative, line, "unparseable-python", str(error))
            )
            continue

        in_test_root = any(path.resolve().is_relative_to(root) for root in resolved_test_roots)
        discoverable_file = bool(TEST_FILE_PATTERN.match(path.name))
        test_case_aliases = {"TestCase"}
        skip_aliases: dict[str, str] = {}
        for statement in tree.body:
            if not isinstance(statement, ast.ImportFrom):
                continue
            if statement.module not in {"unittest", "unittest.case"}:
                continue
            for alias in statement.names:
                local_name = alias.asname or alias.name
                if alias.name == "TestCase":
                    test_case_aliases.add(local_name)
                if alias.name in {"skip", "skipIf", "skipUnless"}:
                    skip_aliases[local_name] = alias.name

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                roots = {node.module.split(".", 1)[0]} if node.module else set()
            else:
                roots = set()
            if MUTABLE_LEGACY_IMPORT in roots:
                findings.append(
                    IntegrityFinding(
                        relative,
                        node.lineno,
                        "mutable-legacy-import",
                        "imports mutable control_plane_kit package",
                    )
                )
            if "pytest" in roots:
                findings.append(
                    IntegrityFinding(
                        relative,
                        node.lineno,
                        "pytest-import",
                        "unittest is the only permitted test framework",
                    )
                )
            if in_test_root and isinstance(node, ast.ImportFrom) and node.module == "unittest.mock":
                mock_locations.add(f"{relative}:{node.lineno}")
            if in_test_root and isinstance(node, ast.Call):
                call_name = (_dotted_name(node.func) or "").rsplit(".", 1)[-1]
                if call_name in {"Mock", "MagicMock", "patch"}:
                    mock_locations.add(f"{relative}:{node.lineno}")
            if in_test_root and isinstance(node, ast.ExceptHandler) and _is_swallowed_handler(node):
                findings.append(
                    IntegrityFinding(
                        relative,
                        node.lineno,
                        "swallowed-exception",
                        "test code swallows an exception with pass",
                    )
                )

        top_level_classes = {
            id(node) for node in tree.body if isinstance(node, ast.ClassDef)
        }
        for nested_class in (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
            and _is_test_case(node, test_case_aliases)
            and id(node) not in top_level_classes
        ):
            findings.append(
                IntegrityFinding(
                    relative,
                    nested_class.lineno,
                    "hidden-test-class",
                    f"nested TestCase {nested_class.name} is not collected by unittest",
                )
            )

        for class_node in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            if not _is_test_case(class_node, test_case_aliases):
                continue
            if in_test_root and not discoverable_file:
                findings.append(
                    IntegrityFinding(
                        relative,
                        class_node.lineno,
                        "hidden-test-file",
                        f"TestCase {class_node.name} is outside unittest discovery pattern",
                    )
                )
            candidates: list[tuple[str, ast.AST, Sequence[ast.expr]]] = [
                (
                    f"{relative}::{class_node.name}",
                    class_node,
                    class_node.decorator_list,
                )
            ]
            for method in class_node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test"):
                    identity = f"{relative}::{class_node.name}.{method.name}"
                    test_identities.append(identity)
                    if _is_placeholder_body(method.body):
                        findings.append(
                            IntegrityFinding(
                                relative,
                                method.lineno,
                                "placeholder-test",
                                identity,
                            )
                        )
                    candidates.append((identity, method, method.decorator_list))

            for identity, owner, decorators in candidates:
                for decorator in decorators:
                    skip = _skip_decorator(decorator, skip_aliases)
                    if skip is None:
                        continue
                    kind, condition, reason = skip
                    if kind == "skip":
                        findings.append(
                            IntegrityFinding(
                                relative,
                                owner.lineno,
                                "unconditional-skip",
                                identity,
                            )
                        )
                        continue
                    if condition is not None and isinstance(_literal(condition), bool):
                        findings.append(
                            IntegrityFinding(
                                relative,
                                owner.lineno,
                                "literal-skip-condition",
                                identity,
                            )
                        )
                        continue
                    approval = approvals_by_identity.get(identity)
                    if approval is None:
                        findings.append(
                            IntegrityFinding(
                                relative,
                                owner.lineno,
                                "unapproved-skip",
                                identity,
                            )
                        )
                        continue
                    if reason != approval.reason:
                        findings.append(
                            IntegrityFinding(
                                relative,
                                owner.lineno,
                                "skip-reason-mismatch",
                                identity,
                            )
                        )
                        continue
                    encountered_approvals.add(identity)

        if in_test_root:
            for function in (
                node
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test")
            ):
                findings.append(
                    IntegrityFinding(
                        relative,
                        function.lineno,
                        "hidden-test-function",
                        f"top-level test function {function.name} is not collected by unittest",
                    )
                )

    for approval in approvals:
        if approval.identity not in encountered_approvals:
            findings.append(
                IntegrityFinding(
                    approved_skips_path.name if approved_skips_path else "approved-skips",
                    1,
                    "stale-skip-approval",
                    approval.identity,
                )
            )

    for gate_file in gate_files:
        if not gate_file.exists():
            findings.append(
                IntegrityFinding(
                    str(gate_file), 1, "missing-gate-file", "gate file does not exist"
                )
            )
            continue
        for line_number, line in enumerate(
            gate_file.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for match in PROOF_CHANGING_NAME.finditer(line):
                findings.append(
                    IntegrityFinding(
                        str(gate_file.resolve().relative_to(package_root)),
                        line_number,
                        "proof-changing-option",
                        match.group(0),
                    )
                )

    return IntegrityReport(
        findings=tuple(sorted(set(findings))),
        test_identities=tuple(sorted(set(test_identities))),
        mock_locations=tuple(sorted(mock_locations)),
        approved_skip_identities=tuple(sorted(encountered_approvals)),
    )


def _paths(package_root: Path, values: Sequence[str]) -> tuple[Path, ...]:
    return tuple(package_root / value for value in values)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check package test integrity")
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--source-root", action="append", default=[])
    parser.add_argument("--test-root", action="append", default=[])
    parser.add_argument("--gate-file", action="append", default=[])
    parser.add_argument("--approved-skips", default="tests/approved_skips.json")
    args = parser.parse_args(argv)

    package_root = args.package_root.resolve()
    report = inspect_package(
        package_root,
        source_roots=_paths(package_root, args.source_root or ["src"]),
        test_roots=_paths(package_root, args.test_root or ["tests"]),
        gate_files=_paths(package_root, args.gate_file or ["test.sh"]),
        approved_skips_path=package_root / args.approved_skips,
    )
    print(
        f"package-integrity contract={INTEGRITY_CONTRACT_VERSION} "
        f"tests={len(report.test_identities)} mocks={len(report.mock_locations)} "
        f"approved_skips={len(report.approved_skip_identities)}"
    )
    for location in report.mock_locations:
        print(f"mock-evidence {location}")
    for finding in report.findings:
        print(
            f"{finding.path}:{finding.line}: {finding.code}: {finding.message}"
        )
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
