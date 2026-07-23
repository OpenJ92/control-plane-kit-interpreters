from __future__ import annotations

from dataclasses import dataclass


INTERPRETER_SPINE: tuple[str, ...] = (
    "cpk-server",
    "configured operations application",
    "ExecutionCoordinator",
    "RuntimeInterpreterDispatcher",
    "DockerRuntimeInterpreter",
    "Python Docker SDK",
)


@dataclass(frozen=True)
class InterpreterBoundary:
    """Repository ownership marker for concrete runtime effect packages."""

    package: str
    owns_concrete_effects: bool
    owns_durable_dispatch: bool
    owns_server_process: bool


INTERPRETERS_BOUNDARY = InterpreterBoundary(
    package="control-plane-kit-interpreters",
    owns_concrete_effects=True,
    owns_durable_dispatch=False,
    owns_server_process=False,
)
