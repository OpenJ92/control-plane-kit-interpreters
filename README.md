# control-plane-kit-interpreters

Concrete runtime interpreters for Control Plane Kit.

This package is the effectful sibling of the extracted Control Plane Kit
language and operations packages. It starts small and Docker-first. The first
runtime target is a Docker interpreter backed by the Python Docker SDK, but this
scaffold intentionally does not implement Docker behavior yet.

The governing spine is:

```text
cpk-server
  -> configured operations application
    -> ExecutionCoordinator
      -> RuntimeInterpreterDispatcher
        -> DockerRuntimeInterpreter
          -> Python Docker SDK
```

The boundaries are deliberately sharp:

- core owns pure graph, product, socket, planning, and operation contract values;
- operations owns durable dispatch, UnitOfWork, stores, lifecycle, observations,
  and current graph advancement;
- interpreters own concrete effects;
- cpk-server owns FastAPI/MCP process composition and receives configured
  runtime authority.

Importing the package root is lightweight:

```python
import control_plane_kit_interpreters
```

It must not import Docker SDK, cpk-server, FastAPI, psycopg, stores, or any
runtime authority.

Run validation with:

```bash
./test.sh
```

Use `unittest` only.
