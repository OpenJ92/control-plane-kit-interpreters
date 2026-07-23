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

## Docker SDK Client

`control_plane_kit_interpreters.docker.DockerSdkClient` is the first concrete
backend adapter. It is intentionally only the SDK client for the Docker
realization boundary pinned by operations:

```text
inspect/create network
inspect/create volume
pull image
inspect/run/start/stop/remove container
remove network
```

The client is lazy: importing the module does not import the optional `docker`
package. Instantiating the client without an injected SDK client calls
`docker.from_env()` at the concrete effect boundary.

## Probe And Verification Adapters

`control_plane_kit_interpreters.probes` owns concrete address authorization,
TCP/UDP reachability, and HTTP application-health probes. The probe intent and
observation values remain in `control-plane-kit-core`.

`control_plane_kit_interpreters.verification` owns concrete semantic check
interpreters for HTTP, Redis, and Postgres. Postgres readiness is represented as
a semantic `select_one` transport result, not as raw TCP reachability. The
Postgres transport is injected so later secret materialization can provide
connection authority without placing credentials in descriptors, logs, or
generic endpoint material.

Run validation with:

```bash
./test.sh
```

Use `unittest` only.
