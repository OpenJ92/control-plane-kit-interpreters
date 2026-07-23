# control-plane-kit-interpreters

Concrete runtime interpreters for Control Plane Kit.

This package is the effectful sibling of the extracted Control Plane Kit
language and operations packages. It starts small and Docker-first. The first
runtime target is a Docker interpreter backed by the Python Docker SDK, but this
package intentionally stays below operations dispatch and cpk-server process
composition.

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

## Docker Runtime Interpreter

`control_plane_kit_interpreters.docker.DockerRuntimeInterpreter` is the first
runtime interpreter for the extracted effect boundary:

```text
RuntimeEffectRequest -> IO RuntimeEffectResult
```

It consumes core `RuntimeEffectRequest` values produced by operations and
executes only Docker requests. It does not import operations stores, cpk-server,
server products, FastAPI, or Postgres. Product material arrives as
`RuntimeProductMaterial`, already selected from registered descriptor truth by
operations.

The initial interpreter slice supports generic Docker runtime and node
lifecycle work:

```text
StartRuntime        -> create or verify owned Docker network
StopRuntime         -> logical runtime barrier; no destructive network removal
StartNode           -> pull digest image, create owned container, report observations
ReconcileNode       -> same desired-container convergence path as StartNode
StopNode            -> stop only the owned container
RemoveNodeResource  -> remove only the owned container
```

Ownership is label/fingerprint based. Existing Docker resources are inspected
before mutation; unowned or mismatched resources fail before pull/create/remove.
Private-only networking is the default. Host publication remains explicit and
continues to use the lower-level `DockerSdkPortBinding`/published-port proof
surface.

Secret-bearing products currently fail closed unless secret values have been
resolved by a future authority boundary. That is intentional: secret references
may be durable graph data, but secret values are not part of
`RuntimeEffectRequest`.

## Docker SDK Client

`control_plane_kit_interpreters.docker.DockerSdkClient` is the first concrete
backend adapter. It is intentionally only the SDK client for the Docker
realization boundary pinned by operations:

```text
inspect/create network
inspect/create volume
pull image
inspect/run/start/stop/remove container
remove network/volume
publish explicit TCP/UDP host port bindings
materialize and verify configuration artifacts
materialize and verify secret files
derive runtime-private and host-observed endpoint observations
verify requested host publication postconditions
```

The client is lazy: importing the module does not import the optional `docker`
package. Instantiating the client without an injected SDK client calls
`docker.from_env()` at the concrete effect boundary.

Configuration artifacts are consumed from core `ConfigurationArtifact` values.
The Docker SDK client writes bounded, secret-free content into owned Docker
volumes through a short-lived helper container, verifies the stored digest, and
mounts only the `content` subpath read-only into workload containers. Host paths
never enter graph data.

Secret files use a separate runtime-only path. Core may durably describe
`SecretReference` and `SecretFileDelivery`, but operations supplies authorized
`SecretValue` material at dispatch time. The Docker SDK client writes that value
through the same bounded helper-container pattern, mounts only the `content`
subpath read-only, and exposes only digests as verification evidence. Secret
bytes must not appear in descriptors, labels, logs, argv, or durable evidence.

Host publication is opt-in. `DockerSdkPortBinding` interprets graph-derived
provider ports and explicit host publication policy into Docker SDK `ports`
arguments. `DockerSdkPublishedPort` records what Docker actually published
after container start, and `verify_published_ports()` proves the requested
transport, host address, and fixed host port when one was requested.
`runtime_endpoint_observations()` maps those verified facts to core
`RuntimeEndpointObservation` values. Runtime-private, host-local, and public
contexts remain distinct; UDP publication is never inferred from TCP. Endpoint
observations are evidence for operations to persist, not graph truth.

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
