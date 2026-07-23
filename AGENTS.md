# control-plane-kit-interpreters Agent Guide

This repository owns concrete runtime interpreter implementations for
Control Plane Kit. It is not the owner of graph truth, Postgres stores,
UnitOfWork, cpk-server routes, product descriptors, or OCI publication.

## Interpreter Spine

Every issue in this repository must preserve this ownership shape:

```text
cpk-server
  -> configured operations application
    -> ExecutionCoordinator
      -> RuntimeInterpreterDispatcher
        -> DockerRuntimeInterpreter
          -> Python Docker SDK
```

Meaning:

- `cpk-server` does not own Docker behavior.
- `cpk-server` receives configured runtime authority.
- operations owns durable dispatch because it owns ActivityRealizationContext,
  UnitOfWork, run lifecycle, observations, and current graph advancement.
- interpreters own concrete runtime effects.
- core stays pure and never imports Docker SDK or concrete effect code.

## Ownership

This repository may own:

- Docker SDK clients and effect interpreters;
- probe and verification clients;
- configuration-artifact materialization;
- secret materialization;
- host publication realization;
- endpoint observation extraction;
- Docker ownership, cleanup, residue, and retained-data helpers.

This repository must not own:

- Postgres stores;
- UnitOfWork implementations;
- durable journals;
- ActivityRealizationContext;
- ActivityExecutionAdapter if operations still owns the protocol;
- ActivityExecutionOutcome if operations still owns the outcome;
- observation persistence;
- product registration;
- graph truth;
- approval, admission, lifecycle, or advancement services;
- cpk-server FastAPI/MCP routes;
- product descriptors, Dockerfiles, OCI images, or catalogue publication.

## Development

Use Docker-first validation:

```bash
./test.sh
```

Use `unittest` only. Do not add pytest.

Keep package roots lightweight. Importing `control_plane_kit_interpreters` must
not import Docker SDK, FastAPI, psycopg, cpk-server, or concrete runtime
authority.

## External Effects

Future interpreter implementations must preserve the external-effect law:

```text
short transaction: record durable intent
  -> commit
    -> bounded Docker / filesystem / network / health effect
      -> short transaction: record result, event, observation
```

Never require a Postgres transaction or lock to remain open across Docker SDK
calls, filesystem writes, probes, image pulls, container startup, volume
operations, network operations, or cleanup.
