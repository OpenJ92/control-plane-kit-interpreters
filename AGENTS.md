# control-plane-kit-interpreters Agent Guide

Canonical contract: `cpk-agent-contract/v1`

Source: [CPK #1741](https://github.com/OpenJ92/control-plane-kit/issues/1741).
This root guide carries the shared contract needed to work in this repository
without another checkout. Local interpreter rules may tighten it; they may not
weaken authorization, Docker-only validation, truthful uncertainty, test
ownership, or GitHub-memory requirements.

## Shared Product Boundary

CPK is a human-authorized, AI-assisted infrastructure control plane. Providers
own external runtime truth. CPK owns topology, inspectable plans, execution of
approved actions, durable history, and truthful bounded reports.

- Provider reads and bounded reporting may be automatic.
- Consequential mutation requires an inspectable plan and appropriate user
  authorization.
- Destructive cleanup, public exposure, cost or capacity changes, credential
  changes, cross-provider movement, adoption, and ambiguous retries require
  explicit approval.
- Never blindly redispatch an interrupted or ambiguous external mutation.
- Never fabricate success, graph advancement, ownership, or cleanup. Preserve
  uncertainty until authoritative evidence resolves it.
- Do not assume autonomous recovery, compensation, failover, or adoption.

Interpreter code performs only explicitly authorized provider effects. It does
not infer authority from resource names, labels, private networking, or caller
reachability.

## Durable Memory And Collaboration

GitHub issues, PRs, and material comments are durable project memory. Commits,
hashes, local logs, `/tmp` packets, inventories, task messages, and chat are
supporting coordinates only. Record decisions, releases, stops, evidence
meaning, reviews, and handoffs on the governing issue or PR.

When roles are assigned, North coordinates scope, authority, topology, and
merge disposition; Vale implements; Meridian reviews independently and reports
findings-first `PASS` or `HOLD`. Assignments and handoffs name the governing
GitHub artifact, repository/base/destination, scope, suite/prerequisites,
authority limits, stop conditions, and next reviewer. Silence is not approval.

Tests prove interpreter representation and external-effect behavior. They do
not recreate Core/Operations state machines, police helper layout, or turn
fixture examples into runtime invariants. Keep review proportional and block
only concrete correctness, ownership, contract, authority/security,
durable-data, destructive-operation, or evidence defects.

## Shared Validation And Stops

All executable validation uses the established Docker-backed `./test.sh`.
Pinned mode is the normal suite; `local-core` requires the explicitly selected
Core checkout described by the script. Do not use host Python/PostgreSQL,
venvs, host `pip`, alternate databases, shims, or custom wrappers. If the suite
or prerequisite is missing, cannot start, or fails for apparatus, stop and ask;
do not improvise, silently retry, rebaseline, or repair shared state.

One-shot wrappers, leases, provider-mutating/live gates, and destructive cleanup
require explicit issue-specific authority. Provider cleanup is exact-ID and
interpreter-owned; never prune or select broadly. Stop on uncertain ownership,
authority, base/destination, prerequisites, or external-effect outcome.

## Branch Flow

This repository currently develops directly from `main`:

```text
main -> codex/<issue-id>-<slug> -> PR into main
```

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
