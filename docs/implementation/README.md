# Interpreters implementation companions

Follow the shared [CPK #1799 convention](https://github.com/OpenJ92/control-plane-kit/issues/1799). A source path `tests/example.py` maps to `docs/implementation/tests/example.py.md`; retain the source suffix. Each note begins with its source path/link and same-change maintenance reminder. Read it with the actual source and selected imported contracts, not instead of them.

[inventory.json](inventory.json) records the complete initial tracked-source scope, including explicit exclusions and remaining work. Pending/authored/reviewed describe documentation coverage, not certified runtime behavior or perpetual freshness. The governing slice is [Interpreters #143](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/143); its PR records source coordinates and review depth.

Begin with [gate completion](test.sh.md), [the SDK owner](src/control_plane_kit_interpreters/docker/sdk.py.md), [synthetic fixture inputs](tests/live_docker_start_node_contract.py.md), and [the creation evidence relation](../architecture/docker-creation-evidence.md). Source-specific test notes identify law ownership and what their passing result does not establish.

Keep updates in the existing PR flow: inspect the actual source/dependency diff, pair relevant creates/moves/removals, and update affected meaning. If meaning is unchanged, record companion review/no semantic update needed in the normal decision log. Dependency changes require actual consumer search at their selected version; known links are not exhaustive. Do not add another report, hash ledger or documentation test programme. A missing initial note is recorded work; bring newly touched relevant files current without blocking unrelated work on the whole inventory.
