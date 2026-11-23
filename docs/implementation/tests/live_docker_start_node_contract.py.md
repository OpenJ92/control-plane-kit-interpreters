Source: [tests/live_docker_start_node_contract.py](../../../tests/live_docker_start_node_contract.py).
Maintain this companion in the same change when the source or its selected imports change the contract.

The [numeric-reader controller](../../../tests/live_docker_secret.py) calls `run_provider_contract`
only for the separately enabled StartNode witness. Before preparing its synthetic topology,
the function checks Docker 7.2.0 and hashes the installed Interpreters SDK adapter and runtime
modules. Both expected digests belong to the historical source. Both files on the main revision
used for this companion differ, so installing those bytes would stop the witness at source
admission. The [#141 receipt](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/141#issuecomment-5629083712)
records one passing attempt at `aa95de25`.

After admission, `prepare_fixture` uses the selected Core product and runtime-effect contracts
to construct synthetic StartRuntime and StartNode requests. It binds versioned secret selections
and grants to the node request. The witness observes the recipient's API create and the inspect
correlated with the returned ID, then checks the running recipient’s image, network, mounts,
numeric-user file access and local readiness. Its journal tracks the exact resources eligible
for cleanup. Missing journal evidence or incomplete cleanup leaves the fixture on HOLD.

When interpreting a result, distinguish the fixture’s terminal record from the
[owning gate’s final completion](../test.sh.md). The published receipt applies to the admitted
source, image and test inputs for that attempt.
