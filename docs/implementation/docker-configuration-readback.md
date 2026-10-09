# Configuration readback foundation (I177-A)

Governing I177
dry run is comment6071162689; concrete interface and bounds are frozen in
comment6071205155. North released A on the existing I176 selected dependencies,
separate from later staged replacement and exact cleanup.

`tests/test_docker_configuration_readback.py` exercises the actual SDK adapter
over its existing fake Docker boundary. The public methods under test are
`inspect_configuration_file(volume_name)` and
`inspect_configuration_mount(container_id, mount)`. File facts contain only
digest, actual mode and regularity. Installed facts also identify the actual
container and exact configured/effective volume, target, subpath and read-only
binding, then read the installed file from that same container ID.

Missing file/container returns None. Malformed, ambiguous, conflicting or
oversized evidence raises a fixed configuration-evidence error. Provider and
lazy stream failures, including helper cleanup failure, remain uncertainty;
they cannot become absence or completed invocation evidence. The content limit
is 262144 bytes, separate from the 1048576-byte archive and 1024-chunk bounds.
Only one regular file with the exact expected member name is admitted; links,
extra files, truncation and malformed streams cannot prove material.

Targets preserve existing materialization and read-only helper cleanup laws,
then add mode/regularity, exact container/mount correlation and actual installed
bytes. The public client-surface expectation adds the two SDK observation
methods. No effect dispatch, allocation naming, cleanup, authority, dependency
or RuntimeEffectResult contract changes are part of this slice. Existing digest
readback remains compatible but is not the later installation proof.

The unchanged pinned `./test.sh` owns red/green evidence. Its existing numeric
configuration witness will retain independent file-mode/content and EROFS laws
when it consumes the new readback. No new provider opt-in or live acceptance is
implied. B must account for all helper/workload mutation uncertainty before
emitting Core's whole-invocation completion; A creates no completion assertion.

## Implementation and causal evidence

Targets-only `69e4775` reached 420 tests in 20.195s through the unchanged pinned
gate (run37860922888/job113596169903): 20 assertion failures exclusively in the
six new methods and the two-name public-surface expectation, zero errors.
The other 413 methods passed; 26 support tests and integrity passed (40 reported
mock sites, zero skips). The missing methods, not collection or apparatus,
caused red. The target methods are unchanged in the implementation.

`docker/sdk.py` now returns local typed file and mount observations. The bounded
archive parser checks the whole regular-file record, hashes actual bytes and
returns actual mode, leaving comparison to the selected artifact to its caller.
It never returns content. Staging uses the existing read-only helper and its
cleanup; failure of either provider stream or cleanup escapes as uncertainty.
Installed readback validates a canonical container ID, resolves that exact ID,
checks returned provider identity and correlates both mount views before file
access. The archive comes from the selected target on that same container.
Identity/mount facts are checked again against that object before returning.

The existing real-engine witness now consumes staged and installed observations
and compares them with its selected artifacts, alongside independent numeric
file reads and EROFS checks. The legacy digest method is retained unchanged for
compatibility; later B must use the bounded new observations. No runtime dispatch,
cleanup operation, pin, authority guard or retrospective observer changed.
