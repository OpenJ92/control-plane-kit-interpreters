# Configuration readback foundation (I177-A)

Target checkpoint: provider implementation is not changed yet. Governing I177
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
