# Selected configuration delivery witness (#156)

The ordinary gate's existing daemon-authorized secret controller calls
`run_configuration_witness` after its numeric secret checks. Package tests retain
no daemon socket. The controller and engine/image identities, outer cleanup and
owning-gate status remain governed by the existing script.

Shared test fixtures retain #155's public gateway configuration and static CPK
http-api/V2 liveness schema. They do not execute a CPK configuration decoder or
receiver process. Two freshly generated configurations provide default A versus
selected B. Actual SDK materialization and digest reads fill two fresh labeled
volumes. One captured-ID numeric reader mounts B at both declared receiver paths.

Numeric exec proves UID/GID, regular0444 files and B-not-A digests. Engine
inspection proves both exact volume destinations are RW=false. Root exec accepts
only EROFS from attempted writes, not EACCES. The public-data reader drops all
capabilities except DAC_OVERRIDE for this distinction; it is not privileged,
has no network or daemon socket, and uses captured image identity.

Create acknowledgements are recorded before subsequent effects. Unacknowledged
creates report bounded attempted coordinates and HOLD, without retry or invented
absence. Finally cleanup checks exact reader identity/image/run labels, captured
helper IDs/image/volume bindings, and volume names/run labels. Containers precede
volumes; every acknowledged resource is checked absent. Failed removal, residue,
ownership mismatch or uncertain creation prevents success. A helper removed by
the SDK normally is still checked absent. The original SDK helper wrapper is
restored so the outer secret witness retains its own bookkeeping.

Package tests protect partial-create uncertainty, ownership refusals, failed
helper removal, residue and already-absent resources. This is a validation-only
slice with new/strengthened fixture laws, not an artificial missing application
feature. Actual execution requires reviewed source plus North's ordinary-CI
release; no local retry or alternate harness. The composed evidence proves
selected bytes and readonly mounts, not production graph/lifecycle/receiver
health, a full cluster, published images or the #158 generation-client gap.

I177-A additionally exercises the SDK's bounded staged-file observation and
installed-file observation on the captured reader container ID. Both must report
the selected digest, actual mode and regularity. Installed evidence must also
match exact configured/effective volume, target, content subpath and read-only
facts. These checks supplement rather than replace numeric reading and EROFS.
The helper tracking and exact owned cleanup remain unchanged. This is readback
foundation evidence, not staged-replacement or production cleanup acceptance.

I177-B2 creates the reader through the real SDK, records its returned immutable
ID before subsequent reads, and starts that ID through the SDK. A test-only
additive override of the existing kwargs builder preserves the reader's
read-only root, dropped capabilities, DAC override and no-new-privileges; the
original builder is restored immediately. Explicit network `none` preserves
the disconnected reader and is checked in engine inspection. No creation,
start, identity or installed readback is simulated. The cleanup fixture also
tests recording the returned ID before a later read can fail. This extends
the real SDK creation-to-installation witness, not full runtime replacement
or live grandparent acceptance.
