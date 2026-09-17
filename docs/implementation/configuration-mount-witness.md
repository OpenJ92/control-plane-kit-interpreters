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
