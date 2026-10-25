# Docker recovery metadata (#224)

The separate `DockerRuntimeEffectObserver.observe_metadata` capability reports
current selected addresses. Its result is always indeterminate or unsupported;
it never establishes the historical effect outcome, installed bytes, predecessor
quiescence, ownership authority, readiness, or permission to retry or delete.
The existing general `observe` capability keeps its original behavior.

The reviewed interface accepts the original `RuntimeEffectObservationRequest`,
the authority object and the mandatory keyword `expected_daemon_id`. The caller
in Operations owns active registration, workspace/ref/request binding and
authorization. This adapter checks the explicit local transport and exact daemon
expectation; shape checks do not establish those durable authorization facts.

## Behavioral provenance and validation

The focused target tests in `tests/test_docker_recovery_metadata.py` strengthen
the existing observer's passive-attestation refusal and owned Unix lifetime laws
with a new metadata-only capability. Existing generic observer tests remain the
regression context. Configuration allocation and selected secret naming reuse
the existing configuration and selected-secret owners.

New laws cover the closed projection, strict daemon binding, zero secret/file
access, unavailable image-derived file addresses, typed absence versus unknown,
ownership conflicts, bounded actual SDK calls, drift and scheduling expiration.
The positive fixture contains existing container/network/image/configuration and
selected-secret metadata, with forbidden high-level SDK managers and Env access.
It does not create resources to establish the expected test state.

The owning gate is pinned-mode `./test.sh`, including its ordinary isolated local
SDK witness and exact owned cleanup. Provider-contract opt-in stays disabled.
The test checkpoint precedes source implementation; red and green evidence are
recorded on the issue and PR. Package evidence is not live recovery evidence.

## Security and operational boundary

No provider mutation, secret resolver, remote TLS admission, archive access,
exec/log calls, image pull or broad inventory scan belongs to this capability.
All endpoint observations are empty. Failures are fixed public values; raw
provider errors, labels, addresses, mount paths, environment and daemon IDs do
not enter the result. Unexpected internal errors propagate to the consuming
public boundary for sanitization.

No durable state is written here. Operations must collect outside its database
transaction, strictly validate the versioned result and current owner context,
then revalidate its pins before accepting any evidence. Two sequential sweeps
detect observed drift but do not constitute an atomic provider snapshot.

## Exact wire commitments and bounds

Daemon identifiers match `[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}` exactly. The provider
binding is SHA256 of `b"control-plane-kit.docker-provider-binding.v1\0"` followed
by the exact ASCII identifier. There is no normalization or alternate algorithm.

The selector is SHA256 of `b"control-plane-kit.docker-recovery-selector.v1\0"`
followed by RFC8785 bytes of `[role, exact_lookup_coordinate]`. Volume identity is
SHA256 of `b"control-plane-kit.docker-recovery-volume.v1\0"` followed by RFC8785
bytes of `{name, labels, driver, scope, created_at}`. These hashes never include file bytes,
Env, mountpoints or an installed-content assertion. Image/container/network
identities are canonical SHA256 image IDs or 64 lowercase hexadecimal IDs.

Targets are ordered container/network/image, then original configuration indices,
then file-role indices in original file-delivery order (environment deliveries
do not shift those indices). File selectors use only the exact local
image's supported numeric user and existing selected-secret naming. Missing UID
leaves explicit null-selector rows. At most eight combined volumes are admitted;
the eleven-row maximum passes through the actual Core 4096-byte evidence codec.
Known duplicate coordinates refuse before I/O; UID-dependent duplicates stop
after the image read and before any volume query.

Parsed mappings have at most 64 fields. Label keys/values are limited to 256/2048
characters and 16384 characters in aggregate before copying; repository digests
are at most 32 strings of 1024 characters. Unrelated response fields are ignored,
not recursively copied. These are projection bounds, not raw HTTP allocation
limits. Each volume has at most one attachment existence query per sweep, with
all container states, exact volume filter, and limit one.

Returned container/network names and all CPK ownership labels must agree.
Container image identity, network identity, selected mounts and state are bounded
internal comparison facts. They detect conflict/drift without exposing private
addresses or mount paths. Volume identity includes its creation timestamp.
Attachment evidence requires a bounded exact volume mount on the returned holder;
contradictory absence/attachment facts cannot earn complete coverage. Known
provider faults or malformed projections stop all later reads, including the
second sweep, and preserve the current partial rows before closing.

Two sweeps cost `8 + 4N` Engine reads plus at most one API compatibility call,
maximum 41. The explicitly owned local policy must have timeout at most 10 seconds.
A private monotonic budget starts before acquisition, checks construction,
negotiation and every subsequent Engine call, and stops scheduling at 30 seconds
or invalid clock behavior. Cleanup still runs; there is no hard cancellation.

Target-red checkpoint `6390da2` ran 604 package tests in 90.839 seconds and
produced exactly 23 missing-capability assertion failures across the twelve new
test methods and their subcases, with no errors. This establishes causal absence
of the new API, not independent execution of each deeper law. Implementation and
additional negative targets must pass the subsequent owning gate.

Independent review found omitted legacy configuration scope, incomplete exact
correlation/attachment/drift facts, continued reads after faults, file-index
mapping and malformed Unicode handling. The pre-fix regression checkpoint
`2f4b882` produced six intended assertion failures and one provider-Unicode
encoding error across 619 tests; that error was a source defect, not an apparatus
failure. The repairs reject legacy unallocated configuration before I/O, retain
bounded comparison facts, validate holder mounts, stop on faults, preserve
role-specific indices and classify invalid provider Unicode as malformed.
Official Docker Hub spellings reuse the existing `matches_image_reference`
owner; unrelated registry/repository digests remain conflicts.

The final ownership pass also preserves known name/label conflicts when image
or UID context is unavailable. Allocation-aware container and file-volume labels
include `configuration.selection`, derived through the existing pure Core
configuration correlation/selection owner, just as runtime creation does. The
positive fixture asserts matching ownership on that actual producer shape;
wrong selection and unknown extra CPK labels remain conflicts.
