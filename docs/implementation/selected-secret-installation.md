# Selected secret installation checkpoint (#191)

Current Interpreters #220 retains Core
`955666898218e4f2956b6e9fcd33bdba97ffdb06`, advances to accepted Secrets #66
merge `b73cfc183931c019c786885297d458a9a43c5039`, and retains SDK #67 merge
`cad5cc3dacbff1da79e6cc8b4c0c88526363e033`. Consumed
selection/grant/request/receipt contracts remain unchanged. The pin adds only
the provider family used by the surface-read client witness; no secret
installation, readback or cleanup implementation changes accompany it.
The unchanged full owner gate must establish installation and existing Docker
witnesses; provider-contract opt-in stays off. Retained-image observation is
the separate #214 target, not a provider or live deployment claim.

Historical Interpreters #211 selects Core
`ec61e2b17c3a3f1bdea1dd6bc8fc64ac1b9528b0`, accepted Secrets #63 merge
`b30e62664da50cfdda347509a17fa70888cb169a` and its accepted SDK #65 merge
`eff09090755eb21028695f0224eec7b81f2db535`. Installation continues to consume
concrete selected artifacts and exact grants; Core refuses unresolved required
slots at the effect-material boundary. No installation, receipt, readback,
uncertainty or cleanup implementation changes here. Ordinary pinned validation
is pending and must include the existing actual Docker witnesses and owned
container/reader fixture image/record cleanup. The main package test image is
retained by the existing runner; provider-contract opt-in remains off.
This is dependency adoption for Servers #280, not managed transport or live proof.

Historical Interpreters #207 dependency adoption selects Core #2005 merge
`73d87e99bf711ff8a88112ca56c5eee8055ac5b7`, test Secrets #61 merge
`7ff1e771874e5963ee840d7148d2d4052278baa1` and its SDK #63 merge
`1657cb91b143931bafcdb32108950d2bbbb66d95`. Core changes controller selection
compatibility and planning, not the selection/grant/request/receipt contracts
consumed here. Installation code and witnesses remain unchanged. The ordinary
owning gate must prove the adopted dependency combination and exact fixture
cleanup; provider-contract opt-in stays off. Historical evidence below retains
its original coordinates and is not new live deployment evidence.

Historical Interpreters #205 dependency adoption selects Core/Operations #1998 merge
`9861e536e79314005499ae07379f627bfb1599a2`, test Secrets #59 merge
`165a7dc7abd75e1ba50b9494d0f0aabf0aa3c33c` and its SDK #61 merge
`d4e7c4d91c054f139e2971774ae5e37fc741262d`. Consumed secret selection,
grant, request and receipt contracts are unchanged; only Core's managed-update
compiler production module changes. Installation code and witnesses are unchanged.
The original #191 checkpoints and evidence below retain their coordinates;
new dependency compatibility requires the unchanged owning gate.

The reviewed target is Docker installation of an exact consumer-selected version,
using the accepted Core contract at `87e231c661879e44816ba71ff9320c040c868d60`.
Metadata and exact-version resolution source is separately checkpointed in #190.
The candidate implements #191 locally. The full owning gate passed at
`0557ce46bdb1f9d1b1ae038ef91d4ddf6531aed7`; independent final evidence review
and publication remain separate. The historical failures below are retained.

The agreed shape reuses the existing exact-container configuration replacement
path for both plain and configuration activities. A complete consumer-grant
check precedes authority-client construction and resolution. Immutable file
identity includes the public version/use, destination, mode, and admitted numeric
UID. Environment-only delivery preserves the admitted configured user without
requiring a numeric UID. Private readback must inspect the actual captured
container ID, declared environment, exact readonly mounts, and bounded actual
recipient archive bytes/UID/mode. Shared Core receipts follow successful private
verification, and late authority-close uncertainty strips all success receipts.

Bounded attempt evidence must identify canonical file slots together with their
public identity profile and UID, actual old/new IDs, retained observed mounts,
and partial/unknown staging. Old volumes remain intact. This evidence grants no
cleanup authority. The existing isolated witness may clean only its exact
recorded resources after ownership and detachment checks. Observation remains
conservative and unqualified for exact-version installation.

The initial six new-law tests use the existing archive-backed SDK fixture:
missing-grant zero IO through both entrypoints; created/reused/replaced actual
recipient receipts through both entrypoints and effect kinds; environment-only
named users; unchanged version with changed image UID; incorrect or unavailable
private readback; and partial staging residue. Receipt fingerprints are compared
with the existing independent actual-container-ID preimage. The fixture now
exposes the environment passed to Docker and preserves archive UID/GID. These
are fixture premises, not evidence of successful implementation. Additional
malformed-grant, close-failure, archive-negative, capacity, observer, and exact
cleanup laws were still required at that initial checkpoint; their subsequent
implementation and evidence are recorded below.

Validation stopped twice before package collection:

- The first ordinary pinned `./test.sh` ran 26 support tests with one failure:
  its exact Core coordinate expectation still named the prior merge. Review
  approved changing only that literal to the accepted coordinate, preserving
  the equality assertion and runner. Log SHA256:
  `008fee56be7e28627e367b1d7a8d9aea02bf99babb4d0c0f3e8c7991b3420928`.
- The second ordinary pinned run passed all 26 support tests and the integrity
  check, then failed dependency resolution while building the package image.
  Interpreters requires Core `87e231c6`; its pinned Secrets
  `28c9045c5d0aecf7471c151cae90ebb9ac88a123` requires Core `05b5f28a`.
  Log SHA256:
  `633f40028df1470434d0243096262b2d358568a2d46740496348a4b63e680b61`.

Neither run is causal red evidence for #191. Compilation, package tests, clean
import, and real Docker witness were not reached. No dependency bypass, custom
runner, local-Core substitution, or provider-contract opt-in was used. Resume
only with an accepted compatible Secrets coordinate and the unchanged owning
gate; establish genuine missing-behavior evidence before implementation.

Dependency stop resolution: accepted SDK #55 merge
`ad0582937d7e41f1e7a41295fa1de58c2ce4cba2` selects the same Core, with 24 support
and 207 package tests plus all installed probes passing. Accepted Secrets #53
merge `b3e6d21f1f53c3ad2fe9ec33900ddde0611e2b5a` adopts that SDK and Core, with
21 support and 99 package tests, compilation and clean import passing in its
hosted owning gate. Both received independent review. The Interpreter test-extra
and exact installed-owner expectations now select those actual accepted merges.
The earlier failed-run classifications remain unchanged; the resumed Interpreter
gate still must establish genuine missing-behavior evidence.

Independent review passed the source-free design and focused target shape.
The public Operations-port bridge remains Servers #252 work. No metadata or
installation result in this checkpoint grants execution authorization, proves
production deployment, or changes durable external resources.

At exact candidate `a91f0e4510654acb460f5e20d36cd4a74015ee58`, the resumed
ordinary pinned gate passed 26 support tests, dependency assembly and
compilation. The package run executed 505 tests in 63.617 seconds and ended
with 13 assertion failures plus 150 construction errors (exit 1). Log SHA256:
`3d952e365a391e8c36d8c9b814b221b8d9ebfa86c21c188cf4aeb6a5c39eed46`.

All 13 assertion failures belong to the six new #191 methods. They expose
consumer-version grants being sent through the old operational helper, and
missing-grant rejection happening after container lookup or authority-client
construction. Later recipient, replacement and residue assertions were not
reached and have no red/green proof yet. Separately, 144 errors arise from old
fixture material lacking the now-required exact selections; six arise from
negative fixtures constructing node requests the new Core rejects immediately.
Those are fixture translation work, not missing #191 behavior evidence. They
occur in connector, runtime, observer and SDK tests sharing a few constructors.

The seven #190 metadata methods, eight provider-resolver methods and isolated
real-provider method all passed in this package run. This is focused evidence
inside a failing package gate, not whole-adapter acceptance. Clean import and
the separate real-Docker witness were not reached; no package container remained
after the gate. The runner and provider opt-in were unchanged.

## Candidate implementation

`docker/runtime.py` routes selected consumers through the existing exact-ID
replacement path. Core request reconstruction validates the closed grant union
and every correlation binding before either execution entrypoint opens runtime
authority. `secrets.py` checks complete selection coverage, resolves each exact
version once, and rejects invalid/oversized material and unrepresentable
environment values before resource mutation. There is no latest-version or
operational-grant fallback.

File identity hashes only public workspace/runtime/node/reference/use/version,
destination, mode and admitted numeric UID. Its full hash is checked alongside
ownership labels; populated material is never overwritten. Generic inspection
and evidence expose no secret bytes or content digests. The SDK's private
recipient verifier reads the captured actual ID, checks exact declared values
and configured/effective readonly subpath mounts, reads bounded regular-file
archives, then checks that recipient facts remained stable. The adapter admits
at most 32 file slots, 65,536 UTF-8 bytes per value, 1,024 environment entries
and 1 MiB environment data; archive transport is bounded to 1,024 chunks and
16 MiB. Full result capacity is reserved before mutation.

Shared Core receipts are constructed only after installed verification.
Configuration completion is emitted only for the configuration effect kind.
Unknown creation, materialization, actual readback or authority close leaves
bounded uncertainty and no installation receipt. Late close also removes
configuration completion and observations. Attempt evidence records canonical
slots, UID, exact old/new IDs, retained observed mount names and unknown flags;
it neither resolves cleanup nor authorizes it.

The new tests add forged-grant zero-IO admission, malformed private values,
uncertain create readback, late close, actual recipient archive negatives,
file-slot capacity and conservative observation. Existing positive consumer
fixtures explicitly select versions and construct bound consumer grants;
negative/default request fixtures never invent authority. No assertions are
weakened to accommodate the new model.

The existing finite Docker installation witness now has a selected-secret
sequence: configuration plus environment/file installation, reuse and version
replacement. It preserves the admitted policy image's configured user and uses
the actual runtime/SDK throughout. The separate existing UID 10006 witness
continues to prove numeric-reader access. The selected sequence adds no ports,
credentials, provider opt-in or production resources. It owns one fresh internal
network, six volumes, two sequential workloads and at most 21 helpers. Recorded
original identities/labels and observed detachment govern exact test cleanup;
foreign holders, ambiguous creates or remaining resources prevent acceptance.

These descriptions were recorded before candidate execution; terminal evidence
follows below.

Candidate `88027b49df663ed543f79cc41f9f77154c884352` passed 26 support tests,
integrity, dependency build and compilation. Its package run executed 515 tests
in 70.524 seconds, ending with 44 assertion failures and two construction errors
(exit 1); clean import and real Docker witnesses were not reached. Log SHA256:
`828b4aaf57b3b21a006066c709cabb80074081d84b04e873d62eec7854303305`.

Static diagnosis found that the archive-backed provider fixture lacked the SDK
`reload()` boundary used by private verification; 43 failure entries cluster at
that initial verification. Another assertion is the exact SDK method inventory,
and the two observer fixtures still supply operational consumer grants that
the accepted Core now refuses. These are distinct from accepted recipient
behavior. The correction exposes recorded reloads and between-read changes in
the existing provider fixture, updates the exact method inventory, and models
current observer grant admission. Archive-negative tests additionally require
the actual recipient read to be reached, preventing an unrelated earlier
fixture failure from satisfying a negative test. No production source or test
runner change was needed for these corrections. The following run validated them.

The corrected candidate `2334dc5ef006ed9276e25db1055e16b5496123c1` passed all
26 support and 516 package tests (73.862 seconds), compilation and clean import.
The actual-target archive negatives and same-ID refresh drift test now reach
their intended boundaries. Existing real configuration installation, reuse,
replacement and cleanup witnesses passed with absent residue. The new selected
secret witness stopped in image-user preflight before creating any of its
resources; the full gate exited 1. Log SHA256:
`21191787cbe812f6d12eeb92d221af7c4011489b0eff0d2b87b5008b9741f608`.

The public policy image's valid Config object omits User. The SDK interprets
omission as unknown, whereas Docker documents omission of unset image User
fields since API 1.52 and the default container user as UID 0. This is distinct
from explicit null or malformed/missing Config. The prior negative fixture
treated an empty Config object as unknown user; review of that premise is
required before a narrow image-only normalization. No override, fabricated
RepoDigest, alternate runner or selected-witness success is claimed.

Provider references: [Docker API history](https://docs.docker.com/reference/api/engine/version-history/)
and [default container user](https://docs.docker.com/engine/containers/run/#user).

Bounded raw evidence from daemon API 1.55, `GET /v1.55/images/python:3.14-slim/json`:
image ID `sha256:83ff1d245a3d57d04152252d3ef9cb361494d0b3395abd65a5ebe91c401c8e83`;
Config present and object-valued; User key absent. No environment or full image
configuration was recorded. This confirms documented omission, not explicit null.

North and independent review approved the narrow representation correction:
`inspect_image` maps omitted User inside a valid Config object to the existing
empty-string default. `_configured_user` for actual containers, connector image
admission and numeric UID validation remain unchanged. The old `{}` negative
fixture becomes an explicit default-user law with provider provenance; null,
nontext, missing/malformed Config and unsupported user forms remain negative.
An actual-container missing/null/nontext User test prevents this image default
from weakening installed-recipient evidence. Its validation is recorded below.

## Terminal owning-gate evidence

Candidate `0557ce46bdb1f9d1b1ae038ef91d4ddf6531aed7` passed the unchanged
pinned `./test.sh`, exit 0 with terminal `owning-gate=PASS`. Its 26 support tests
passed in 0.064 seconds, 518 package tests passed in 72.897 seconds, and integrity,
compilation and clean import passed. Log SHA256:
`a66336aef62a4728e4d3e3c58d06fc992af82b6db9dd9ac74248873294719224`.

The existing real numeric-reader/configuration witnesses passed. The selected
secret runtime witness then verified actual created/reused/replaced incarnations,
coherent configuration and secret receipts, unchanged old secret file material,
stable reuse identity, distinct replacement identity and verified prior absence.
Its exact resource totals were one internal network, six volumes, two sequential
workloads and 21 helpers. Cleanup passed with zero unresolved creates and absent
residue; outer numeric-reader cleanup and the runner's recorded-resource cleanup
also passed. Provider-contract opt-in remained off.

This proves the configured local Docker adapter and its actual private recipient
readback under the admitted policy image's default root user. The separate real
UID 10006 access witness and synthetic selected UID-change laws are not a real
full selected non-root sequence. It does not prove Servers production injection,
public Operations-to-provider integration, published-image adoption, a grandparent
deployment, or general production secret-volume cleanup. No such resources or
credentials were changed by this validation. Subsequent checkpoint-only edits
do not change the validated source or executable tests.
