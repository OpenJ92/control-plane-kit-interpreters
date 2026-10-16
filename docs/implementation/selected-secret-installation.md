# Selected secret installation checkpoint (#191)

The reviewed target is Docker installation of an exact consumer-selected version,
using the accepted Core contract at `87e231c661879e44816ba71ff9320c040c868d60`.
Metadata and exact-version resolution source is separately checkpointed in #190.
The candidate now implements #191 locally; validation and independent acceptance
remain pending. The historical red evidence below predates this implementation.

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
cleanup laws remain required before acceptance.

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

These are source and test descriptions, not claims of a passing candidate gate.
