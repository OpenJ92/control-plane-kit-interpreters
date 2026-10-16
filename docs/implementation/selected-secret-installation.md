# Selected secret installation checkpoint (#191)

The reviewed target is Docker installation of an exact consumer-selected version,
using the accepted Core contract at `87e231c661879e44816ba71ff9320c040c868d60`.
Metadata and exact-version resolution source is separately checkpointed in #190.
No #191 application source or accepted runtime behavior exists at this checkpoint.

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

Independent review passed the source-free design and focused target shape.
The public Operations-port bridge remains Servers #252 work. No metadata or
installation result in this checkpoint grants execution authorization, proves
production deployment, or changes durable external resources.
