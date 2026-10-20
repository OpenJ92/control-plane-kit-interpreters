# Native connection observation (#167)

## Explicit managed wrapper profile (#148)

`ConnectorConnectionProfile.MANAGED_WRAPPER_V1` explicitly selects the accepted
managed Cloudflared launch and configuration shape. Native reader-v1 remains
the default, with its existing refusal and fresh/retained laws. No product class
name or extra mount implicitly changes the profile.

```python
from control_plane_kit_interpreters.docker.connector_connection import (
    ConnectorConnectionProfile, DockerConnectorConnectionObserver,
)

observer = DockerConnectorConnectionObserver(
    client, reviewed_product_reference, reviewed_image_reference, utc_clock,
    profile=ConnectorConnectionProfile.MANAGED_WRAPPER_V1,
)
```

The pure shape query admits the exact declared JSON/read-only
`cloudflared-control` slot at `/etc/cpk/cloudflared/control.json`, configuration
environment binding and V2 control surface. It checks canonical product/image,
graph metadata, complete supported plan and current runtime authority. Declared
slot selection does not decode receiver material, resolve a token or establish
installation. Full qualification requires genuine matching receiver material
and the selected token file/version; observation also checks workspace scope.

SDK image inspection requires the managed Python entrypoint, empty Cmd, `/app`,
user `65532:65532`, SIGTERM, fixed configuration binding and unchanged readiness
HEALTHCHECK. Effective container launch must equal that selected image with only
the admitted token-path overlay. The container must have exactly two distinct
readonly volume/content-subpath mounts: selected token and configuration.
Extra, duplicate, overlapping, writable, bind/tmpfs/VolumesFrom and inconsistent
configured/effective mounts fail closed. Sharing token storage with the
configuration mount is rejected before any archive read.

Retained observation uses the existing original request/secret receipt pair.
Core's original receipt reader already validates the coupled configuration
receipt; Operations owns that durable source proof and current admission.
Original configuration selection determines the expected allocated volume and
receipt incarnation. Missing or incompatible retained selection refuses before
I/O; it cannot use fresh-mode candidate semantics. No second receipt export or
duplicate Operations read is needed.

Fresh observation rejects installation pairs. Its observed configuration volume
is a candidate/stability fact, not accepted allocation history. Both modes read
only the selected configuration target through bounded `get_archive` on the
captured container ID, using the existing installed-configuration projection.
Digest, mode and regular-file facts must match. This projection does not prove
file UID/GID. The observer never reads the token body, stages configuration,
creates a helper, executes a command, probes a network endpoint or repairs state.

The final container inspection must preserve both mounts, launch, ownership,
image, incarnation and newest sample, with the existing strict freshness and
decoder. Changed/unavailable facts return UNKNOWN without retry. These reads are
point-in-time evidence, not an atomic snapshot or continuing attestation.
CONNECTOR_CONNECTED still cannot discharge authenticated management health,
installation/accounting acceptance or cleanup. Existing local/signed readers
and generic legacy helper paths are unchanged; downstream selected composition
must separately prove no helper/fallback on its owned route.

Plan [revision 2](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-6300992975)
uses accepted Servers #280 merge `39928d9` as the product-shape reference, not a
new published image. Core remains pinned to `ec61e2b`; no dependency changed.
The initial target run failed on an omitted fixture endpoint; corrected target
`eeb4880` reached exactly 63 missing-implementation errors, with all 543 prior
tests passing. Source `2e4b087` passed independent source review and the full
unchanged pinned owning gate: 26 policy and 555 package tests, isolated import,
Docker configuration/installation/secret-delivery witnesses and owned cleanup.
This is package/interpreter evidence; the managed native profile itself is
covered by recording-SDK tests, with actual selected-image/live qualification
remaining downstream. Final merge disposition is recorded on #148 and its PR.

The earlier sections below describe the native default and its historical
acceptance; their managed-profile exclusion applies to that default only.

## Descriptor-based shape query (#148)

The approved follow-on interface is `qualify_shape(activity_id=..., plan=...,
current=..., desired=..., product_document=..., authority_ref=...)` on the
existing observer. It returns the existing qualification mode or `None` without
effects, material construction, time reads or authority grants. The source now
implements the query and shares the existing pure plan predicate and token-file
slot validation with full-material qualification. The old strict material and
observation behavior is preserved; SDK inspection is unchanged. Exact source
review and owning-green validation remain pending at this checkpoint.

The real Core descriptor bytes must canonically decode and match the supplied
product before deriving the trusted reference and checking graph metadata and
image. Empty descriptor/node deliveries are a symbolic generated-token
obligation only for the exact supported ingress/plan relation. An explicitly
authored file can match an empty declaration or the same static file slot with
its own instance reference. Descriptor-only delivery is conservatively
unsupported, even where later owner-projected full material could qualify.
The full-to-shape coherence law applies only inside this declared supported
domain. No fake reference/version or duplicated Operations resolver is allowed.

The query reuses Core compilation and observation resolution; its narrow
fresh/content-update restriction is a Docker capability, not generic topology
validity. Operations retains producer/consumer effects, durable versions,
current authority and installation provenance. Other interpreters can query the
same Core intent with their own explicit supported/refused profiles; provider
parity and host provisioning are not implied. The authored graph stays unchanged.

Managed receiver environment/artifacts and new launch/mount profiles remain
unsupported in this leaf. Strict selected-version and retained-proof checks,
C-label/REUSED-A UNKNOWN, bounded passive observations and all existing reader-v1
guards remain governing laws. Servers #181 owns future composition; Rowan's
#188 product declaration/profile work is separate from this query.

Plan: [approved interface](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-6278254403),
[language/ownership note](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-6278263216),
[coherence-domain correction](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-6278292316),
[Kepler PLAN PASS](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-6278299447).

The final target head `8f23fd6` passed independent target review after two
constructor-invalid fixtures and the no-mutation witness were corrected before
any run. Its sole normal local pinned gate ran 26 policy tests green and 543
package tests with exactly 45 missing-query NotImplementedError cases; all 30
prior connector methods passed. [Causal-red PASS](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-6278492802)
released this source step. The 12 new methods and all prior targets remain
unchanged. Assertions previously hidden behind the stub still need green
execution, including detached public-codec no-mutation snapshots. Red did not
reach the later isolated-import or local integration witnesses.

## Retained observation (#148)

The reviewed #148 slice adds a pure `qualify` result (`FRESH`,
`RETAINED_CONTENT_UPDATE`, or `None`) and paired optional
`installation_request` / `installation_receipt` arguments to `observe`.
The implementation shares pure graph/material qualification between selection
with complete material and observation; retained dispatch separately validates
the installation proof. This behavior was accepted in PR209 at `2274d974`.
Earlier target/source checkpoint accounts below are historical; the new shape
query above has its own pending source review and owning-green evidence.

Qualification takes the actual plan activity, validated graph pair, selected
Core product material and current runtime authority reference. It performs no
Docker or clock read and needs no effect identity or installation witness.
Retained observation separately requires the original Core installation request
and exact typed `SecretInstallationReceipt`, correlated by Core's request and
secret-selection fingerprints. The caller remains responsible for trusted
durable provenance and current execution authority. Historical authority
references never supply current credentials or authority.

The retained graph relation is deliberately narrow: one public JSON application
file changes content, its receiver configuration and all other graph values stay
unchanged, and the actual Core managed-update compiler returns the exact ready
plan. The changed workload must belong to the observed runtime and must not be
the gateway or connector. Image, secret, verifier, declaration, topology,
multi-file and path changes do not qualify. This capability predicate does not
replace Core planning or Operations admission.

The current observation B returns B's effect/activity identity while checking
the original installation A's owned name, labels and selected readonly volume.
The inspected immutable container ID must match A's receipt commitment. Existing
launch, image, mount, newest-sample, nanosecond freshness, final reinspection,
redaction and three-read/no-retry laws remain mandatory.

A is a receipt-correlated installation request, not necessarily a birth-label
origin. A real REUSED reconciliation can retain an earlier creation C's labels.
This slice returns `UNKNOWN` after the first container read for C-label/A-receipt
evidence even when the immutable ID matches. It does not normalize labels,
search a provenance chain or guarantee success for every valid REUSED receipt.
Missing/malformed/mismatched supplied proof instead refuses before lazy SDK
initialization. The fixture models actual Core values and recording provider
reads, without reproducing the Operations ledger or lifecycle.

Plan review: [Kepler PASS](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-6276358825).
Target review passed at `608c526`; [causal-red review passed](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-6276624788)
after 529 package tests produced only the 67 explicit missing-behavior errors
(28 qualification, 39 retained observation), with 26 policy tests green. The
earlier `549d671` attempt had a fixture import error and is not causal-red
evidence. Assertions behind the scaffolds still require owning-green validation.
Servers #181
owns the native-port adapter, witness unwrapping, compatible pin selection and
process activation. Whole #148 still includes separate legacy-helper retirement;
product qualification and live #225 are not released by this slice.

This opt-in reader-v1 adapter consumes a product-owned Docker health sample.
Operations must supply the original admitted request, exact plan and validated
graph pair, and independently recheck current actor/runtime authority and worker
fence before I/O and durable acceptance. The constructor authorizes nothing.

```python
observer = DockerConnectorConnectionObserver(
    client, reviewed_product_reference, reviewed_image_reference, utc_clock)
result = observer.observe(original_request, plan=plan, current=current, desired=desired)
```

The composition-owned product reference/image binding identifies reviewed reader
code. This first profile supports fresh desired-side resources, one tunnel file
delivery under Core's protected secret namespace with TUNNEL_TOKEN_FILE binding,
and the exact derived readonly volume. Fresh observation refuses retained
resources; only the bounded retained-content profile above can admit them with
installation proof. Both profiles refuse base-side observation and environment
token delivery. Source availability is not image publication or live
adoption. Default dispatch and signed management observer guards are unchanged.

Selection uses Core's actual compiler/resolver and existing Docker ownership/name
derivation. The plan must equal the actual graph-pair compilation, with new
runtime, gateway, connector and ingress identities and actual StartRuntime,
both StartNode and AllocatePublicIngress obligations. A newly named attached or
external runtime is not fresh. Bounded SDK projection precedes comparison of effective launch,
environment, mounts and current process incarnation. Environment key order is
irrelevant; duplicate names, malformed/truncated values and extra overrides are
rejected before hashing. Ordered argv is preserved. The newest completed sample
is decoded strictly; aggregate health never substitutes for connection evidence.
Reinspection pins the actual container ID and must preserve the sample as well as
ownership/launch/incarnation. Failure is closed and redacted, with no raw provider
configuration, sample output or exception diagnostics in public results.

Passive samples may precede observation admission. Require
StartedAt <= Start <= End <= acceptance time and End age <=10 seconds, retaining
nanosecond precision. Native timestamps reject invalid zone components before
Python can normalize them. There is no invented native grant/expiry; signed-stage
health windows remain unchanged and distinct. This is point-in-time evidence, not an atomic or
continuing attestation. Unknown/disconnected never becomes fabricated readiness.

Three semantic SDK lookups: container by owned name, pinned image, same container
by immutable ID. Lazy initialization may additionally negotiate API version.
Effective API timeout must be finite, positive and <=60 seconds; it is an
inactivity timeout, not a hard wall-clock limit. Projection bounds apply after
ordinary SDK decoding, not to HTTP wire bytes. Time is checked after each read.
No pull, exec, helper, start, polling, observer retry, timeout mutation or alternate
Docker transport is introduced.

## Target provenance and current evidence

The new-law tests use a pure actual compiled managed graph and recording SDK API,
not a workflow/admission emulator. They preserve prior signed-observer guards and
SDK/runtime laws. Covered cases include original selection denial before lazy I/O,
file-only delivery, owned name/image/network, launch/environment/mount tampering,
latest output strictness, nanosecond boundaries, late reads and final replacement.
Initial target6cded83 reached82 intended NotImplementedError cases in normal
owning CI36025322221. Independent review found three isolated fixture-law gaps;
corrected target332a119 passed target review5817814885 and reached84 intended
NotImplementedError cases in CI36025736670/job107721673826. Both runs had400
package tests and26 policy tests; no unrelated exception/failure type. Corrected
red log SHA256: d2e3f2e81e259b30ace37c7b30cd339d39574fd9884aa9313dd26db3a6704def.
The scaffold is now replaced with source; exact source-green evidence remains
pending on PR168. No claim of live deployment or selected product adoption.

First source39238ac ran all400 package tests: the14 new methods passed, while
the existing exact public SDK method inventory required adding the two planned
projection methods. Its set-equality assertion remains strict; no behavioral
assertion was removed. This is source/test API inventory alignment, not a new
contract or unrelated apparatus repair.

Meridian source HOLD5818004839 found the incomplete fresh-profile guard and
invalid-offset normalization. Three focused regression methods were added. The
first checkpoint7bb5a3a was mixed evidence (3 intended failures,6 fixture/compiler
errors). Corrected6194a5b owning CI36027819235/job107728725277 ran403 package
tests with exactly5 intended assertion failures, zero errors;26 policy tests
passed. SHA256:2da12bb14d35e7473ed069835dff7bf65c207d1abe55794ba43c51d31dd52160.
Source now checks the actual full creation plan and explicit timezone components.

The attempted attached/external *node* fixtures hit an existing selected Core
compiler `_add_dependencies` KeyError and are outside this adapter's validated
profile. Supported attached/external *runtime* cases and actual retained node
identities remain executable regressions. The compiler limitation is preserved
on Core1860comment5818088268; it was not repaired, skipped or marked xfail here.

## Handoff

Operations #1860 must change both tunnel delivery generation and recognition to
the file shape, preventing competing environment-token append. It also owns the
original attempt/event join, current authority/fence checks, durable observation
fold and truthful operator continuation for an initially absent sample. Servers
#181 selects reviewed coordinates, #188 owns persistent protected native lifecycle,
and #225 owns bootstrap/API Hello/protected health/empty-graph live acceptance.
