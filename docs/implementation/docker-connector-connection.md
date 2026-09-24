# Native connection observation (#167)

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
and the exact derived readonly volume. It refuses base/retained resources and
environment token delivery. Source availability is not image publication or live
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
