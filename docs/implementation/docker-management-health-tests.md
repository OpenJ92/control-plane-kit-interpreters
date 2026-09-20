# Pinned Docker workload health targets (#162)

Governing [exact plan](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-5750611634)
and [target-only release](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/162#issuecomment-5750627936).
Meridian and Kepler approved the workload-only interface/laws; source is not yet
implemented. Eight focused tests cover the selection-to-effect boundary.

`docker_management_health_fixtures.ManagedWorld` extends the existing real signer,
relay and SDK fixture. It constructs the actual Servers #182 three-artifact source
contract and copies its verification, surfaces, capabilities, artifacts, provider
ports and transit declaration into a validated graph without modifying them.
The real Core compiler selects the workload operation; the real resolver validates
it. Fixture construction happens before the missing-module assertion, so causal
red must also establish that this selected contract and graph compile. Deeper
variant assertions remain unexecuted until application implementation exists.

The base-side fixture deliberately places a base-side operation in a small explicit
plan and passes the actual resolver. This tests supported base-side interpretation;
it does not claim the initial-deployment compiler emits base-side observations.
Current/desired graph values may be equal while authored revisions differ. Tests
check wrong-side rejection followed by a successful original revision.

New laws join actual plan selection, source authored identity, original signing
context and public gateway destination. Strengthened laws retain four semantic
outcomes, categorical failures, cancellation and bounded redaction from #147.
Otherwise-valid signed pairs for another target/context isolate pre-I/O selection
rejection. Complete ingress comparisons include authority, connector, target,
hostname and lifecycle; HTTPS is currently the sole exposure enum member.
Unsupported bootstrap/legacy tests use protected inputs that raise on access.

The eight tests are: real selected kind/four outcomes; base/desired authored
identity; plan/graph/relation/full-ingress mismatches; independently signed wrong
context/destination; non-Docker/missing-surface refusal; early unsupported
bootstrap/legacy refusal; original expiry/receiver denial/post-send timeout;
cancellation/closure/redaction. No fake observer or duplicated Operations state
machine provides successful evidence. Network behavior uses the real #147 client
with its existing injected HTTP transports.

The test-only Servers coordinate changes from accepted #180 `49f50e4` to accepted
#182 `127b7cbf9ae33ae05edbb01e9b610b518e824b90`, keeping `--no-deps`. The existing
exact provenance assertion advances with it. Core, Secrets, SDK and production
dependencies are unchanged. No historical image is promoted or qualified.

Validation must be ordinary pinned PR CI running the unchanged owning gate. No
host tests/imports, local Docker or manual workflow is authorized. Expected red:
eight explicit missing `docker.management_health` assertion failures, no collection,
fixture or apparatus error. Record actual results before source release.

Security/history: protected data remains ephemeral; refusals contain only a closed
code. Tests do not establish current production admission, alias provenance or
durable observation folding. All three bootstrap stages, production adoption and
legacy HTTP-helper retirement remain parent #148 work; the new entrance must never
use those helpers. Existing legacy behavioral tests remain unchanged.

Initial target head `182f271` ordinary CI35518925141/job106099502885 is **not causal
red**: all eight new tests errored during `desired.require_valid()` because the
fixture's BlockSpec role IDs did not match its graph node IDs. Core's actual
GraphDescriptorCodec correctly rejected those identities. The existing 365
package tests and 26 support tests passed; integrity counted 373/38 mocks/0 skips.
No new target test body or downstream gate witness ran after the fixture failure;
the missing-adapter assertion was not reached.
Log SHA256 `f7d35533ff03c45100f5f77dc6517afac8087f471d295a3a73633c55c978b8f7`.

The target-only correction aligns all three role IDs and makes the shared actual
SDK fixture install callbacks only for declared health kinds. Meridian identified
the latter deeper defect: a liveness-only declaration must not install readiness.
Keep that narrowed declaration so the real compiler selects liveness. Prior #147
fixtures declare both kinds and retain their original behavior. All eight target
bodies and the missing-adapter guard remain unchanged. The corrected target needs
ordinary automatic CI to establish actual missing-behavior red, plus delta review.
