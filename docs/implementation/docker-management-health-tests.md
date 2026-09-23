# Pinned Docker workload and bootstrap health targets (#162, #164)

Governing [exact plan](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/148#issuecomment-5750611634)
and [target-only release](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/162#issuecomment-5750627936).
Meridian and Kepler approved the workload-only interface/laws. Eight focused tests
cover the selection-to-effect boundary. #162 subsequently passed 26 support and
373 package tests and merged as388282a. Its setup/red sequence below is historical.

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
Unsupported local-ready, connector-connected and legacy tests use protected
inputs that raise on access; #164 adds the two protected bootstrap stages.

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
durable observation folding. Local/native bootstrap observation, production adoption
and legacy HTTP-helper retirement remain parent #148 work; the new entrance must never
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

That gate is now satisfied at `1886f085`: Meridian target PASS and independent
causal-red PASS; ordinary CI35519295967/job106100477511 ran 373 tests with exactly
eight missing-adapter failures and zero errors, alongside 26 green support tests.
The actual default product/compiler/resolver prerequisite succeeded. Log SHA256
`33697a4a9e899c8e29c539259c8f4487b34be582f4ee3a955598eb7c9d98420c`.
Source implementation preserves these target files unchanged.

#164 adds seven bootstrap methods using the actual Core-compiled original
AUTHENTICATED_MANAGEMENT_PATH and GATEWAY_INGRESS_READY stages. The actual
three-artifact gateway and same-app relay/own SDK lifespan exercise READINESS;
independent stage requests and attempts, full pins/ingress, authored side,
wrong signed contexts, original expiry, receiver denial and cancellation retain
their existing owners. Coherent whole-bundle durable stage provenance remains
outside this API and is not claimed by cross-component refusal tests.

The corrected #164 targets at0a8743a reached exactly seven intended assertion
failures with zero errors,373 existing and26 support tests passing in ordinary
CI35806391490. Meridian causal-red PASS is PR165 comment5787410141. The source
atac20918 preserves those targets; full source-green evidence is required.

#164 checkpoint d196433 resolved the dependency conflict but all seven bootstrap
methods errored while constructing signed fixtures. `resign` changed the context
and transit attempt ID while leaving synthetic key-resolution `operation_id`
from the base world. The existing signer correctly rejects that mismatch before
resolving keys. The narrow fixture correction carries the same supplied attempt
into both resolution grants; legacy default attempt-a and all signer/assertion
semantics remain unchanged. Run 35806125926 is setup-only evidence (26 support
and 373 existing package tests passed), not causal observer red. The corrected
fixture must pass setup before missing observer behavior can be credited.
