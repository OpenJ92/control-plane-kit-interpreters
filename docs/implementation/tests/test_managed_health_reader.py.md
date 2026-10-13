# I189 managed health reader targets

The targets preserve the existing compiler, signer, receiver and public-transport
laws. Eight new methods exercise the composition boundary: signed base/desired
selection, private gateway endpoint/policy refusal before signing, public
selection refusal before key resolution, original expiry/grants, complete-plan
native refusal, bounded local transport and cancellation.

Two socket witnesses are mandatory. A real UVicorn listener hosts the existing
gateway's protected readiness route; the test records exactly one GET with the
original workload bearer and checks server/socket closure. A second listener
hosts the real SDK receiver; the existing gateway relay's actual HTTP client
forwards to it using matching selected route material. Public ingress in that
second witness is explicitly ASGI substituted; the relay-to-receiver hop is real
TCP. Neither witness proves Docker Desktop/remote-daemon routing or public TLS.

Target setup constructs the existing compiled bootstrap/signing fixture before
asserting that the new composition module exists. Initial red may therefore
establish missing interface only; it does not execute the new target bodies.
No owner admission state machine, journal or runtime mutation is emulated.
The owning gate is the unchanged pinned `./test.sh`.

Initial checkpoint `e128b998`, run `38325318834`, failed during fixture setup:
the existing fresh-deployment BootstrapWorld cannot select LOCAL_READY because
the actual compiler emits INGRESS_READY for that branch. All eight new methods
errored before the missing-interface assertion; this is not causal red. The
bounded LocalWorld correction keeps the desired graph, supplies a valid current
snapshot retaining gateway/connector/ingress but not the ordinary workload, and
selects LOCAL_READY from the actual compiler's nonfresh workload-add plan. It
rebinds the original request/attempt signing context and invokes the real
resolver; no operation is invented or stage assertion removed. The existing
469 package tests and 26 support tests passed in the failed run.

Corrected checkpoint `eec3cc7d`, CI `38325771922`, establishes causal red:
26 support tests passed; the package ran 477 tests in 33.753 seconds with eight
failures and zero errors. Each new method constructed the corrected real fixture
then failed on the missing managed-health composition assertion. All 469 existing
tests passed. The new bodies and socket witnesses had not yet executed; source
green remains pending. The eight target methods are unchanged for implementation.
