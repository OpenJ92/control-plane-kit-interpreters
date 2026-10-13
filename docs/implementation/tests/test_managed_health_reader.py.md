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
