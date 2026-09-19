# Selected signed gateway health transport (#147)

Design: [focused plan](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/147#issuecomment-5743167319),
[independent review](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/147#issuecomment-5743180581),
and [owner disposition](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/147#issuecomment-5743181523).

This target-test stage specifies the missing opt-in `probes.health_transport`
client. Application implementation has not begun. Existing #149 signing and #180
relay contracts are reused; production authority and lifecycle remain Operations
and the #181/#1860 caller's responsibility.

## Governing laws

- **Strengthened — selected destination:** existing gateway/address tests reject
  substitution and pin public DNS. The new client consumes a caller-selected
  named management ingress/gateway/socket/runtime/target alias, requires HTTPS,
  preserves Host/SNI and certificate verification, and dispatches once without
  proxy, redirect, address retry, legacy probe or runtime-private fallback.
- **New-law — original complete pair:** #149 output and independently supplied
  original context/grants must agree before DNS/HTTP. No partial pair, new window,
  renewal, signing, observation allocation or material resolution occurs here.
  Structural congruence does not authenticate signatures or current authority.
- **New-law — real receiver composition:** the actual signer, selected Servers
  relay and SDK verify the protocol and protected callback boundary. This is an
  injected ASGI witness, not TLS, live network or deployed-image evidence.
- **Strengthened — resource bounds:** existing timeout/oversize/redaction laws
  extend to one asynchronous deadline over DNS and HTTP, raw identity-encoded
  response bytes, strict JSON, closure and cancellation. OS DNS can outlive its
  cancelled await; no credential-bearing HTTP is then dispatched.
- **New-law — semantic results:** only HTTP 200 plus the original Core result
  codec yields a health observation. Healthy, unhealthy, unknown and unsupported
  remain distinct; denial/malformed/timeout/transport failures have no semantic
  result. Failure after dispatch is uncertain and never authorizes retry.

`tests/test_health_transport.py` owns these client laws; its independent
prerequisite test sends a genuine signer pair through the existing actual relay
and SDK before the missing client is introduced. Test-only Servers is pinned to
accepted #180 merge `49f50e4df3ec1a380e70f2bddb10b25096c043b7`, installed without
dependency resolution so its historical Interpreter pin cannot replace the
candidate. Existing Core, Secrets and SDK coordinates remain unchanged.

Security: only the selected gateway receives credentials; no server surface or
durable mutation is introduced. Gateway transit denial has zero workload HTTP;
workload signature denial can follow HTTP but has zero protected callbacks.
Secrets, peer bodies, addresses and exception chains must not enter returned
evidence. The production caller derives target aliases from selected relay
configuration; the projection's construction is not permission.

The ordinary pinned Docker PR gate supplies red-to-green and owner validation.
No host Python, local Docker, manual workflow runs, live provider effects, image
publication or downstream work is part of this slice. Legacy route retirement
remains a parent completion requirement.
