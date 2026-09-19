# Selected signed gateway health transport (#147)

Design: [focused plan](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/147#issuecomment-5743167319),
[independent review](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/147#issuecomment-5743180581),
and [owner disposition](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/147#issuecomment-5743181523).

The opt-in `probes.health_transport` client connects existing #149 signing and #180
relay contracts are reused; production authority and lifecycle remain Operations
and the #181/#1860 caller's responsibility.

```python
client = SignedGatewayHealthClient(clock=epoch_seconds)
result = await client.dispatch(
    context, pair, selected_gateway,
    transit_grant=original_transit, workload_grant=original_workload,
)
```

`SelectedManagementGateway` contains the selected `NamedPublicIngress`, gateway
node, transit provider socket, workload runtime and relay target alias. It is a
caller projection, not proof of selection or permission. `dispatch` validates
that it agrees with the independent context and HTTPS ingress target; it never
derives expected destination/context from a credential. The client structurally
compares each compact token with its original grant and leaves cryptographic
admission to the real receivers. It does not resolve signing material or sign.

The default async system resolver is awaited within the same finite deadline
as HTTP (default and maximum 5 seconds). Empty, malformed, excessive or any
non-global answers are refused; a single deterministic public address is pinned.
The request retains the ingress Host/SNI and ordinary certificate verification.
There is no second hostname lookup, ambient proxy, redirect, retry or fallback.
The original half-open credential window is checked immediately before send.
An injected async resolver/HTTP transport supports controlled composition tests.

`GatewayHealthTransportResult.code == RECEIVED` carries the original-correlated
Core `result`. Every other code carries `None`: invalid-context,
destination-rejected, gateway-rejected, timed-out, transport-failed,
malformed-response or oversized-response. HTTP 400/401/403/413 are gateway
refusals, 504 is timeout, other 5xx are transport failure; no non-200 creates a
semantic observation. Status bodies are not read. HTTP 200 requires raw identity
encoding, at most446 bytes and strict JSON before the Core result codec.
Responses and clients close on success/failure/cancellation. Cancellation
propagates without an invented observation; timeout after dispatch is uncertain.

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

Target-red evidence: PR161 head `e0bf91dd8b7441cf3a3f8a5b3ac1d9e8c260163a`,
ordinary CI35452961597/job105923202492, composition `7e012cf`:26 support tests
passed;365 package tests had only12 missing-client failures and0 errors. The
actual signer/relay/SDK prerequisite and immutable dependency provenance passed.
Corrected target commit `e8c10938e1fb94d4ce6925565fe5a7d1c9e663fa` was reviewed
before source implementation: trailing-chunk/yield-count assertions now isolate
early stream cutoff; otherwise-valid full duplicate JSON isolates duplicate
rejection. These deeper corrected assertions first execute in source-green CI;
the unchanged missing-interface guard made another target-only red run redundant.
Source-green and full owning-gate evidence remain pending on PR161.
