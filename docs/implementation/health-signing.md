# Immediate-use paired health signing (#155)

## #175 preimplementation target interface

The reviewed migration targets change `HealthSigningContext.request` and
`SignedHealthCredentialPair.request` to `ReceiverHealthReadRequest`, and replace
`gateway_node_id` with independent `gateway_target: NodeControlReceiverTarget`.
The existing signer accepts only receiver V2 workload/transit grants through
their Core codecs/predicates. Receiver target/runtime and original request
authority remain separate; signing cannot restamp either or authorize itself.
Construction stays non-authorizing data; actual admission and fixed detached
refusal remain at `sign`. Original key resolution, purposes, window and complete
pair rules below are preserved. At this target checkpoint production is still
old and this successor behavior has not run. The frozen valid obsolete specimen
must continue reaching the real signer and then fail before observed effects.

`probes.health_signing` turns a trusted post-transaction projection of an already
admitted authority pair into two ephemeral compact credentials. Import it
explicitly with the existing gateway crypto extra; the package root stays light.

```python
signer = Ed25519HealthCredentialPairSigner(authorized_resolver, epoch_seconds)
pair = signer.sign(context, transit_grant=preparation.transit_grant,
                   workload_grant=preparation.workload_grant,
                   transit_key=transit_key, workload_key=workload_key)
```

`HealthSigningContext` carries the independently admitted exact request, attempt
wire identity, gateway, declaration and issuers. `HealthSigningKey` carries a
selected public identity and original committed resolution grant. Construction
does not establish current authority. The caller must reload authority through
Operations, retain its original graph/key/interval pins and finish that
transaction before calling the signer. Registration/correlation fingerprints,
approval, revocation, replay and lifecycle remain Operations responsibilities.

Both families are canonicalized and checked before either material read. The
public Core predicates compare the grants against independent context. Both
purposes, resolution intents, workspace/attempt linkage, common actor/session/
run/activity, distinct keys/references and original windows must agree. The
existing authorized resolver receives exactly the original grants; each resolved
Ed25519 key must derive the selected public fingerprint.

The clock is injected and returns integer epoch seconds. Validity is the original
half-open interval `not_before <= now < expires_at`, checked before material work,
between each material/signing stage, and after the second signature. There is no
clock skew, sleep, renewal or implicit retry. In particular, a first-start ceil
timestamp may still be in the future on immediate reload; refusal is correct.
Re-signing keeps the same request/digest/observation identity.

Only the complete `SignedHealthCredentialPair` is returned. It contains the exact
request and two compact ASCII byte credentials in the existing SDK/gateway
formats. The module sends no target HTTP and writes no durable history. A failure
after one provider read returns no partial pair. All effect-boundary failures are
fixed and context-free; reprs redact protected fields. Credentials must never be
placed in descriptors, history or logs. Python memory erasure is not promised.

Tests join the actual selected SDK workload verifier and Servers gateway verifier,
plus real local Secrets API provisioning and Interpreter authorized resolution.
The #158 generation-client tests separately verify both actual provider health
responses and the explicit supported purpose-to-intent mapping. This closes the
old probe-only response limitation without changing this fixture's ownership:
signer fixtures still provision through the provider API directly. Protocol
compatibility does not grant authority to provision keys or complete live setup.

The selected configuration recording witness proves the material-to-SDK bytes and
readonly mount specifications, including digest refusal. Its CPK bytes are static
schema-aligned input, not an executed CPK decoder witness. Actual mounted delivery
and exact disposable cleanup remain #156; #149 stays open. Production lifecycle/
caller composition remains #1860/#181 and relay transport #147/#180.

Governing target-red: PR157, head71f25fa, normal Docker CI35256060980. It ran26
support and347 package tests with exactly7 missing-interface failures and0 errors;
provider/provenance/material prerequisites passed. Full same-target green and
ordinary owner gate are required before acceptance. No real provider, image or
grandparent deployment is part of this change.
