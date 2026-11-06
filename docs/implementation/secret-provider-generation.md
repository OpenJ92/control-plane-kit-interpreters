Current dependency selection (#244): accepted Core
`976901c609d950a557ec1e9966f018e8ff6e16aa`, accepted Secrets #87 / PR #88 merge
`158b17ed10689360c4e1529a395b3ee2b47aecbc`, and its actual SDK
`d61b374cb2a23d773c31748f47f88169499298b7`. Secrets and SDK select this same Core.
This changes only metadata and existing exact provenance coordinates from the
reconciled #242 baseline. Runtime source, the #232 policy client and all 13 policy
tests, assertions, provider fixtures, extras and owning runner are unchanged.
The normal pinned Docker gate owns resolver and package compatibility evidence;
[issue #244](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/244)
records its result. No new signing/sample implementation, image/installation pin,
publication or live acceptance is implied. Earlier notes retain historical coordinates.

# Delegation generation purpose validation (#158)

`secret_provider/client.py` keeps the existing generation request and result
types. The target contract extends its private closed `_GENERATION_INTENTS`
table from the five existing probe/control/health families to the exact
surface-read family, reusing `GATEWAY_PROBE_SIGNING_KEY` as required by Core's
legacy compatibility mapping. `_generation_intent` still rejects untyped values
and unsupported enum members without a fallback or provider import.

`generate_delegation_key` checks this selection before `_request_json`, which
owns credential loading and the single HTTP request. Unsupported purpose is
`MALFORMED_REQUEST/DEFINITE`. `SecretProviderGeneratedDelegationKey` uses the
same selection for response metadata, preserving exact reference, issuer,
purpose and public key bindings. Unsupported or mismatched response metadata
is `MALFORMED_RESPONSE/UNCERTAIN`; existing wire identity and fingerprint checks
remain in the client. No public signature changes. The earlier test dependency selected
accepted Secrets merge `46e0718664c425d002f2420a6ad1f996be62b2c5`, which
admits the same exact pair.

The six added methods in `tests/test_secret_provider_client.py` strengthen the
existing probe/public-identity/error laws with all six supported mappings,
truthful replay flags, credential-before-dispatch refusal, family/identity
substitution, generation-specific one-send timeout/malformed/conflict behavior,
and unsupported result construction. The last method reuses the existing
in-process real provider fixture for both health families and deliberately
replays its original generation correlations. It does not simulate provider
admission or introduce an automatic retry.

Target-red is PR166 at a0c84f59, normal owner CI35881284687: 26 support tests
passed and 386 package tests collected. Six assertion failures and ten bounded
client exceptions expose the missing mapping/preflight behavior. The earlier
f0a38f3 real-client context-manager fixture error was corrected before this
evidence; it is not accepted as causal red.

#220 target-only commit `f0113e6` ran the pinned Docker owner suite against the
previous accepted Secrets pin: all 26 policy tests passed and 592 package tests
ran in 95.095 seconds. Only the new surface-read cases failed (two preflight
errors and nine substitution assertions) because the client sent zero requests.
This localizes the missing client map without claiming provider support. The
source change adds only that map entry; the existing real-provider process
witness selects accepted Secrets #66 and generates surface-read with the legacy
gateway probe intent before verifying private/public correspondence.

Generation remains an explicitly requested provider mutation. Provider scope,
transactions, idempotency and audit remain provider-owned. This client returns
public/reference metadata only; it does not generate or expose private keys,
grant authority, mint registrations, rotate keys or adopt uncertain outcomes.
Ambiguous responses remain uncertain and never cause an automatic retry.
The normal owner gate uses disposable test custody. User live resources and
the #221 protected-input/live-verification boundary remain separate.
