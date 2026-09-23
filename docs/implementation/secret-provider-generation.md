# Delegation generation purpose validation (#158)

`secret_provider/client.py` keeps the existing generation request and result
types. Its private closed `_GENERATION_INTENTS` table maps the three existing
probe/control families explicitly and uses Core's `health_signing_intent_for`
for the two health families. `_generation_intent` rejects untyped values and
unsupported enum members without a fallback or provider import.

`generate_delegation_key` checks this selection before `_request_json`, which
owns credential loading and the single HTTP request. Unsupported purpose is
`MALFORMED_REQUEST/DEFINITE`. `SecretProviderGeneratedDelegationKey` uses the
same selection for response metadata, preserving exact reference, issuer,
purpose and public key bindings. Unsupported or mismatched response metadata
is `MALFORMED_RESPONSE/UNCERTAIN`; existing wire identity and fingerprint checks
remain in the client. No public signature or dependency coordinate changes.

The six added methods in `tests/test_secret_provider_client.py` strengthen the
existing probe/public-identity/error laws with all five supported mappings,
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

Generation remains an explicitly requested provider mutation. Provider scope,
transactions, idempotency and audit remain provider-owned. This client returns
public/reference metadata only; it does not generate or expose private keys,
grant authority, mint registrations, rotate keys or adopt uncertain outcomes.
Ambiguous responses remain uncertain and never cause an automatic retry.
The normal owner gate uses disposable test custody. User live resources and
the #221 protected-input/live-verification boundary remain separate.
