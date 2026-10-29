# Fixed Secrets policy client (#232)

The accepted Core port comes from `c7b16007467085be997f8dc3025e90e78649b00a`.
The normal test fixture cohort uses Secrets
`cf2827a73c6b7b082aa5942904fd7b8f92da690d` and SDK
`3192360c36934feadc37bb9ae3733ce7da755c31`, preserving the existing provider
fixture. Accepted Secrets E `adf58aae75d5616e6ea262ad223672afdb10bb26` is the
policy wire-contract source, not an adopted process fixture.

`secret_provider/policy.py` implements Core's five synchronous typed methods
against one separately admitted fixed endpoint/credential/provider binding.
The caller owns authorization and durable command history. The client serializes
only E's closed coordinate/revision/correlation body; it does not forward CPK
actor, idempotency, endpoint or credential fields. Canonical responses preserve
provider actor, provider-issued grant identity and exact command correlation.
Revoke additionally verifies the requested grant ID. Read/list never invent
current policy from a past command result. Lists return one bounded ordered page.

Shared transport owns credential loading, request/response/time limits and
response closure. Policy errors are fixed, bounded and redacted. A lost mutation
reply remains ambiguous. HTTP 409 is not canonical evidence and never causes an
automatic command-result read. Each method makes at most one request, with no
redirect following, retry, alternate endpoint or pagination. Operations owns
separately admitted readback and retains the original intent for matching.

GET audit correlation is transport-only metadata, separate from persisted
mutation correlation. Mutation correlations and audit headers are limited to 128
characters by E, while command-result URL targets retain Core/E's 512-character
limit. No truncation or rehashing changes durable command identity.

The initial mapping checkpoint deliberately retains the existing transport,
which lacks a policy GET audit header and bounded 422 mapping. The new public
adapter tests expose those missing transport behaviors; this checkpoint is
unvalidated and not feature acceptance. Validation must use unchanged Docker
`./test.sh`. No new provider process proof, fixture migration, live provider
operation, credential inspection or image publication is included.

The first owning gate at `6666067` passed 26 support and 702 of 704 package tests;
the audit-header and bounded-422 cases failed as predicted. These two paths are
now corrected, pending validation. No preimplementation red exists for the other
new mapping laws; this test-first deviation is explicit in the issue decision log.
Meridian additionally identified unknown mutation error-envelope certainty. A
public-adapter regression is added before correcting that defect, and the cursor
negative case now uses a full valid page so it cannot be masked by page length.

Checkpoint `68d726f` then passed 26 support and 704 of 705 package test methods;
three subtests in the new malformed-error-envelope method failed before its fix.
GET audit headers, bounded 422 mapping and the isolated cursor case passed.
The correction retains mutation ambiguity for every unsupported/malformed
policy error mapping even when the shared secret-data error was definite.
Recognized policy refusals and GET semantics are unchanged. Full owning-gate
acceptance remains pending the corrected checkpoint.
