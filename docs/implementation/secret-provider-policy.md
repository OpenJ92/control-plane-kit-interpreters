# Fixed Secrets policy client (#232)

`secret_provider/policy.py` implements Core's five synchronous typed methods:
grant, revoke, grant read, one-page list and command-result read. Construction
binds a separately admitted fixed endpoint, credential and logical/provider
identity. The client owns transport mapping only; callers retain admission and
durable command history, and Secrets retains policy, revisions and replay.

Requests contain only E's closed coordinate, expected revision and persisted
correlation. They never forward CPK actor, idempotency key, endpoint or credential
fields in the body. Canonical responses preserve provider actor, exact provider,
correlation, tuple and revision, and the provider-issued grant identity. Revoke
also verifies the requested grant ID. Current grant reads remain distinct from
historical command results. Lists return one current filtered, unrevoked,
ordered page with a consistent cursor; no multi-page snapshot is promised.

Shared transport owns credential loading, request/response/time limits and
response closure. Each method makes at most one request. Redirect following,
retry, automatic command-result lookup, fallback endpoints, auto-pagination and
compensation are excluded. Failures use fixed bounded text without raw exception
context. Recognized HTTP refusals remain noncanonical failures. HTTP 409 does
not become a canonical conflict: a separately authorized command-result read
can supply that evidence. Transport loss, malformed or unsupported mutation
responses retain possible effects; failed reads do not settle an earlier
mutation. Operations retains the original intent for matching and reconciliation.

Each GET adds a fresh audit-only `cpk-policy-read.<uuid>` header, separate from
the persisted mutation correlation. It is transport metadata, not a new durable
local command identity or an asserted CPK/read-audit join. E limits mutation
correlations and read audit headers to 128 characters; command-result URL targets
retain the distinct 512-character limit. No truncation or rehashing changes
command identity. Invalid request/binding/correlation checks precede credential
loading and transport.

The selected Core port is accepted
`c7b16007467085be997f8dc3025e90e78649b00a`. Normal test fixtures use Secrets
`cf2827a73c6b7b082aa5942904fd7b8f92da690d` and SDK
`3192360c36934feadc37bb9ae3733ce7da755c31`, preserving existing fixture behavior.
Accepted E `adf58aae75d5616e6ea262ad223672afdb10bb26` is the wire-contract source,
not an adopted policy process fixture. No Core7af adoption or E fixture migration
is included; Servers/G retain their separate composition and process evidence.

The unchanged Docker `./test.sh` is the owning gate. Public adapter tests use
synthetic HTTP transport for exact encoding, returned identity, bounds, redaction,
request counts, mutation uncertainty and read/page semantics. They do not
reimplement provider CAS, persistence, admission or Operations command history.

The original mapping and tests were introduced together without preimplementation
red evidence, a recorded deviation from the planned test-first loop. Checkpoint
`6666067` supplied actual failures for missing audit headers and bounded 422
mapping; `68d726f` passed those cases and exposed unsupported error-envelope
mutation certainty through three new failing subtests. The corrected `dd64e26`
retains that uncertainty. The cursor negative case uses a full valid page so
cursor mismatch is independently tested. Exact gate results, reviews and
remaining acceptance boundaries belong to the [#232 decision log](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/232).
