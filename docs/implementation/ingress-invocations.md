# Named ingress semantic invocations (#226)

`CloudflareNamedIngressInterpreter.create` and `teardown` accept the composing
application's keyword-only `invocations` port. Dynamic composition selects
`require_invocations=True`; absent or malformed ports refuse before token reads.
The port must provide the closed control base, admission, secret outcome recording
and nonsecret `record_result`. No Operations import, store or policy moves here.
Other ingress methods remain unenrolled; separately trusted no-port create/remove
retain their existing legacy behavior.

Create prepares the exact API-token grant and acknowledges its raw resolver sum.
It then admits provider creation before exact hostname observation, tunnel/config/
DNS creation and token retrieval. The extracted provider sequence retains its
existing bounded cleanup and DNS reconciliation. Only an acknowledged
`provider-created` result permits the separately admitted custody write. A valid
active exact Core custody receipt must match its grant, have a true-integer version
in 1 through 2^53−1 and bounded reference metadata before its descriptor is recorded.
The allocation return does not perform Operations' durable fold.

Dynamic custody errors, malformed/inactive receipts and failed acknowledgements
stop without entering legacy compensation. The created tunnel/DNS/token are not
retried, revoked or deleted under the earlier create admission. This preserves
the accepted #1120 partial-allocation limitation: known results can remain partial,
with separately authorized recovery required and no newly invented Remove route.

Remove resolves/acknowledges its token, admits custody revoke, requires a None
return and acknowledges it, then admits provider removal. The existing exact
DNS/connections/tunnel stages run only inside that provider unit. A custody failure
or acknowledgement error prevents every delete. Ordinary provider cleanup failures
still attempt all three exact stages and record a bounded ordered failure list.
Operations owns REMOVING and the later durable fold, not this adapter.

Nonsecret units use closed version-1 result dictionaries: provider-created IDs;
provider-create-stopped stage/category/mutation/cleanup/IDs/provenance; unclassified
creation uncertainty; custody receipt or returned revoke; and returned removal or
unknown custody/removal reason. No token, raw provider body, exception text or
arbitrary result object enters these records. Existing provider failure evidence
maps to failed unless mutation or cleanup is uncertain, in which case it maps to
unknown. Unclassified provider exceptions remain unknown.

DNS IDs observed before mutation or on failed DNS creation are observed-only.
Owned provenance begins at successful exact DNS creation or the existing complete
qualifying transport reconciliation. It survives a later token-fetch failure and
its cleanup result. Matching a target alone never grants ownership.

Dynamic creation validates each returned tunnel/DNS identifier immediately after
its provider response and before dependent calls or result recording. Invalid
identifiers produce a bounded unclassified unknown result without becoming cleanup
targets. Provider failures are captured as values before cleanup runs, so a later
closed control cannot inherit the earlier provider exception as its context.

The supplied control base crosses token resolution, HTTP transport, provider
handlers and exact cleanup unchanged, before generic catches. Admission and result
recording are outside provider compensation handlers; failed recording causes no
second write, retry or cleanup. Non-Exception interruptions attempt one bounded
unknown result record and remain primary even if that record fails. No durable
acknowledgement is claimed when recording fails.

The owning `./test.sh` covers actual adapter wrappers with provider doubles and
the ordinary local Docker witnesses. This source does not establish live Cloudflare
behavior, downstream composition, deployment or provider-contract acceptance.
