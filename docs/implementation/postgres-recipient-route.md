# PostgreSQL recipient-route observation (#2089)

Private native helper, not a SQL result, authorization owner or public protocol.
Prepared Core/Ops original-check inputs remain the authority boundary.

Strengthened laws: inspect one selected network, at most64 listed IDs, exactly
those containers; unknown/incomplete/empty/duplicate route ownership refuses.
The expected gateway and installed recipient must be observed on that exact
network. Both must be running with observed process StartedAt; other members
need complete per-network name/alias/address facts. Gateway multi-network DNS
ambiguity refuses rather than scanning other networks. Read the network again
after bounded member reads; membership must still match. Compare private before/
after snapshots explicitly, including StartedAt and aliases which ordinary SDK
snapshot equality intentionally omits. No private addresses enter repr/errors.

The interpreter supplies an original-check deadline and checks it around each
SDK read. Expiry, malformed provider facts or a slow read means unavailable;
there is no retry or successful observation. This does not make Docker reads
atomic or attest a packet responder. North accepts the trusted local daemon and
controlled network for this demo; no fleet inventory or stronger attestation is
claimed. Product/image/config/selected-byte verification and existing V2 health
signing must still happen in the enclosing reached-check adapter before PASSED.

Tests use actual SDK normalization with external Docker resources doubled;
there are no fabricated Operations rows, invocations, plans or public history.
The initial fail-closed stub establishes behavioral red for the missing route
observation, not an import/collection failure. Owning Docker test.sh is the only
executable validator. North released exact base
`36d45ef956932f32eee3b73375d0c6dca66f6773` after26 support+742 package tests on
Core054e and pinned ordinary SDK/import/cleanup witnesses passed, with source
review. Global source adoption/pins/live deployment are outside this slice.
No persistence, new network exposure, secret
read/write, mutation or cleanup behavior is introduced by this helper.

Red source checkpoint `0fd049a` collected749 package tests. Three new helper
positive-path cases errored at the deliberate fail-closed stub; imports and
negative-case collection succeeded. The gate also failed the unchanged HTTP
timeout-plus-interval law (UNCERTAIN vs SUCCEEDED). This is not unrelated green.
Red log SHA256:
`b27cb1d17319a5637656ed3a9a99e797448193bb55925ff71405357dc03490e2`.
North accepted the stop and requested a bounded test-only observation before
classifying the old failure. The next owning gate adds only failure diagnostics
to that one HTTP law: native/transport guard function+line, exception type,
dispatch code and synthetic numeric times. No headers, tokens, secret bytes,
private keys or payloads; no clock/deadline change or assertion weakening.
The original failure lacks these observations, so its cause is not inferred.

Observed01 completed owning-gate PASS:26 support+749 package tests/112.836s,
pinned import/SDK and exact cleanup. SHA256:
`6d59cca59b4334f66e4dd15ba9b875419f9a1c1875aff279f08aa3901c23bccc`.
The timing assertion passed, so no failing branch was observed; its historical
failure remains unexplained. This PASS does not override the source HOLD below.

Independent review found two false positives in9fc8716: treating an IP-looking
alias as literal-address ownership, and ignoring a peer's configured hostname
when considering DNS competition. Docker's [endpoint name builder](https://github.com/moby/moby/blob/v28.5.1/daemon/container_operations.go#L595-L611)
includes configured hostname/short ID beyond aliases; the [API1.45 schema](https://github.com/moby/moby/blob/v26.1.5/api/swagger.yaml#L2486-L2498)
also defines network-qualified names. The bounded fix accepts only the exact
ordinary single-label authored node DNS alias used by this installation's Docker
interpreter, rejects literal/numeric/local names before any SDK read, and uses
only actual per-network `dns_names` for matching all selected participants.
Missing DNSNames never falls back to resource names/aliases; explicit snapshots
also include that field. No IP routing or DNS-name synthesis is introduced.

Literal target-red reproduced eight rejected-host false positives; log SHA
`7452367f53a662cc4bd4914a469bea4a153a248a976506330cb16af1c69c7720`.
That run additionally rejected a test's attempted localhost graph reference at
Core's public-material boundary; the invalid fixture construction was removed.
The valid original-target/localhost-origin negative remains. New raw Docker
fixtures also cover a peer's hostname-only DNSNames collision, missing/empty
target DNSNames and DNSNames drift. Full successor validation and rereview remain
required before this observer can be selected; metadata evidence is not SQL.

Corrected consumer owning gate completed exit0:26 support+756 package tests in
94.829s on exactCore054e, with Lin's reviewed/tested DNSNames base
`db5db6b9f726c2ce5b252b59b4124a0db85b264b`. Separate pinned API1.45 SDK witnesses
confirmed reported DNSNames and exact owned cleanup. Consumer log SHA256:
`0869d597bbc097b431ce448f53b753a05a0ab797fd622008bce416e0f1d0b96c`.
Independent rereview is still required;9fc8716 is not released by that receipt.
The corrected supported path also requires the intended node name in its actual
Aliases while considering **all** participants' DNSNames for collisions. Numeric,
dotted and reserved origin tests include legal matching Core target IDs, so a
target-ID inequality alone cannot satisfy them. Core itself rejects localhost
and canonical IP graph references. Pre/post deadline checks refuse late reads;
they do not cancel a blocking SDK call or promise tighter return latency than
the underlying SDK timeout. The enclosing check must use one remaining original
monotonic budget for both snapshots and bounded provider I/O.
