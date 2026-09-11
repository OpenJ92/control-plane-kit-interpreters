Source: [src/control_plane_kit_interpreters/verification.py](../../../../src/control_plane_kit_interpreters/verification.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

## Owned checks and composition

This file executes Core HTTP status, Redis PING and PostgreSQL SELECT 1 checks. VerificationCheckMaterial correlates node/graph/socket coordinates before execution. The interpreters advertise their own capabilities and return Unsupported for another check kind; the caller owns planning, durable history and decisions based on the result. Core check/result contracts are consumed at pyproject.toml's pin.

All transports use the address-policy owner. HTTP public endpoints are freshly resolved and authorized on every attempt; unresolved DNS can retry, but non-global/untrusted admission stops without target HTTP. Private HTTP, Redis and PostgreSQL authorize before their retry loops, so the public HTTP re-resolution guarantee must not be generalized to all checks. The shared timing iterator supplies attempt count and delay only between attempts, and success stops further attempts.

HTTP keeps status and bounded body-size evidence, discards the body and rejects redirects/overflow. Redis sends exactly RESP PING and requires exact PONG bytes; it returns size evidence, not payload. PostgreSQL resolves credentials after endpoint admission and executes the fixed SELECT 1 query. The authorized credential path requires its exact password-use grant and does not fall back when that grant is missing or denied. A separate legacy resolver path remains when no authorized resolver was supplied; callers select the intended mode explicitly.

## Limits an editor must preserve

These are semantic checks, not merely TCP reachability. Network activity and credential use occur here, but arbitrary SQL or user-selected Redis commands do not. HTTPX/socket phase timeouts and attempt cadence do not establish a total wall-clock deadline. The default psycopg transport supplies connect_timeout but sets no statement_timeout, so the SELECT 1 call is not independently deadline-bounded by this implementation. Its wrapped failure also retains the underlying exception as cause; bounded result evidence is not a blanket promise about raw traceback disclosure.

Tests use injected HTTP/Redis/Postgres/resolver collaborators for outcome, admission and retry laws. The local source review and these test definitions are not evidence of fresh database or deployment execution.

Related source and evidence: [pyproject.toml](../../../../pyproject.toml), [src/control_plane_kit_interpreters/probes/security.py](../../../../src/control_plane_kit_interpreters/probes/security.py), [src/control_plane_kit_interpreters/timing.py](../../../../src/control_plane_kit_interpreters/timing.py), [tests/test_verification_adapters.py](../../../../tests/test_verification_adapters.py), [tests/test_public_dns_resolver.py](../../../../tests/test_public_dns_resolver.py).
