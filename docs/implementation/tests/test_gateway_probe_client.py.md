Source: [tests/test_gateway_probe_client.py](../../../tests/test_gateway_probe_client.py).
Maintain this companion in the same change when the source or its selected imports change the contract.

`test_signs_exact_grant_and_posts_canonical_request` uses a generated Ed25519
key, a recording secret resolver and `httpx.MockTransport`. It verifies the
outgoing token with the public key, checks its grant and headers, and compares
the decoded POST body to the request descriptor. Its HTTP 200 fixture reports
`passed`. The test asserts both the client code and the returned target evidence.
The [client](../src/control_plane_kit_interpreters/probes/gateway.py.md) also accepts
a well-formed `failed` outcome, but this suite has no direct assertion for that case.

The refusal cases show where effects stop. An untrusted endpoint or a substituted
request never reaches the HTTP handler. A missing or mismatched resolution grant
produces zero resolver and HTTP calls. Provider denial reaches the resolver once
and stops before HTTP. A different resolved signing key also stops before HTTP.

Controlled responses exercise redirect, timeout, oversized body, malformed result
and gateway rejection. The 403 fixture puts private test material in the response
body and checks that only the HTTP status survives in the result. These are client
tests with injected responses. Deployed gateway reachability, receiver replay
enforcement and actual target health require separate evidence.
