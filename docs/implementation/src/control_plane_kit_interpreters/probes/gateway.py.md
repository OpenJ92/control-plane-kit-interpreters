Source: [src/control_plane_kit_interpreters/probes/gateway.py](../../../../../src/control_plane_kit_interpreters/probes/gateway.py).
Maintain this companion in the same change when the source or its selected imports change the contract.

## What a successful dispatch means

`GatewayProbeClientCode.SUCCEEDED` means the client accepted the gateway's response.
Read `result.evidence["outcome"]` to learn what happened at the target. For example, a
gateway can return HTTP 200 with a valid `http-status` result reporting `failed`,
target status 503 and a body size of zero. The client returns `SUCCEEDED` with
`outcome="failed"` and `http_status=503`. A gateway that itself returns HTTP 503
produces `TRANSPORT_FAILED`. On that path `http_status` describes the gateway.

After a 2xx response, `_decode_result` checks that the decoded fields match the
request's target and probe kind, the outcome is `passed` or `failed`, and any
HTTP status and body size are in range. Response signatures and observation
freshness are outside these checks.

## Authority and transport

`SignedGatewayProbeClient.dispatch` matches the request kind, target and canonical
digest to the delegated grant. It checks the gateway's HTTP control endpoint and
applies the [address policy](../../../../../src/control_plane_kit_interpreters/probes/security.py)
before signing. The signer checks the workspace, operation and probe IDs and the
grant for the exact private-key reference and signing intent. It resolves the key
and checks the derived Ed25519 public identity against the selected key before
signing the grant. Core owns the request digest and secret-grant contracts.
See the [selected dependency](../../../../../pyproject.toml).

The client sends the canonical request descriptor once to `/cpk/probes` with the
`CPK-Gateway` authorization scheme. It disables redirects and environment-derived
proxy settings, carries the public endpoint's Host and SNI when provided, and caps
the response bytes it accepts. HTTPX enforces per-phase timeouts. Receiver replay
enforcement and durable operation history belong to their respective owners.

See the [client test companion](../../../tests/test_gateway_probe_client.py.md) for
the cases exercised through the injected transport.
