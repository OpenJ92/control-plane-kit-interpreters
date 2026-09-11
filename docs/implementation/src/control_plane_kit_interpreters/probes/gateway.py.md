Source: [src/control_plane_kit_interpreters/probes/gateway.py](../../../../../src/control_plane_kit_interpreters/probes/gateway.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

## Authority and effects

This client binds a Core delegated gateway grant to the exact request kind, target and canonical request digest, and to a gateway control endpoint with the admitted context/protocol. The Ed25519 signer requires the separate committed secret-resolution grant for the selected private-key reference and signing use. It resolves key material only after those checks, derives the public key and checks its identity/fingerprint before creating the capability JWT. Grant issuance, time/replay enforcement by the receiver and durable operation history remain other owners' responsibilities.

Dispatch authorizes the address before signing, sends the canonical request to /cpk/probes with the CPK-Gateway authorization scheme, disables redirects/environment proxies and preserves public Host/SNI pinning. Streamed response bytes are capped; only selected status and exact decoded result fields are retained. Expected HTTP failures produce closed client result codes; authority/signing failures are errors. The client has phase timeouts and performs no automatic retry or independently timed total deadline.

## Result meaning and limits

SUCCEEDED means the response was admitted as a valid gateway result. Its evidence outcome can be passed or failed; consumers must inspect that field before claiming the target probe passed. Decoding checks exact target/probe/result shape, not a signed response or fresh runtime identity. Result construction admits scalar mappings more broadly than the decoder's selected fields; do not treat the public value constructor as a general-purpose redaction boundary.

Representations hide key/client material and signing failures use bounded messages. The actual request token remains sensitive in memory and transport. Mock-HTTP tests verify cryptographic request shape, grant/key substitution rejection and bounded responses; they do not prove deployed gateway replay protection or end-to-end application acceptance.

Related source and evidence: [pyproject.toml](../../../../../pyproject.toml), [src/control_plane_kit_interpreters/probes/security.py](../../../../../src/control_plane_kit_interpreters/probes/security.py), [tests/test_gateway_probe_client.py](../../../../../tests/test_gateway_probe_client.py).
