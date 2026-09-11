Source: [src/control_plane_kit_interpreters/secret_provider/client.py](../../../../../src/control_plane_kit_interpreters/secret_provider/client.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

## Owned boundary

This is the concrete HTTP interpreter for the CPK Secrets API: write, resolve, revoke, exact-version revoke and delegation-key generation. It consumes Core secret/key values at the version selected in pyproject.toml; the test extra selects a separate exact Secrets source revision. A dependency adoption must recheck wire shapes against that consumer pin, including metadata identity and public-key projection. The client does not own authorization policy, durable audit storage or retry scheduling.

The full secret reference is injectively encoded as one provider path segment. Requests carry workspace, actor and correlation identities. Successful responses are admitted against exact shapes and expected workspace/reference/status; exact-version revocation also checks the returned version identity/number. Write/revoke results expose metadata, resolve wraps admitted UTF-8 plaintext in SecretValue, and generation returns public-key/reference metadata. Redacted representations do not remove plaintext from in-memory request and decoding buffers.

## Effects, errors and limits

Each request rereads the configured credential file with a size cap and restricted ASCII-token grammar, then creates a scoped HTTP client and sends bearer authentication. File reading does not enforce mode, owner or no-symlink rules. Bootstrap/provisioning must supply the intended protected file. Redirect following is explicitly disabled. Response size is checked against declared and streamed bytes; content type, JSON and response identity are validated before admitting results.

HTTPX phase timeouts accompany an elapsed-time check during/after streaming. That check is not an independently interrupting hard wall-clock deadline. Expected transport failures become bounded categorical errors without raw provider bodies. For mutation, transport failure, oversized/malformed success and relevant server failures retain uncertain outcome certainty. A later error does not prove the provider made no change. This module performs no automatic retry or compensating mutation; correlation semantics and durable reconciliation belong to the provider and caller.

## Evidence

The mock-transport suite covers exact shapes, credential rereads, identity substitution, limits and definite/uncertain outcomes. The live-provider suite exercises the pinned Secrets process and local SQLite audit correlation through loopback HTTP. Neither establishes Cloudflare or deployed grandparent/child acceptance. Documentation work ran neither suite.

Related source and evidence: [pyproject.toml](../../../../../pyproject.toml), [src/control_plane_kit_interpreters/secret_provider/bootstrap.py](../../../../../src/control_plane_kit_interpreters/secret_provider/bootstrap.py), [tests/test_secret_provider_client.py](../../../../../tests/test_secret_provider_client.py), [tests/test_live_secret_provider_client.py](../../../../../tests/test_live_secret_provider_client.py).
