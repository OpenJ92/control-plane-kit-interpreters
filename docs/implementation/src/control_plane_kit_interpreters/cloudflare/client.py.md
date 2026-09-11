Source: [src/control_plane_kit_interpreters/cloudflare/client.py](../../../../../src/control_plane_kit_interpreters/cloudflare/client.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

## Owned boundary

This module interprets Core named-public-ingress intent through Cloudflare tunnel/DNS operations. Zone authority constrains hostnames and identifies the API-token reference; exact secret-resolution and token-custody grants are required at the interpreter boundary. Core contracts are consumed at pyproject.toml's pin. Grant admission and durable operation history remain upstream responsibilities. The low-level API client is an effectful primitive, not a replacement for that authority boundary.

Creation preobserves the exact hostname, allocates/configures a tunnel, reobserves before DNS mutation, obtains the tunnel token and stores it through the custodian. The allocation returns resource IDs, endpoint and custody receipt, not the token. DNS-create transport ambiguity can adopt only the narrowly admitted complete exact-record reconciliation. Unknown ownership or incomplete reconciliation withholds cleanup rather than guessing a resource by name.

## Retention and failure meaning

Retained rebind updates one recorded reservation for a new tunnel epoch and verifies its target. Compensation may restore the previous target only under the observed conditions implemented by _restore_rebind_reservation. Deactivation revokes custody and removes connections/tunnel while verifying the reservation remains; release separately deletes that exact reservation and verifies absence. These operations are not interchangeable with teardown, which attempts all recorded custody/DNS/connection/tunnel cleanup stages and reports failures without providing the same final absence observations.

Creation exposes closed stage/category/mutation-certainty/cleanup evidence. Other operations retain their own bounded error paths; do not imply every method returns the creation evidence algebra. Cleanup failure can take precedence over the triggering error, and a lost provider receipt can leave mutation uncertain. No cross-provider transaction or automatic general retry exists. Durable recording, recovery policy and user approval belong to the composing control plane.

## Transport and evidence limits

The low-level client sends bearer authentication to the fixed Cloudflare API base, hides raw transport exception text, and reports bounded API status errors. HttpxCloudflareTransport loads HTTPX lazily and supplies a phase timeout; unlike the Secrets client, it does not implement its own streamed response-byte cap or total elapsed-time budget. Do not copy stronger bounds from another adapter into this companion.

Fake transport/custodian suites protect preobservation races, ambiguous DNS reconciliation, exact-owned compensation, grant rejection and retained reservation behavior. They do not attest to current Cloudflare state, deployed token custody, or success of a user deployment. A source/documentation review authorizes no provider call.

Related source and evidence: [pyproject.toml](../../../../../pyproject.toml), [src/control_plane_kit_interpreters/secret_provider/custody.py](../../../../../src/control_plane_kit_interpreters/secret_provider/custody.py), [tests/test_cloudflare_named_ingress.py](../../../../../tests/test_cloudflare_named_ingress.py), [tests/test_cloudflare_retained_reservations.py](../../../../../tests/test_cloudflare_retained_reservations.py).
