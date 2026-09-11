Source: [src/control_plane_kit_interpreters/probes/clients.py](../../../../../src/control_plane_kit_interpreters/probes/clients.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This file implements one-attempt TCP, UDP and HTTP health probes and a small graph/subject-correlated endpoint registry. Core owns the closed intent/observation values; the local address-policy owner authorizes the endpoint before network use. Routing uses the typed transport, not the socket label or block class.

TCP proves connection reachability only and closes the acquired connection. UDP requires a nonempty bounded response exchange; send success alone is not reachable evidence. HTTP health streams only to enforce a response-size limit, discards content and interprets status against the intent policy. It disables redirects and environment proxy configuration and preserves public Host/SNI while connecting to the pinned address. Expected refusal, timeout, malformed and unknown outcomes remain distinct. Security rejection propagates rather than pretending a network attempt failed.

These adapters do not persist observations, schedule retry loops or prove application semantics beyond their selected checks. Timeout arguments configure transport operations; no independent whole-operation deadline is implemented here. The static endpoint provider checks returned subject/graph identity but does not establish freshness or discover endpoints.

Related source and evidence: [src/control_plane_kit_interpreters/probes/security.py](../../../../../src/control_plane_kit_interpreters/probes/security.py), [src/control_plane_kit_interpreters/verification.py](../../../../../src/control_plane_kit_interpreters/verification.py), [tests/test_probe_adapters.py](../../../../../tests/test_probe_adapters.py).
