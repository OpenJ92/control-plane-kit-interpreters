Source: [tests/test_gateway_probe_client.py](../../../tests/test_gateway_probe_client.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This suite generates test Ed25519 material, records authorized resolution and decodes outgoing JWTs through an injected HTTP transport. It checks exact grant/request digest correspondence, canonical POST shape, selected public identity, endpoint rejection before I/O and no signing/network when the credential grant is missing, mismatched or denied. Controlled responses protect redirect, timeout, oversize and malformed-result classifications.

The fixture is client-side evidence. It does not execute the receiver's authorization/replay store or demonstrate deployed gateway reachability. Keep private test material out of claimed public evidence and retain both client result code and probe outcome when extending result assertions.

Related source and evidence: [src/control_plane_kit_interpreters/probes/gateway.py](../../../src/control_plane_kit_interpreters/probes/gateway.py), [src/control_plane_kit_interpreters/probes/security.py](../../../src/control_plane_kit_interpreters/probes/security.py).
