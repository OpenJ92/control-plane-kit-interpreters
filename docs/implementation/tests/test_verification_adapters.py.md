Source: [tests/test_verification_adapters.py](../../../tests/test_verification_adapters.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This suite uses scripted Redis/Postgres transports, secret/address resolvers and HTTP responses to test semantic check results. Consequential cases distinguish SELECT 1 readiness from TCP reachability, rejection before credential resolution, HTTP size/redirect limits and public DNS reauthorization on retry. Patched cadence checks verify delays between attempts without spending real time.

An injected query transport accepting a timeout argument does not prove the default driver enforces a query deadline. These tests own adapter policy/outcome evidence; live database, provider and deployment validation are separate.

Related source and evidence: [src/control_plane_kit_interpreters/verification.py](../../../src/control_plane_kit_interpreters/verification.py), [tests/test_verification_timing.py](../../../tests/test_verification_timing.py), [tests/test_public_dns_resolver.py](../../../tests/test_public_dns_resolver.py).
