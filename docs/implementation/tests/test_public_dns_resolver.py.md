Source: [tests/test_public_dns_resolver.py](../../../tests/test_public_dns_resolver.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

Wire-format DNS responses travel through an injected HTTPX transport to exercise A/AAAA collection, deduplication, fresh calls after NXDOMAIN, record/byte bounds, correlation parsing and configuration/error admission. The concrete-verification cases compose that resolver with HTTP verification to prove requery/repinning and zero target requests for non-global answers.

These tests use controlled DNS and target HTTP responses. They protect the same-request resolution/authorization composition but do not validate an external resolver, current public DNS or TLS routing against the Internet.

Related source and evidence: [src/control_plane_kit_interpreters/probes/public_dns.py](../../../src/control_plane_kit_interpreters/probes/public_dns.py), [src/control_plane_kit_interpreters/verification.py](../../../src/control_plane_kit_interpreters/verification.py).
