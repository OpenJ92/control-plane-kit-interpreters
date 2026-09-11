Source: [src/control_plane_kit_interpreters/probes/public_dns.py](../../../../../src/control_plane_kit_interpreters/probes/public_dns.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This is the concrete public-address resolver: fresh DNS-over-HTTPS A and AAAA queries, with no local answer cache. It admits an explicitly configured HTTPS resolver URL, disables redirects/environment proxies and bounds streamed response bytes and answer records. DNS message correlation and answer parsing use dnspython; Core probe address policy separately rejects non-global answers before target I/O.

NXDOMAIN returns an empty address result; transport, timeout, oversized and malformed responses remain categorical errors. Answers are deduplicated/sorted, while record limits apply during collection as well as within responses. The configured resolver is a trust input: HTTPS URL-shape validation is not a public-IP policy for the resolver itself. HTTPX's timeout is per transport phase; the two-family resolution has no separately interrupting aggregate deadline.

The resolver returns addresses, not persistent DNS provenance or TTL/freshness evidence. Callers needing renewed truth must call again. The public HTTP verification interpreter does so for each attempt, then authorizes and pins the returned target.

Related source and evidence: [pyproject.toml](../../../../../pyproject.toml), [src/control_plane_kit_interpreters/probes/security.py](../../../../../src/control_plane_kit_interpreters/probes/security.py), [src/control_plane_kit_interpreters/verification.py](../../../../../src/control_plane_kit_interpreters/verification.py), [tests/test_public_dns_resolver.py](../../../../../tests/test_public_dns_resolver.py).
