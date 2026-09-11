Source: [tests/test_cloudflare_named_ingress.py](../../../tests/test_cloudflare_named_ingress.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This fault-oriented suite supplies controlled Cloudflare transport and secret/custody collaborators. It checks exact request construction, hostname/authority rejection before API I/O, repeated preobservation, race handling, complete versus incomplete DNS reconciliation and compensation restricted to known resources. Closed failure-evidence assertions distinguish mutation uncertainty from cleanup result; selected unexpected mapping exceptions preserve identity unless cleanup failure takes precedence.

The fake's recorded request order and injected failures are the evidence surface. They do not prove actual provider pagination, current API behavior or absence of historical resources. Retained reservation lifecycle laws live in the separate retained suite.

Related source and evidence: [src/control_plane_kit_interpreters/cloudflare/client.py](../../../src/control_plane_kit_interpreters/cloudflare/client.py), [tests/test_cloudflare_retained_reservations.py](../../../tests/test_cloudflare_retained_reservations.py).
