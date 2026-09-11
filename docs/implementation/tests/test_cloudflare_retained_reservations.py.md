Source: [tests/test_cloudflare_retained_reservations.py](../../../tests/test_cloudflare_retained_reservations.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These controlled-provider tests protect the difference between a retained DNS reservation and a tunnel epoch. They exercise exact-record rebind, stale/foreign/missing truth, compensation to the observed old target, deactivation that preserves DNS, and explicit release with absence verification. Transport ambiguity can remain uncertain even when a subsequent observation reports absence; do not replace that assertion with a blanket retry-safe success.

The fixture models provider responses and tracks requests. It does not create public DNS or tunnels. Keep ordinary create/teardown and retained operations distinct when translating or extending these laws.

Related source and evidence: [src/control_plane_kit_interpreters/cloudflare/client.py](../../../src/control_plane_kit_interpreters/cloudflare/client.py), [tests/test_cloudflare_named_ingress.py](../../../tests/test_cloudflare_named_ingress.py).
