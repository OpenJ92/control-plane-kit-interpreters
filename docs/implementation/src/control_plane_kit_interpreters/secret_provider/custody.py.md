Source: [src/control_plane_kit_interpreters/secret_provider/custody.py](../../../../../src/control_plane_kit_interpreters/secret_provider/custody.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This adapter translates Core custody and exact-version revocation grants into provider-client calls selected through the bootstrap registry. It propagates the grant's workspace, reference, intent, actor and correlation coordinates; returned Core receipts preserve provider version metadata. It does not mint grants or own the Operations journal.

Whole-reference revoke maps a provider MISSING result to already-absent success and verifies reference agreement. That narrow idempotency treatment must not absorb transport or uncertain-mutation errors. Exact-version revocation uses the distinct grant and client operation; replacing it with whole-reference revoke would affect sibling versions. Callers own approval, persistence of receipts, retries and compensation sequencing.

Related source and evidence: [src/control_plane_kit_interpreters/secret_provider/client.py](../../../../../src/control_plane_kit_interpreters/secret_provider/client.py), [src/control_plane_kit_interpreters/secret_provider/bootstrap.py](../../../../../src/control_plane_kit_interpreters/secret_provider/bootstrap.py), [tests/test_secret_provider_client.py](../../../../../tests/test_secret_provider_client.py).
