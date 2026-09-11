Source: [tests/test_secret_provider_client.py](../../../tests/test_secret_provider_client.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This suite uses temporary credential files and injected HTTPX transports to exercise the provider client, bootstrap registry and custodian. Its consequential cases distinguish exact-version from whole-reference revoke, injective reference encoding, substituted metadata/public identity, credential rereads, bounded failures and uncertain mutation outcomes. A malformed successful mutation response must not become evidence that no mutation happened.

The tests inspect generated requests and controlled responses; they do not contact a deployed provider or prove its authorization/database semantics. Keep that evidence boundary when adopting Core/Secrets pins. The separate live-provider suite owns real local process and audit checks.

Related source and evidence: [src/control_plane_kit_interpreters/secret_provider/client.py](../../../src/control_plane_kit_interpreters/secret_provider/client.py), [src/control_plane_kit_interpreters/secret_provider/custody.py](../../../src/control_plane_kit_interpreters/secret_provider/custody.py), [tests/test_live_secret_provider_client.py](../../../tests/test_live_secret_provider_client.py).
