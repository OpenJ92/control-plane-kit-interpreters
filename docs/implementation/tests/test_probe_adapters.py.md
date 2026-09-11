Source: [tests/test_probe_adapters.py](../../../tests/test_probe_adapters.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

Controlled resolver, connector, datagram and HTTP collaborators protect address-policy rejection, public address pinning, secret endpoint resolution timing and transport-specific outcomes. TCP reachability, nonempty bounded UDP exchange and status-driven HTTP health remain separate laws. The router tests exercise the typed transport factor and explicit unsupported behavior.

Redaction assertions inspect selected str/repr surfaces; they are not proof that complete exception chains are secret-free. HTTP mocks and fake sockets establish adapter behavior without proving a live service, DNS authority or runtime graph freshness.

Related source and evidence: [src/control_plane_kit_interpreters/probes/security.py](../../../src/control_plane_kit_interpreters/probes/security.py), [src/control_plane_kit_interpreters/probes/clients.py](../../../src/control_plane_kit_interpreters/probes/clients.py).
