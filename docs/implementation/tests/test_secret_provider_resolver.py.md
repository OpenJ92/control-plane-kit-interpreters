Source: [tests/test_secret_provider_resolver.py](../../../tests/test_secret_provider_resolver.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These controlled-provider tests protect exact grant/correlation forwarding, bounded missing/denied mapping, bootstrap/transport failure behavior and rejection of substituted reference metadata. The fixture selects explicit bootstrap references and intercepts HTTP responses; it does not supply evidence that a real server authorized the grant. Preserve the distinction between a negative resolution result and a provider/transport error when changing the resolver.

Related source and evidence: [src/control_plane_kit_interpreters/secret_provider/resolver.py](../../../src/control_plane_kit_interpreters/secret_provider/resolver.py), [src/control_plane_kit_interpreters/secret_provider/client.py](../../../src/control_plane_kit_interpreters/secret_provider/client.py).
