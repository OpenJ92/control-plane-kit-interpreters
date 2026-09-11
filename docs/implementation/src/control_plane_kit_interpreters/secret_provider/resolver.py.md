Source: [src/control_plane_kit_interpreters/secret_provider/resolver.py](../../../../../src/control_plane_kit_interpreters/secret_provider/resolver.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This is the grant-only bridge from Core AuthorizedSecretResolver to the concrete provider client. It selects endpoint and credential by exact registered references and forwards the grant's workspace, secret reference, use intent, actor and correlation. It returns a Core SecretResolved carrying the provider metadata reference and SecretValue; it does not infer authority from a hostname or legacy secret lookup.

Provider MISSING becomes SecretMissing; DENIED and REVOKED become SecretDenied. Bootstrap and transport failures remain errors rather than absence. The resolver's representation is redacted. The client owns response-identity and plaintext decoding checks, while admission of the grant and durable effect history belong to the caller's authority/persistence owners.

Related source and evidence: [src/control_plane_kit_interpreters/secret_provider/client.py](../../../../../src/control_plane_kit_interpreters/secret_provider/client.py), [src/control_plane_kit_interpreters/secret_provider/bootstrap.py](../../../../../src/control_plane_kit_interpreters/secret_provider/bootstrap.py), [tests/test_secret_provider_resolver.py](../../../../../tests/test_secret_provider_resolver.py).
