Source: [src/control_plane_kit_interpreters/secret_provider/__init__.py](../../../../../src/control_plane_kit_interpreters/secret_provider/__init__.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This facade exposes the bootstrap registry, provider client, grant resolver and custodian from their owning modules. Importing the facade does not select credentials or send requests. Keep exports coordinated with those owners and the package's optional dependency boundary; the provider client imports its HTTP dependency when this surface is loaded.

Related source and evidence: [src/control_plane_kit_interpreters/secret_provider/client.py](../../../../../src/control_plane_kit_interpreters/secret_provider/client.py), [src/control_plane_kit_interpreters/secret_provider/bootstrap.py](../../../../../src/control_plane_kit_interpreters/secret_provider/bootstrap.py), [tests/test_secret_provider_client.py](../../../../../tests/test_secret_provider_client.py).
