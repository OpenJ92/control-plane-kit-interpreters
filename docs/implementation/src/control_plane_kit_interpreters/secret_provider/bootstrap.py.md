Source: [src/control_plane_kit_interpreters/secret_provider/bootstrap.py](../../../../../src/control_plane_kit_interpreters/secret_provider/bootstrap.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This module admits local bootstrap coordinates: opaque provider/credential references select a normalized HTTP(S) base URL and an absolute credential-file path. The registry copies nonempty mappings into immutable views. Missing exact references fail; it does not discover endpoints, fall back to another credential, read a credential file, or authenticate the caller.

The configuration rejects URL user information, query/fragment and non-root paths and redacts its representation. It permits HTTP as well as HTTPS. An absolute path is a coordinate, not proof of file ownership, permissions or trustworthy contents. File admission and request-time reading belong to the client; provisioning and protecting that file remain the composing process's responsibility.

Related source and evidence: [src/control_plane_kit_interpreters/secret_provider/client.py](../../../../../src/control_plane_kit_interpreters/secret_provider/client.py), [tests/test_secret_provider_client.py](../../../../../tests/test_secret_provider_client.py).
