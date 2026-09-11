Source: [tests/test_docker_runtime_effect_observer.py](../../../tests/test_docker_runtime_effect_observer.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This suite owns resource-observation laws: exact workspace/node/plan ownership, absence versus conflict/unestablished/unsupported, known versus ambiguous container state, image/network conformance, and local/remote authority client behavior. It explicitly rejects inferring delivered secret/configuration/retained content or health from a resource fingerprint.

TLS fixtures check exact connection-grant correlation and dedicated-client cleanup while prohibiting product/pull secret resolution. SDK malformed/provider errors and unexpected programming errors are intentionally different categories. The provisional Desktop configured/actual mount relation is tested narrowly; do not generalize it from a green fixture. These fake and local SDK-boundary checks are not current provider inventory or permission to reconcile history.

Source and governing references: [src/control_plane_kit_interpreters/docker/observer.py](../../../src/control_plane_kit_interpreters/docker/observer.py), [src/control_plane_kit_interpreters/docker/authority.py](../../../src/control_plane_kit_interpreters/docker/authority.py), [src/control_plane_kit_interpreters/docker/sdk.py](../../../src/control_plane_kit_interpreters/docker/sdk.py).
