Source: [src/control_plane_kit_interpreters/docker/observer.py](../../../../../src/control_plane_kit_interpreters/docker/observer.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This is a read-only resource-postcondition observer for the Core observation request/result language. It deliberately does not prove delivered content, health readiness or endpoint reachability. Admission rejects unsupported operations/material before provider reads; StartNode/Reconcile with secret/configuration/retained content cannot be confirmed just from a declared fingerprint. Stop/remove observations have different postconditions and content requirements.

Authority binding is separate from workload delivery. Local Docker uses the supplied ambient client. Remote TLS observation requires the selected authority's exact connection grants, creates a dedicated client and closes it; it does not resolve product secrets or pull credentials. Provider/connection uncertainty produces unestablished evidence, while unexpected programming exceptions retain their identity. Close errors must not overwrite unrelated read errors.

Ownership, exact image/network and configured-versus-effective authority delivery are checked without mutating provider state. A confirmed resource postcondition does not advance Operations history, authorize retry or settle every historical external effect. Keep absent, conflict, unsupported and unestablished distinct.

Source and governing references: [src/control_plane_kit_interpreters/docker/authority.py](../../../../../src/control_plane_kit_interpreters/docker/authority.py), [src/control_plane_kit_interpreters/docker/runtime.py](../../../../../src/control_plane_kit_interpreters/docker/runtime.py), [tests/test_docker_runtime_effect_observer.py](../../../../../tests/test_docker_runtime_effect_observer.py).
