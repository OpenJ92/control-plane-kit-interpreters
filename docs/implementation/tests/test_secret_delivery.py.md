Source: [tests/test_secret_delivery.py](../../../tests/test_secret_delivery.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This file covers the legacy delivery helper's environment/reference/file distinctions, missing-resolver refusal, bounded redacted missing/denied outcomes and conflicting environment names. It uses a supplied resolver and inspects runtime material, not provider custody or actual mounted-file permission.

Do not treat its legacy resolver path as permission to bypass exact grants in authorized runtime calls. Authorized grant integration and OCI credential shapes have their own cases in the runtime interpreter suite; real numeric file access belongs to the ordinary Docker controller.

Source and governing references: [src/control_plane_kit_interpreters/secrets.py](../../../src/control_plane_kit_interpreters/secrets.py), [tests/test_docker_runtime_interpreter.py](../../../tests/test_docker_runtime_interpreter.py), [tests/live_docker_secret.py](../../../tests/live_docker_secret.py).
