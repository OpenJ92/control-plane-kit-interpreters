Source: [src/control_plane_kit_interpreters/secrets.py](../../../../src/control_plane_kit_interpreters/secrets.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This owner turns selected Core secret-delivery values into interpreter runtime material and parses bounded OCI credentials. Value-bearing environment/file deliveries require resolution; reference-only environment delivery carries the reference rather than revealing its value. File path bindings publish only a mounted path. Conflicting environment assignments fail instead of silently overriding one another.

The authorized path selects exactly one grant permitting the reference and use intent and passes that grant to the authorized resolver. It must not silently fall back to the legacy resolver when grant selection or authorized resolution fails. Upstream Core/Operations correlation and custody remain their owners; this helper does not invent a grant or recover transient authority from stored intent.

OCI material accepts only the supported identity-token or username/password JSON shape, rejects duplicate keys and enforces size bounds. SecretValue and redacted representations matter even though runtime material must reveal bytes at the effect boundary. Never copy resolved values into descriptors, logs, persistent companion notes or error text.

Source and governing references: [src/control_plane_kit_interpreters/docker/runtime.py](../../../../src/control_plane_kit_interpreters/docker/runtime.py), [tests/test_secret_delivery.py](../../../../tests/test_secret_delivery.py), [tests/test_docker_runtime_interpreter.py](../../../../tests/test_docker_runtime_interpreter.py), [pyproject.toml](../../../../pyproject.toml).
