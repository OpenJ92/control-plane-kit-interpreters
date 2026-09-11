Source: [tests/test_docker_runtime_interpreter.py](../../../tests/test_docker_runtime_interpreter.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This broad interpreter suite protects the selected request-to-effect behavior using controlled clients/resolvers: runtime and node ownership/reuse, lifecycle and retained storage, configuration/secret material, authority delivery and client binding, canonical images, endpoint observations and health checks. Its fake state models call ordering and returned facts, not a production Operations state machine.

Keep exact-grant negative cases, before-mutation refusal, uncertain post-acquisition behavior and caller-visible result distinctions. A fake create callback can return normally where a real SDK later inspect fails; package green is therefore not combined provider acceptance. Source changes should select the relevant existing law group and inspect the actual imported Core contract rather than copying fixture constructors blindly.

Source and governing references: [src/control_plane_kit_interpreters/docker/runtime.py](../../../src/control_plane_kit_interpreters/docker/runtime.py), [src/control_plane_kit_interpreters/secrets.py](../../../src/control_plane_kit_interpreters/secrets.py), [tests/test_docker_start_node_phase_total.py](../../../tests/test_docker_start_node_phase_total.py), [tests/live_docker_start_node_contract.py](../../../tests/live_docker_start_node_contract.py).
