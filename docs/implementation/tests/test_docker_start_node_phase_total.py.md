Source: [tests/test_docker_start_node_phase_total.py](../../../tests/test_docker_start_node_phase_total.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This file drives each StartNode boundary with a controlled phase client. It protects canonical cached/pulled image admission, familiar official-image digest matching, ownership/network refusal and success only for a running exact-image recipient on the intended network. Provider faults stop at their recorded uncertain phase; final absence is not successful startup.

The selected Hello request is an example input, not a product-specific interpreter branch. Preserve phase-specific negative cases and one-attempt call expectations; do not turn an early cache/authority refusal into a later effect. These controlled failures demonstrate the runtime's classification behavior, not the HTTP status or resource history of a past real Docker failure.

Source and governing references: [src/control_plane_kit_interpreters/docker/runtime.py](../../../src/control_plane_kit_interpreters/docker/runtime.py), [src/control_plane_kit_interpreters/docker/sdk.py](../../../src/control_plane_kit_interpreters/docker/sdk.py), [tests/live_docker_start_node_contract.py](../../../tests/live_docker_start_node_contract.py).
