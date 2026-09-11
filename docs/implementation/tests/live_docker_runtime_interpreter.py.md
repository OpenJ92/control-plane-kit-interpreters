Source: [tests/live_docker_runtime_interpreter.py](../../../tests/live_docker_runtime_interpreter.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This older standalone fixture translates fixed StartRuntime and StartNode requests through DockerRuntimeInterpreter, then checks a running container and returned endpoint observations for a digest-selected nginx product. It does not establish application health or exercise the richer secret/configuration/retained-storage contract of the later synthetic StartNode witness.

Cleanup learns network/container names only from successful result evidence. If an effect changes Docker state without returning that success receipt, this fixture has no prospective resource journal to recover the identity for cleanup. Fixed request/workspace/run coordinates also differ from the newer isolated fixture. Sequential cleanup can stop on an exception and performs no final residue audit. The current test.sh does not call this script; review/adapt its contracts before any separately authorized use, and do not infer green status from historical source.

Related source and evidence: [src/control_plane_kit_interpreters/docker/runtime.py](../../../src/control_plane_kit_interpreters/docker/runtime.py), [test.sh](../../../test.sh), [tests/live_docker_start_node_contract.py](../../../tests/live_docker_start_node_contract.py).
