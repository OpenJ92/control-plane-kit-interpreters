Source: [tests/live_docker_publication.py](../../../tests/live_docker_publication.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This standalone Docker fixture pulls the helper image, starts a sleeping container with loopback TCP and UDP publications and verifies inspected publication metadata plus derived host-local endpoint observations. The process does not serve those ports: publication metadata is not TCP/UDP reachability or application health.

UUID-derived names scope the network/recipient. Finally cleanup performs sequential inspect/remove by those names, without a durable prospective journal or final absence audit; an earlier cleanup exception stops later cleanup. It is outside the current test.sh invocation path and must not be counted as fresh owning-gate evidence merely because its source exists.

Related source and evidence: [src/control_plane_kit_interpreters/docker/sdk.py](../../../src/control_plane_kit_interpreters/docker/sdk.py), [test.sh](../../../test.sh), [tests/live_docker_start_node_contract.py](../../../tests/live_docker_start_node_contract.py).
