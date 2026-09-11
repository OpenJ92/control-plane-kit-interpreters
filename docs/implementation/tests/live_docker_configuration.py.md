Source: [tests/live_docker_configuration.py](../../../tests/live_docker_configuration.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This standalone Docker fixture creates uniquely named network/volume/container resources, materializes a fixed non-secret JSON configuration artifact, compares its digest and runs a recipient script that checks bytes and attempts a write against the read-only mount. It explicitly pulls the SDK helper image. Success is a configuration-file/mount witness, not a package-wide runtime acceptance result.

Finally cleanup inspects/removes the named recipient, network and volume in sequence. It has no prospective durable journal, full ownership revalidation or final residue audit; an early cleanup exception can prevent later stages. Failure output fetches complete container logs without an explicit byte cap. Those limitations differ from the current synthetic StartNode fixture. The current test.sh does not invoke this standalone script; its presence is not a fresh execution claim.

Related source and evidence: [src/control_plane_kit_interpreters/docker/sdk.py](../../../src/control_plane_kit_interpreters/docker/sdk.py), [test.sh](../../../test.sh), [tests/live_docker_start_node_contract.py](../../../tests/live_docker_start_node_contract.py).
