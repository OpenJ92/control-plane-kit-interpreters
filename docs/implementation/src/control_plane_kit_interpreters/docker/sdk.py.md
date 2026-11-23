Source: [src/control_plane_kit_interpreters/docker/sdk.py](../../../../../src/control_plane_kit_interpreters/docker/sdk.py).
Maintain this companion in the same change when the source or its selected imports change the contract.

`DockerSdkClient.create_container` builds the request and endpoint configuration, then calls
the installed Docker SDK’s high-level `containers.create` once. A successful return carries
identity evidence only when the returned model’s `attrs["Id"]` is a canonical 64-character
lowercase hexadecimal ID. Otherwise the adapter returns `None`. A container may exist in
either case. Looking it up by name can resolve to a different container.

The [runtime](../../../../../src/control_plane_kit_interpreters/docker/runtime.py) uses this
distinction during configuration replacement. It starts the replacement by the returned ID
and treats missing identity as an unknown observation. The ordinary StartNode creation path
still starts by name. Keep these two consumers distinct when changing the adapter.
The [creation identity tests](../../../tests/test_docker_creation_identity.py.md) exercise
the return value, name reuse and provider exceptions with a fake SDK.

A provider exception during the high-level create call leaves the effect uncertain.
In the Docker 7.2.0 witness, that call included both creation and a follow-up inspect.
The `sdk-create` diagnostic covers the whole call. The selected Docker extra permits a
version range, so verify installed SDK behavior before attributing a failure to either
operation. See the [StartNode diagnostics](../../../../../README.md#startnode-creation-diagnostics),
[dependency declaration](../../../../../pyproject.toml) and [historical witness](../../../tests/live_docker_start_node_contract.py.md).
