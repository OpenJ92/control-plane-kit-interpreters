Source: [src/control_plane_kit_interpreters/docker/__init__.py](../../../../../src/control_plane_kit_interpreters/docker/__init__.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This facade forwards selected Docker SDK configuration/material values, the runtime interpreter, effect observer and endpoint/publication helpers. The implementation contracts remain in sdk.py, runtime.py and observer.py; no duplicate semantics belong here.

Importing this module loads those owners, but should not instantiate a Docker client or perform provider I/O. This differs from the base package's smaller dependency surface and from the lazy probe facade. Preserve explicit public names and verify selected optional-dependency behavior when changing exports.

Source and governing references: [src/control_plane_kit_interpreters/docker/sdk.py](../../../../../src/control_plane_kit_interpreters/docker/sdk.py), [src/control_plane_kit_interpreters/docker/runtime.py](../../../../../src/control_plane_kit_interpreters/docker/runtime.py), [src/control_plane_kit_interpreters/docker/observer.py](../../../../../src/control_plane_kit_interpreters/docker/observer.py), [tests/test_scaffold.py](../../../../../tests/test_scaffold.py).
