Source: [src/control_plane_kit_interpreters/__init__.py](../../../../src/control_plane_kit_interpreters/__init__.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This package entrance exports only the interpreter-spine and boundary-value names plus package version metadata. It deliberately does not import concrete Docker, provider or server implementations. Importing the base package must not establish a client or pull optional runtime dependencies into the process.

The source owner for the forwarded values is boundaries.py. Changes to this facade are public API changes even though it is small; inspect import-isolation and explicit export tests before adding a convenient backend alias.

Source and governing references: [src/control_plane_kit_interpreters/boundaries.py](../../../../src/control_plane_kit_interpreters/boundaries.py), [tests/test_scaffold.py](../../../../tests/test_scaffold.py).
