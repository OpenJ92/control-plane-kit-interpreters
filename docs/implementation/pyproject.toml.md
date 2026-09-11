Source: [pyproject.toml](../../pyproject.toml).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This is the package distribution and dependency-selection boundary. The base dependency is the exact Core archive selected here; runtime backends are optional extras. The Docker extra accepts a range rather than pinning Docker7.2.0, and the test extra also imports a selected Secrets test distribution. Check the actual installed environment before attributing version-specific SDK behavior.

Do not duplicate Core archive coordinates in the Dockerfile or gate. A dependency-pin or optional-extra change requires reviewing affected source companions even without editing their Python files. Keep the root package lightweight and the py.typed marker included. Package/version metadata and an installed dependency do not by themselves establish public compatibility or provider success.

Source and governing references: [Dockerfile](../../Dockerfile), [test_support/tests/test_gate_contract.py](../../test_support/tests/test_gate_contract.py), [src/control_plane_kit_interpreters/__init__.py](../../src/control_plane_kit_interpreters/__init__.py).
