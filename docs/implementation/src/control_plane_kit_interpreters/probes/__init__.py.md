Source: [src/control_plane_kit_interpreters/probes/__init__.py](../../../../../src/control_plane_kit_interpreters/probes/__init__.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This facade selects a concrete owner only when a public probe name is requested through module __getattr__. TYPE_CHECKING imports serve tooling; runtime ownership is the explicit export-to-module map. Unknown names raise AttributeError. Do not catch a missing selected dependency or unexpected backend import exception and turn it into an unrelated fallback.

The public export list and concrete object identity are part of the contract. Resolving an export must not perform provider I/O or require every unselected optional backend. Keep dependency isolation when adding names; a bare 'import probes succeeds' check is weaker than cold resolution of each selected backend.

Source and governing references: [tests/test_scaffold.py](../../../../../tests/test_scaffold.py), [pyproject.toml](../../../../../pyproject.toml).
