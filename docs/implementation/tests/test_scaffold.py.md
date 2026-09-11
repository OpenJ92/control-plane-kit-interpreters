Source: [tests/test_scaffold.py](../../../tests/test_scaffold.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This file owns lightweight root exports, the declared interpreter spine and cold optional-backend import laws. Subprocess fixtures deny selected imports and instrument provider-I/O audit events; they check export identity, isolation from unselected dependencies, and preservation of missing/unexpected import errors.

Do not turn selected-backend failures into silent fallbacks or weaken the fixture's guard checks to make a lazy import appear valid. Required fixture dependencies must actually be present; otherwise a missing test prerequisite is not evidence of correct isolation. These subprocess tests establish the observed import boundaries, not provider deployment or exhaustive network-sandbox guarantees.

Source and governing references: [src/control_plane_kit_interpreters/__init__.py](../../../src/control_plane_kit_interpreters/__init__.py), [src/control_plane_kit_interpreters/probes/__init__.py](../../../src/control_plane_kit_interpreters/probes/__init__.py), [src/control_plane_kit_interpreters/docker/__init__.py](../../../src/control_plane_kit_interpreters/docker/__init__.py).
