Source: [src/control_plane_kit_interpreters/boundaries.py](../../../../src/control_plane_kit_interpreters/boundaries.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This file records the intended execution spine and a frozen repository-ownership marker: Interpreters owns concrete effects, not durable dispatch or the server process. These values are architectural declarations, not runtime authorization checks or evidence that callers followed the spine.

When ownership changes, consult the governing repository contract and actual dependency direction; do not merely flip a boolean or update a test to match an accidental import. Operations and server responsibilities remain with their selected external owners.

Source and governing references: [AGENTS.md](../../../../AGENTS.md), [tests/test_scaffold.py](../../../../tests/test_scaffold.py), [tests/test_package_boundary.py](../../../../tests/test_package_boundary.py).
