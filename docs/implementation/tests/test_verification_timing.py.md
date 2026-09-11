Source: [tests/test_verification_timing.py](../../../tests/test_verification_timing.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These focused tests patch the timing module's sleep and assert attempt numbering, exactly one interval between successive attempts, no trailing delay after early stop and rejection of an untyped policy. They preserve generator cadence semantics; they do not exercise real elapsed time, network timeouts or cancellation of a blocked transport.

Related source and evidence: [src/control_plane_kit_interpreters/timing.py](../../../src/control_plane_kit_interpreters/timing.py), [src/control_plane_kit_interpreters/verification.py](../../../src/control_plane_kit_interpreters/verification.py).
