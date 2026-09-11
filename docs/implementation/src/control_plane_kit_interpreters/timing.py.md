Source: [src/control_plane_kit_interpreters/timing.py](../../../../src/control_plane_kit_interpreters/timing.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This small interpreter helper yields one-based verification attempt ordinals up to the Core policy maximum, sleeping only between attempts. It validates the policy type. It does not apply an attempt's transport timeout, impose a total wall-clock deadline or decide which result warrants another attempt.

Consumers own those effect/result decisions. Preserve the no-initial-sleep and between-attempt cadence when changing timing; do not convert attempt count into a claim that an arbitrary blocking provider call is bounded.

Source and governing references: [src/control_plane_kit_interpreters/verification.py](../../../../src/control_plane_kit_interpreters/verification.py), [src/control_plane_kit_interpreters/docker/runtime.py](../../../../src/control_plane_kit_interpreters/docker/runtime.py), [tests/test_verification_timing.py](../../../../tests/test_verification_timing.py).
