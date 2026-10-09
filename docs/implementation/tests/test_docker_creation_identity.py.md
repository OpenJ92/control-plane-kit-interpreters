Source: [tests/test_docker_creation_identity.py](../../../tests/test_docker_creation_identity.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

I177-B1 tests the actual SDK creation adapter over the existing fake Docker
boundary. It requires the exact canonical ID from the object returned by the
single create call, even when the same logical name now selects another object
and a separate `.id` attribute disagrees. No name lookup, start or removal may
occur. Missing, short, uppercase, nonhex or wrongly typed ID evidence returns
None after a successful create response; the resource exists in the fake and
is not retried or cleaned up. Provider timeout remains the existing classified
creation exception rather than being converted to missing identity or absence.

The canonical-return assertion supplies genuine target red; malformed identity
and error behavior are opposing preservation laws. The unchanged pinned Docker
gate also exercises all existing runtime, phase, configuration and secret tests
and ordinary real witnesses. Those witnesses are regression evidence, not proof
that this new SDK return is wired into replacement. I177-B2 must use the captured
ID for start and installed-material checks, refuse unknown identity after create,
and preserve truthful uncertainty and whole-invocation completion semantics.
