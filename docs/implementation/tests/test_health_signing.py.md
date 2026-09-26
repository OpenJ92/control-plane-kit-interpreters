Source: [tests/test_health_signing.py](../../../tests/test_health_signing.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

The #169 dependency adoption touches only the existing installed-owner
provenance expectations in HealthSigningPrerequisiteTests. Secrets now selects
the reviewed #36 merge `43b742d1ecb4b7b1fbabb62890a4045afa7a2fec`; its SDK
dependency is the reviewed #37 merge `22f1267bde5015efe2fea4f07be4ce8ddf83bc0c`.
The Servers verifier fixture remains at
`77deffd9b32698a1deb2fa173f6c958e6c441f9b`, installed only in the Docker test
stage with its existing no-deps boundary. Exact direct_url comparisons and the
local candidate Interpreter origin/source checks remain unchanged.

The suite uses the actual Secrets provider, SDK workload verifier and Servers
gateway verifier alongside controlled resolver/client observations. Existing
signing, denial, selected-artifact and owner-boundary assertions are untouched;
this note records the narrow dependency review, not an exhaustive new audit of
every signing case. The ordinary pinned test.sh owns executable evidence and
the separate local witness. These tests do not qualify a published image,
native supervisor or live grandparent deployment.
