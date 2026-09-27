Source: [tests/test_health_signing.py](../../../tests/test_health_signing.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

The #173 dependency adoption touches only the existing installed-owner
provenance expectations in HealthSigningPrerequisiteTests. Secrets now selects
the reviewed #40 merge `7a26fdc174ceb08657ed23062bf3323f62e48f4b`; its SDK
dependency is the reviewed #42 merge `e19b7ed205d492bdae3abe7c2449732bcc4d53dc`.
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
