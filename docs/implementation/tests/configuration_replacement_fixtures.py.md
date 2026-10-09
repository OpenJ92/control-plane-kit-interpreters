Source: [tests/configuration_replacement_fixtures.py](../../../tests/configuration_replacement_fixtures.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This provider fixture extends the existing FakeManager with deterministic
canonical container IDs, immutable-ID lookup, removed-container absence and
recorded create/start/remove/read calls. Workload file reads resolve actual
effective mounts to the shared archives written by SDK materialization helpers;
the archive member is renamed as Docker's target-path archive would be. It does
not choose lifecycle outcomes, validate allocation authority, supply selected
bytes from a desired request, or fake completion evidence.

selected_request builds a valid Core configuration request with a complete
original allocation selection. legacy_start establishes an existing container
through the accepted ordinary effect kind, independently of new B2 dispatch.
These remain in-memory provider fixtures, not live mutation or remote attestation.
