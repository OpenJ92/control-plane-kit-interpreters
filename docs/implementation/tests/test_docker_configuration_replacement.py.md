Source: [tests/test_docker_configuration_replacement.py](../../../tests/test_docker_configuration_replacement.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

I177-B2 target checkpoint. Tests call the real runtime interpreter and Docker SDK
adapter with provider fixtures, never a second lifecycle implementation. They
exercise the original Core configuration selection and completion parser.
Legacy Start establishes old owned compute independently of the new dispatch,
allowing pre-removal fault tests to assert real preservation rather than a
fabricated old-container state.

Laws include exact new Start/replay through direct and authority entrypoints;
all-artifact staging before old-ID removal; equal bytes with different allocation
versus unchanged selection on a new graph; ownership and material/mode conflicts;
unknown created ID, ambiguous removal and helper cleanup; installed-file mismatch;
following created identity despite logical-name reuse; and a maximum32 selection
with128-character allocation IDs inside Core's whole-result bound. Completion
must correlate to the original request/full selection and never accompany an
uncertain result. Old volumes remain unchanged; no cleanup policy is inferred.

The fixture extends the existing fake provider only with immutable IDs,
ID lookup, operation recording, removed-object absence and mounted archive reads
from the bytes actually written through the SDK helper. It does not reconstruct
desired content to satisfy inspection. Package tests establish effect semantics;
the existing owning gate's real-engine witness must separately establish numeric,
read-only delivery and the integrated creation/readback path.

Implementation adds an opposing test of the existing nonempty authority-delivery guard through the new request kind, before staging or replacement. The original 12 target methods and assertions remain unchanged from genuine unsupported-kind red. This guard test is preservation evidence, not additional missing-behavior red.
