Source: [tests/test_docker_retained_image_connector.py](../../../tests/test_docker_retained_image_connector.py).
Maintain this document alongside its source and selected dependency contracts.

Interpreters #214's target-only checkpoint exercises public `qualify`,
`qualify_shape` and `observe` through both native-reader and managed-wrapper
profiles. It reuses existing real Core graph/receiver/configuration fixtures
and recording SDK facts. `image_transition` replaces the workload metadata
with one exact same-product immutable image transition and uses the accepted
Core compiler; it does not reconstruct a plan or emulate Operations state.
Original connector request, receipt, labels and selected managed volume remain
from installation A while the observation returns request B's correlation.

Eight methods strengthen existing qualification, original-proof and bounded
observation laws. Pure shape/full results must agree without a clock or SDK
call and without changing graph/plan/document snapshots. Both revision
directions qualify. Complete canonical plans are required; old V1, empty,
filtered, dependency-tampered, foreign and coupled-content inputs refuse.
Current authority, exact connector material and selected token remain required.
Missing/foreign installation pairs refuse before SDK access. Managed image
mode also requires CONFIGURATION_ACTIVITY_V1 and the exact selected instance;
a valid plain-kind origin with a recomputed receipt cannot become fresh mode.
Malformed typed instance fields are supplied by deliberately corrupting copied
proof values, so construction does not obscure the observer's refusal law.

Wrong observed volume/incarnation is UNKNOWN without archive reads. Existing
bounded selected-content, stale/late sample, final-container drift and provider
error paths remain conservative and redacted. Recording SDK calls establish
the native owner's read path, not a real deployed image, atomic snapshot,
continuous availability or Operations registered-workload contract equality.
That full registered-contract comparison belongs to accepted Operations #2017.
Existing fresh/content/old-image negative tests remain unchanged.

The target-only checkpoint preceded semantic observer implementation. Kepler
target review preceded the unchanged full pinned ./test.sh run. Intended red
must be missing image qualification/observation, with valid fixture setup,
dependency installation and collection. Full subsequent green remains evidence
to record on the issue/PR, not a claim made by these notes.

Initial checkpoint `6c0d271` ran 26 policy and 563 package tests. Eighteen
assertion failures were missing image qualification/observation, but one
dependency-tampering subcase used the nonexistent root `core.ReconcileNode`
instead of the public `control_plane_kit_core.planning.ReconcileNode`.
The corrected import preserves the same plan mutation and refusal assertions.
That mixed first run is retained as evidence and is not clean causal red;
review of the correction and an unchanged owner rerun preceded implementation.

Corrected checkpoint `eac62f9` ran 26 policy tests green and 563 package tests
with 18 assertion failures and zero errors. Failures were confined to missing
image qualification/observation in four new methods; the 555 prior methods and
four remaining new methods passed. Kepler independently accepted causal red.
Assertions after each initial failure, isolated imports and actual Docker
witnesses still require the subsequent green gate. Targets remain unchanged
after this corrected checkpoint while the observer implementation is reviewed.
