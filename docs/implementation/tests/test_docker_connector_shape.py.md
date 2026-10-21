# Client-free connection qualification targets (#218)

Source: [test_docker_connector_shape.py](../../../tests/test_docker_connector_shape.py).
Plan218 and Kepler PLAN PASS6318063029 govern the new eight-method
ClientFreeConnectorQualificationTests class. Existing tests/fixtures are unchanged.
Accepted baseline is I216ad9a5da8, owner39611713669:26 policy+584 package+existing
Docker witnesses; no baseline rerun. This is a target-only checkpoint, not an
executed result.

Q1 tests the new public frozen/redacted qualifier without a client, clock,
acquisition policy or factory. Fixture data is built before I/O guards; actual
qualifier construction and queries run with SDK construction/import, file open,
stat and environment reads forbidden. Invalid config preserves the old observer's
fixed error text, positional API and equality while adding no image grammar.

Q2 compares standalone and both observer public queries for all three modes and
both native/managed profiles, with both image revision directions. Repeated
queries preserve graph, plan, canonical document and detached full-material
snapshots. Q3-Q5 cover representative malformed/foreign documents, image,
activity/whole-plan/current authority, slot asymmetry, selected-token/material
requirements and old/filtered/dependency-tampered image plans. Existing exhaustive
observer tests remain as delegation regression coverage rather than being copied.

Q6 proves pure retained qualification does not manufacture installation receipts:
observation still refuses without the original proof before SDK/time effects.
Workspace-specific managed checks and all existing unknown/freshness/final-drift
laws remain owned by the unchanged observation suites. Tests assert semantic
agreement, not private helper layout. Missing public API fails an intentional
in-test assertion; no collection-time dependency on unimplemented names.

No source edit, validation dispatch, new provider or credential action accompanies
these targets. Independent TARGET review precedes unchanged normal Docker
./test.sh causal red; source then preserves the reviewed targets through green.
No host Python, duplicate planner/algorithm, lifecycle framework, Core/Operations
emulator or live/Servers2B claim. Qualification remains capability selection,
not admission, current authority or exact retained installation provenance.
