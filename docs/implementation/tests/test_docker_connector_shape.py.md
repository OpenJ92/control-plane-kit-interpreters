# Client-free connection qualification targets (#218)

Source: [test_docker_connector_shape.py](../../../tests/test_docker_connector_shape.py).
Plan218 and Kepler PLAN PASS6318063029 govern the new eight-method
ClientFreeConnectorQualificationTests class. Existing tests/fixtures are unchanged.
Accepted baseline is I216ad9a5da8, owner39611713669:26 policy+584 package+existing
Docker witnesses; no baseline rerun. The initial target-only checkpoint preceded
the execution evidence recorded below.

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

Independent TARGET PASS6318158938 preceded unchanged normal Docker ./test.sh
run39614565856:26 policy tests pass,592 package methods/43.016s with8 intentional
missing-qualifier assertions and0 errors; all584 prior methods pass. Source
extraction preserves the reviewed test SHA83a1f1142ccce33b2603b3ba3c0dbd5c03c6b40fcce355bb5572a0918acb0352.
Full green and independent source/final review remain pending at this checkpoint.
No new provider or credential action accompanies these targets.
No host Python, duplicate planner/algorithm, lifecycle framework, Core/Operations
emulator or live/Servers2B claim. Qualification remains capability selection,
not admission, current authority or exact retained installation provenance.

The first full source run39615450202 ran592 package methods in46.636s with one
fixture error and zero assertion failures; the other591 methods passed. The
new mismatch branch used `/other`, which Core rejects before qualification
because secret file targets require the protected namespace. Initial red only
proved API absence and did not reach that deeper fixture branch. Later owning
gate stages were not reached; this run is not full-green evidence.

The reviewed correction changes only that declared path to `/run/secrets/other`,
already used by the governing pre-existing negative. It remains different from
the authored `/run/secrets/cloudflare-tunnel-token`; all assertions and production
source remain unchanged. This preserves the intended well-formed declaration
mismatch rather than bypassing Core validation. North released this exact target
correction subject to Kepler CORRECTION review, then one ordinary full owner
rerun. Failed evidence remains on PR219 comment6318383809; no silent retry or
alternate runner. Current corrected test hash and final result belong to the
subsequent exact checkpoint, not the earlier original hash above.
