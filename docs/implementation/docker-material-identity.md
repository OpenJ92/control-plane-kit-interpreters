# Docker material identity and request correlation (#176)

Target checkpoint; application implementation is not yet changed. Accepted base
I-M is `bdbab01c0babaead958450b3c5e643317b2f4cd9`. The reviewed law/source dry run
is issue176 comment5943683903; independent design PASS is comment5943684023.

`test_docker_material_identity.py` adds seven methods using the existing fake
Docker SDK and public execute/observe seams. Targets cover active graph/plan
reuse (running and stopped), immutable creation labels with current effect and
endpoint correlation, exact Start, unsupported profile even with changed
material, malformed creation coordinates/digest, cross-graph foreign scope,
retrospective Reconcile and native health's preserved graph restriction.
The existing authority-delivery matrix changes only its graph-only case to
reuse; image/environment changes still refuse without a prior declaration.

Law provenance: existing canonical-environment reuse, real-material replacement,
authority-change refusal, foreign ownership, final inspection and observer
correlation laws remain. New graph equivalence supersedes only graph-as-material;
unknown-profile refusal strengthens safety before mismatch can reach replacement.
No skips, xfail, test gate, dependency or production source changes.

Expected causal red: graph-bearing hash prevents active graph reuse; no closed
profile/refusal exists; missing/malformed digest can reach replacement. All
opposing Start/observer/health and ownership laws should remain green. Run only
the unchanged ordinary pinned Docker `./test.sh` through PR CI; record actual
results before implementation. Mocked provider boundaries prove interpreter
semantics, not installed routing, Operations admission or provider acceptance.

Core/Operations validates selected continuity/origin and retirement before effect
attempts; see accepted-K receiver_lifecycle, effect_attempt_start_interpreter and
advancement trace in the issue. Docker labels are not lifecycle authority.
Managed Update remains closed. Future I177/1886 owns stage-before-replace and
cleanup; this slice cannot promise configuration rollout safety or availability.
No new listener, secret-value hash, raw credential or automatic recovery is added.
