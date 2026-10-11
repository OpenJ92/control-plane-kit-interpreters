Source: [docker/runtime.py](../../src/control_plane_kit_interpreters/docker/runtime.py) and [docker/configuration.py](../../src/control_plane_kit_interpreters/docker/configuration.py).
Maintain this document alongside its source files. When source or relevant imported contracts change, verify and update this companion in the same change.

# Exact configuration replacement (I177-B2)

## Shared installation receipts (I186)

The final configured Start/Reconcile seam now emits Core's
`configuration-installation-receipt.v1` only after all existing actual
running/image/network/authority and selected mounted-file checks. Original
request/full-selection correlation is unchanged. Created has no prior; unchanged
or stopped/restarted compute is reused with equal prior/current commitments;
replacement requires distinct actual immutable IDs and verified old removal.

The private derivation hashes canonical ASCII JSON with fixed profile
`docker-container-incarnation.v1`, provider `docker`, resource kind `container`
and actual full64-hex `container_id`. Fixed sorted ASCII keys/strings yield
RFC8785 canonical bytes. No request, graph, plan, selection, address, logical
name, credential or secret value enters this preimage. This is a Docker
container-ID commitment, not standalone daemon identity or cross-authority
adoption proof; original request/runtime correlation remains essential.

The builder does not infer installed truth from success/phase/labels: its sole
returned-evidence call is after final installed verification. Existing failure
paths never add a receipt. Later owned-client close failure strips both receipt
and invocation completion. Capacity preflight includes a maximum valid replaced
receipt strictly as sizing data; synthetic sizing evidence is never returned.
Whole-result bounds remain enforced. No cleanup, retry or authority changes.

Reviewed targets at7f72226 produced six intended missing-receipt assertions,
zero errors, with all453 prior methods green in run38106190718. Original targets
remain unchanged. Final acceptance additionally requires one real configured
runtime created/reused/replaced witness; see [resource and evidence boundaries](configuration-mount-witness.md).

B2's replacement path admits Core's configuration activity kind for StartNode and ReconcileNode. The separate [C cleanup path](docker-configuration-cleanup.md) consumes exact cleanup requests. Core validates the complete original selection; Operations owns approval, reservation and history. No new registry or policy is introduced here.

Configuration names hash workspace/runtime/node/allocation ID into 63 characters. Ownership additionally compares exact scope, allocation, configuration kind/profile, artifact identity/digest and the canonical full reference digest. Conflicting material for the same allocation keeps the name and fails ownership. Graph/plan changes do not change allocation names. No populated volume is overwritten, adopted, relabelled or deleted. Exactly owned absent content may be filled and verified.

After existing ownership/material/network/authority and image/secret admission, the runtime stages every selected artifact with bounded actual regular-file, byte and mode readback. It prepares secret/retained mounts before old removal. Reconcile removes only a freshly checked old immutable ID, verifies absence, creates once, captures B1's returned ID, and starts/inspects that ID. Missing ID or ambiguous remove/create/start/helper cleanup is uncertainty, not absence or retry authority. No logical-name lookup follows creation.

I176's logical material fingerprint is unchanged. A separate selection label is only a reuse hint; actual installed mount/bytes/mode/read-only facts must still agree. Same bytes with a different allocation require physical replacement; the same selection on a new graph/plan can reuse it. Start keeps exact creation correlation. Nonempty authority deliveries still refuse changed-material replacement, and also refuse allocation-only replacement without a pinned prior authority declaration. CPK1911 comment6072312668 records the selected empty-delivery G example; U2 must admit its exact graph/product/material.

## Results and partial failure

RuntimeEffectResult carries configuration_attempt with profile, known phase, selection fingerprint, attempted/staged indices into the original canonical selection, old/created IDs, verified old removal, unknown-created-resource flag and zero configuration-volume removals. Original history supplies full references. This describes performed actions, not global absence or a fence against external changes. A missing helper identity remains unresolved under the phase/selection evidence.

Core completion is separate from installed evidence. Only terminal succeeded/failed results carry original request/full-selection correlation. A deterministic material/precondition failure after acknowledged helper completion may be terminal; malformed final readback, missing identity or unresolved provider operations stay uncertain without completion. Authority-client close uncertainty removes completion and preserves bounded attempt evidence. Capacity is checked before mutation using maximum attempt state and reserved failure/address space; every actual result is validated through Core's whole-result fingerprint bound.

No exception triggers rollback, retry, adoption or cleanup. Old configuration remains for separately authorized C cleanup. No database transaction spans Docker effects. Trusted-daemon observations are not remote attestation or protection against external administrator races.

## Validation scope

The original 12 target methods reached 14 intended unsupported-kind assertions, zero errors, with all 423 prior methods green in run37869918463. An additional opposing security test carries nonempty-delivery refusal into the new request kind; original targets remain unchanged. A fixture-cleanup test protects recording a returned reader ID before a subsequent read.

The first source run37871664983 collected 437 methods and exposed an implementation error before provider mutation: a single capacity-reserve string exceeded Core's per-field bound. The reserve now uses bounded 256-character chunks, preserving the conservative whole-result allowance. Behavioral assertions remain unchanged; a new ordinary gate is required.

The existing real configuration witness now uses actual SDK create, records its returned ID, starts by ID and inspects installed selected files on that ID. A temporary additive _container_create_kwargs override calls the real builder and preserves the existing read-only root, dropped capabilities, DAC override and no-new-privileges settings. It simulates no ID, create/start/readback or lifecycle logic. Network none preserves the disconnected reader; the override is restored immediately. Numeric 0444, read-only/EROFS, independent content checks and exact fixture cleanup remain.

This proves the real SDK creation-to-installed chain, not a complete real-engine runtime replacement or final G rollout. Runtime phase/fault semantics use the real interpreter and SDK over the fake provider. Readiness is a separate planned observation; installation is not readiness. Retrospective configuration observation remains unsupported. Full source acceptance requires the unchanged owning gate and independent review.
