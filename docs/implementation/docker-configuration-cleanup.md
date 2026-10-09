Source: [docker/configuration_cleanup.py](../../src/control_plane_kit_interpreters/docker/configuration_cleanup.py), [docker/runtime.py](../../src/control_plane_kit_interpreters/docker/runtime.py), and [docker/sdk.py](../../src/control_plane_kit_interpreters/docker/sdk.py).
Maintain this document alongside its source files. When source or relevant imported contracts change, verify and update this companion in the same change.

# Exact configuration cleanup (I177-C)

Core's original CleanupConfigurationInstances is the only candidate source. Core validates scope and worst-case whole-result capacity before provider calls; Operations owns approval, reservation, prior-invocation completion and current-membership exclusion. Docker receives the admitted request and returns the exact conserved Core outcome set. It does not issue B's Start/Reconcile-only invocation completion, select candidates by searching, or implement a second lifecycle store.

For each original canonical reference, B2's name and full-reference ownership labels select the physical volume. SDK inspection snapshots Name, CreatedAt and labels, and admits only ordinary local-driver/local-scope storage with no driver options or cluster declaration. Foreign/secret/retained/unprofiled material is refused. Unsupported storage is provenance-unproven; malformed metadata is unknown. Labels are copied, so changes in a provider dictionary cannot mutate the admitted comparison value.

The SDK queries the daemon for all container states using the exact volume filter and limit one. Empty means no container reference at that snapshot; a canonical ID plus exact named-volume mount proves use, including stopped/created containers and foreign holders. Malformed or over-limit payloads are unknown, never false. Only a bounded boolean is consumed; no holder metadata is exposed. The limit is provider-side, not a slice of an unbounded listing.

Before removal the SDK fetches the named volume again and compares the independent admitted snapshot, then invokes remove(force=False). A typed Docker APIError with status409 from that endpoint means in-use; no provider-text parsing is used. Acknowledged removal requires a subsequent absent inspection before REMOVED. An initially absent volume is ALREADY_ABSENT. Changed incarnation, failed reads, residuals and ambiguous deletion are UNKNOWN without retry.

Earlier known outcomes survive later failure. Deterministic refusals may continue to later exact selected candidates. The first uncertain candidate stops further destructive calls and preserves every remaining ref as UNKNOWN/NOT_ATTEMPTED. Core derives aggregate success/failure/uncertainty and the fixed redacted failure envelope; no arbitrary evidence is appended. Raw errors, content, secret data, holder names and mountpoints never enter results. Cleanup creates no readback/materialization helper and invokes no compensation.

## Authority and custody boundary

Direct execution uses the supplied client's caller-owned lifecycle. execute_with_authority supports cleanup through the local-docker-socket binding. Other authority kinds, including per-call remote Docker TLS, receive canonical total REFUSED/AUTHORITY_REFUSED before resolver or client construction, provider inspection/deletion or close. Existing remote Start/Reconcile behavior is unchanged.

This explicit limit was accepted in I177 comment6072748650 and independently reviewed in6072740727. Core's closed cleanup envelope has no separate TLS custody-close outcome. The generic wrapper's uncertain rewrite would otherwise erase known removal facts through Operations' canonicalization fallback. Future Core #934 owns remote qualification and that dual provider/local-custody reporting obligation. A representable remote request is not remote cleanup support.

## Concurrency and proof limits

Docker local volumes have names rather than immutable incarnation IDs. Name/CreatedAt/labels rechecks detect observed replacement but are not atomic compare-and-delete. Operations reservations prevent cooperating CPK reuse/current-membership races; non-forced engine deletion protects container references. External administrator recreation/relabeling between calls remains outside that protection. Unsupported shared/plugin/NFS/bind-option storage is retained because one daemon cannot prove its non-use. No database transaction spans provider calls.

The original fifteen new methods produced33 intended assertions with zero errors, all437 prior methods green in run37873028159. A sixteenth snapshot-alias law was added after North's target review without changing original assertions. The owning gate remains the unchanged pinned ./test.sh. Its same-resource real witness preserves selected numeric0444/read-only/EROFS proof, adds running/stopped cleanup refusal, removes only the rechecked fixture reader, then proves real interpreter cleanup and absent replay. Outer exact fixture cleanup remains the residue audit. Source acceptance still requires green CI and independent source/fixture review; no full Operations/public-API, readiness, published-image or live grandparent claim follows from this witness.
