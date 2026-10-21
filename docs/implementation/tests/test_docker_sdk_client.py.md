# Docker SDK client targets: explicit Unix acquisition (#216)

This companion describes the added DockerUnixAcquisitionTests; the existing SDK tests remain unchanged. Plan: Interpreters216 comment6317385431; Kepler PASS6317432306. Classification: new U1/U4/U5, strengthened U2/U3/U6. Baseline: accepted350b1918, owner run39596554301, 563 package tests. New targets are not yet executed or implementation evidence.

The policy is pure, frozen and redacted. Bounds cover canonical path components, length, control characters, strict timeout types and oversized integer overflow. SDK constructors reject contradictory ownership configuration. Explicit Unix/API1.45 arguments and actual Unix adapter/path verification precede the unversioned compatibility read. The installed-SDK witness uses the real DockerClient/APIClient/adapter and intercepts version/network calls; it asserts constructor return and verification before handshake without Engine contact. Other existing fake-resource tests inject malformed version/transport/cleanup failures.

Version evidence is bounded ASCII numeric major.minor, with ordered range containing1.45. Rejected evidence closes exactly once and performs no resource operation. Lazy wrappers become terminal after constructor, handshake or cleanup failure. Tests distinguish unreturned handles from acquired resources and preserve KeyboardInterrupt through cleanup faults. Existing ambient/TLS constructors, borrowed ownership and cleanup assertions are retained.

Missing policy is an intentional in-test assertion failure, not an import/collection error. No host Python, alternative runner, private-version mutation, SDK/session adoption, provider mutation, or live qualification. Validation uses the unchanged owning Docker ./test.sh after independent target review. Security: endpoint independence and redacted failures do not claim absence of SDK config/auth reads or stable daemon identity.

Causal-red update: unchanged targets ran in owner39610482883. All21 new methods
failed only at the intentional missing-policy assertion; all563 prior methods
passed (584 total,0 errors). Kepler independently accepted causal red6317675525.
Source implementation now exists; deeper branches await the unchanged full gate.
