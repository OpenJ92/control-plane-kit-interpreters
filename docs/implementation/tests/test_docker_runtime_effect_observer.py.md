# Docker observer targets: explicit Unix custody (#216)

DockerUnixObserverTests adds U9/U10/U11 from plan216 comment6317385431 and review6317432306. Baseline350b1918/run39596554301 remains the immutable prior green; new targets have not yet run. Existing borrowed/TLS observer targets and unexpected-error assertions are unchanged.

Owned construction is pure and exclusive while retaining positional borrowed calls. Missing authority produces indeterminate; remote/unknown/wrong runtime refuses before credential resolution or provider access. Matching local authority can confirm presence or absence only after acquisition and successful cleanup. Existing read/close failures remain indeterminate, with exact ownership and no mutations.

Real SDK-wrapper acquisition tests inject transport mismatch, incompatible version, handshake, constructor and cleanup failures; none may inspect a resource or report absence. Unexpected factory/read/close errors retain identity and close-before-propagation behavior. Sequential/overlapping calls use independent clients; bounded barriers require both calls in flight before construction returns. Shared policy is not shared mutable client state.

Targets intentionally assert missing API within test execution rather than failing collection. Only unchanged owning Docker ./test.sh after independent target review supplies evidence. The installed-SDK no-contact witness is owned by the companion SDK suite; these cases do not claim real Engine compatibility, native qualification, Servers cancellation handling or live225. No provider/resource mutation or history/schema change.

Causal-red update: owner39610482883 ran584 methods,21 intentional missing-policy
failures and0 errors; the563 prior methods passed. Kepler acceptance6317675525
confirms API absence only. Source now exists and unchanged deeper targets still
require the complete owner gate; initial unexecuted wording is historical.
