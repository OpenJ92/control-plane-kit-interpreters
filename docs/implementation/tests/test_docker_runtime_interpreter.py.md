# Docker runtime targets: explicit Unix custody (#216)

DockerUnixRuntimeTests adds the U7/U8/U11 ownership laws from plan216 comment6317385431 and review6317432306. Existing borrowed/TLS targets remain unchanged. Accepted baseline350b1918/run39596554301 is reused; these new targets have not run yet.

Owned construction preserves positional borrowed clients, rejects ambiguous policy/client/module inputs and performs no acquisition. Direct execution and missing/wrong/remote authority refuse before connection secret resolution. Matching local authority executes through the real SDK/resource fake and closes once; successful behavior proves bound-copy policy clearing without asserting a private helper layout. Effect or acquisition failure remains uncertain, and close failure retains the existing bounded cleanup code.

The selected-secret/configuration target reuses existing materialization fixtures through the public owned execute_with_authority entrance. It verifies recipient execution, stripped completion receipts/observations, authority_close_unknown, and redaction after close failure. It patches only SDK acquisition, not the authority-binding helper. Unexpected execution errors close then propagate. Sequential and overlapping operations use distinct real SDK wrappers, with bounded barriers and separate resources/close counts.

Normal unchanged owner Docker ./test.sh is the only execution gate after independent target review. No source change, provider action, durable semantics, broad lifecycle manager or live startup claim is represented by this target checkpoint.
