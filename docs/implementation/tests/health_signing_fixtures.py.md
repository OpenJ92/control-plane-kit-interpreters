# Real provider fixture for health signing

Under #244, the fixture constructs its existing exact credential tuple before
fresh custody admission and supplies that same tuple as the one-time policy
seed. It returns the real provider-bound ProviderPolicyStore as the fourth API
initializer value. Existing grants, real HTTP transport, signing, receiver
admission and replay assertions are preserved.

The first pinned gate's three custody rejections establish the missing seed
boundary. The four-value initializer mismatch was a masked source finding.
No custody or production API behavior is relaxed. The ordinary pinned test.sh
owns executable evidence and the existing controlled fixture cleanup.
