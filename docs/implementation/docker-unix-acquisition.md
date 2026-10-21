# Explicit Unix Docker clients per operation

Source: [SDK](../../src/control_plane_kit_interpreters/docker/sdk.py),
[runtime](../../src/control_plane_kit_interpreters/docker/runtime.py),
[observer](../../src/control_plane_kit_interpreters/docker/observer.py), and
[Docker exports](../../src/control_plane_kit_interpreters/docker/__init__.py).
Governing issue: Interpreters216, parent148. Maintain this companion alongside
those implementations and their selected dependency contracts.

```python
from control_plane_kit_interpreters.docker import (
    DockerUnixSocketClientConfig,
    DockerRuntimeInterpreter,
    DockerRuntimeEffectObserver,
)

policy = DockerUnixSocketClientConfig("/var/run/docker.sock", 5.0)
runtime = DockerRuntimeInterpreter(local_client_config=policy)
observer = DockerRuntimeEffectObserver(local_client_config=policy)
# These values do not contact Docker. The coordinator supplies each operation's
# admitted request and current local Docker authority to the public entrances:
# runtime.execute_with_authority(request, authority)
# observer.observe(observation_request, authority)
```

The two consumers share immutable policy, not a mutable client. Each authorized
operation constructs its own SDK client and closes it at its existing result
boundary. Positional borrowed clients remain supported and caller-owned.
Exactly one client or local policy is required; the optional keyword-only
Docker module injection applies only to the owned form. Runtime clears owned
policy/module fields when it binds a borrowed copy for execution. A direct
execute on an owned template refuses without authority; an authority-free
observation stays indeterminate. Wrong-runtime or nonlocal authority refuses
before connection-credential resolution. Existing admission, authority delivery,
resource and incarnation checks still apply; policy does not grant authority.

Policy construction is pure and redacted. Paths are lexical absolute, non-root,
bounded4096 characters, and have no empty/dot/dot-dot components, trailing
slash, control characters, query or fragment delimiters. They are not resolved
or inspected. The timeout is an exact int/float excluding bool, finite and
within0<t<=60. Bounds are checked before float conversion can overflow for a
large integer. No socket existence, daemon identity or deployment is attested.

SDK acquisition uses public DockerClient(base_url=explicit Unix URL,
timeout=policy timeout, version="1.45"). The explicit version avoids constructor
Engine negotiation. It retains the returned handle, checks the actual
UnixHTTPAdapter and exact socket path, then requests version(api_version=False).
Only bounded canonical ASCII numeric major.minor MinAPIVersion and ApiVersion
are accepted, with a range containing1.45. Missing/malformed/incompatible evidence
fails closed before resource operations. Current CPK configuration/secret
VolumeOptions.Subpath use motivates1.45. Engines excluding1.45 require a future
explicit contract change; there is no negotiation, fallback or implicit retry.

Acquisition can still read the Docker SDK's ordinary configuration/auth files.
The promise is explicit endpoint selection, not filesystem/environment-free
SDK construction. No registry credential policy changes here. An unreturned
constructor allocation has no fabricated cleanup guarantee. Every returned
handle receives one close attempt after verification/handshake failure; the
wrapper becomes terminal even after constructor failure. It cannot reconnect.
Non-Exception interruptions propagate after applicable cleanup/terminal marking,
including when cleanup also fails. Ordinary acquisition cleanup failure has a
fixed private bounded signal; observer recognizes only that exact type in
addition to its existing provider faults. Unexpected programming exceptions
are not broadly normalized.

Successful acquisition enters the unchanged runtime/observer cleanup boundary.
Runtime close failure remains uncertain and strips selected-secret/configuration
completion evidence and observations where required. Observation read/close
faults do not imply absence; unexpected errors retain the existing propagation
order. No persistent history or admission semantics move into the SDK. There
is no shared shutdown manager, remote network surface, schema change or provider
cleanup operation in this implementation.

Twenty-one new targets supplement the unchanged563 accepted tests. Reviewed
plan6317385431/PASS6317432306 and TARGET PASS6317586120 precede normal owner
run39610482883:26 policy tests passed;584 package tests produced exactly21
intentional missing-policy assertions, zero errors, in43.175s. Independent
causal-red PASS6317675525 confirms that initial red proves missing API, not all
deeper branches. Exact test hashes are retained in the PR; targets are unchanged
through source implementation. The subsequent normal full gate and independent
source/final review remain required. No installed Engine/native/live acceptance
is claimed by these notes. The real installed-SDK construction target intercepts
Engine calls; it is distinct from the owner gate's existing Docker witnesses.

Objects are immutable endpoint policy, current authority and operation request.
The transformation is admitted local request -> acquired verified client ->
existing effect/inspection -> bounded result -> close. Laws are endpoint
independence, transport-before-read, compatible fixed API, per-call custody,
terminal failure, no borrowed close and truthful uncertainty. The interpreter
boundary owns Docker effects; Operations still owns intent, admission and durable
history. Next work is separate client-free native qualification, then Servers2B
startup/worker handling and complete installation. This change alone does not
activate startup or satisfy live225/291/284.
