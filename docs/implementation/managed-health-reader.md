# Admitted managed health composition (#189)

`docker.managed_health.DockerManagedHealthReader` accepts the original Core
`RuntimeEffectRequest`, plan and validated snapshots, independently reloaded
current authority, original signing context/grants/keys, and selected destination.
It owns no admission, transaction, persistence or endpoint discovery. Operations
still records intent and attempts, exits transactions, reloads authority and
folds correlated results. Servers #250 supplies that owner's composition bridge.

```python
reader = DockerManagedHealthReader(signer, signed_gateway_client, local_client)
result = await reader.observe(
    request, plan=accepted_plan, current=current, desired=desired,
    authority_context=current_authority, context=original_context,
    transit_grant=original_transit, workload_grant=original_workload,
    transit_key=current_transit_key, workload_key=current_workload_key,
    local_destination=SelectedLocalGateway(endpoint, private_address_policy),
)
```

This example is a local-ready call. Protected workload/path/ingress reads supply
`destination=selected_gateway` instead. A missing, foreign or ambiguous selection
refuses before signing. The pure guard extracted from `DockerManagedHealthObserver`
checks the original plan/activity, graph side, authored revision, Docker runtime,
installed receiver/declaration, gateway identity and current authority. The
existing observer's local/native refusal remains unchanged; only this composition
opts into local selection. Public destination structure is also checked before
signing. The existing signer validates both original grant/key families before
resolving either key, then signs once without renewal. The public branch invokes
the existing observer and signed relay client with the unchanged values.

`probes.local_health.LocalGatewayHealthClient` authorizes an independently supplied
literal runtime-private endpoint for the exact gateway/readiness socket and
authored revision. Its explicit allowlist is necessary but does not establish
endpoint provenance. It sends one protected readiness GET with the original
workload bearer. The original pair/window checks and strict bounded correlated
result decoder are shared with the public transport. It has one transport deadline
of at most five seconds, no redirects or proxy inheritance, and closes its
response/client on success, failure, timeout and cancellation. Cancellation
propagates; other failures expose only a closed code. All four semantic health
outcomes remain distinct from nonsemantic failures. Signing uses the existing
synchronous resolver contract and is not covered by the network deadline.

`select(plan=..., current=..., desired=...)` returns the complete tuple of supported
health activity IDs, or `None` if any required health stage is unsupported. Native
connector observations and legacy `WaitForHealthy` refuse the whole selection.
This adapter supplies no native observer. S2 must preserve the owner's complete
selection rule and separately qualify any native port before advertising support.

Local means reachable from the Interpreter process, not the Docker daemon.
`RuntimeEndpointObservation` alone is not reachability proof. S2 must supply
endpoint provenance and qualified network placement, or report missing/unsupported
input before dispatch. Docker Desktop and remote-TLS daemon addresses are not
silently translated to localhost. Unreachable supplied endpoints fail boundedly;
there is no helper/exec, scan, fallback, retry, port publication or network change.

The [target companion](tests/test_managed_health_reader.py.md) identifies the
real gateway and receiver socket witnesses and their limits. Public ingress in
the relay witness is ASGI substituted; outgoing relay HTTP uses an actual socket.
Loopback evidence establishes neither public TLS nor production Docker routing.

Security/data/history: no new production listener, credential family, authority,
durable state or provider mutation. Credentials stay ephemeral and are absent from
returned failures. The caller owns authority freshness, admission and provenance;
the receiver still authenticates credentials. Original tunnel/DNS/token and images
are untouched. Parents #148 and Servers #237/#225 remain open for production
composition, native/provider readiness, legacy retirement and live acceptance.
