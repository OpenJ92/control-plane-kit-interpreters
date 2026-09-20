# Pinned Docker workload health (#162)

`docker.management_health.DockerManagedHealthObserver` is an opt-in effect adapter
between existing Core selection and the original signed gateway transport. It is
not connected to the selected production coordinator by this issue.

```python
observer = DockerManagedHealthObserver(signed_gateway_client)
result = await observer.observe(
    operation, plan=accepted_plan, activity_id=activity_id, source=source,
    current=current, desired=desired, context=context, pair=pair,
    transit_grant=original_transit, workload_grant=original_workload,
    destination=selected_gateway,
)
```

The caller supplies the accepted plan and both validated snapshots, existing
`RuntimeEffectSource` authored revision identities, original #149 context/pair and
grants, and the selected installed relay destination. Construction of these values
does not prove approval, current authority, transaction exit or alias provenance.
Those responsibilities remain Operations and the #181/#1860 production caller.

The adapter obtains the expected operation from the supplied plan/activity before
calling Core's real resolver. It requires a Docker runtime and derives the exact
workspace, side-specific authored revision, node, socket, runtime, declaration,
gateway, transit socket and complete named ingress. Mismatches return one closed
redacted refusal before DNS/HTTP. The alias is receiving configuration rather than
graph truth; the caller selects it, and the actual relay enforces its correlation.

Only exact `ObserveNodeHealth` reaches that path. Bootstrap and legacy operations
return unsupported before reading protected inputs. The new adapter cannot use
Docker exec, helpers, private workload access or a fallback route; it has no Docker
client. Existing legacy helper dispatch remains unchanged and is mandatory parent
#148 retirement work when production adoption occurs.

After selection agrees, the adapter calls the actual #147 client once, passing
original values unchanged and returning its result unchanged. All four Core health
outcomes stay distinct from nonsemantic transport failures. #147 retains its single
deadline, original credential-window validation, public address/Host/SNI policy,
receiver authentication, bounded parsing and closure. Cancellation propagates.
No retry, re-signing, credential lookup or separate mutable state is introduced.

Objects: pinned operation/plan/snapshots, source identity, original signed pair,
selected gateway and correlated Core result. Transformation: rederive selection,
check congruence, dispatch once. Invalid compositions return a fixed refusal.
The adapter's output is not generic `RuntimeEffectResult` or durable history.
Operations owns admission, attempts, uncertain outcome policy and result folding.

The [target companion](docker-management-health-tests.md) records provenance and
fixture corrections. Corrected target `1886f085` passed its actual product/compiler
setup and failed exactly eight missing-adapter assertions in ordinary
CI35519295967/job106100477511; 365 existing tests and 26 support tests passed, zero
errors. Source-green evidence remains pending.

Security/data/history: no new listener, credential family, Docker authority, socket
recipient or durable mutation. Refusals contain only a closed code. The real
receivers still own signature admission. Public transport success does not prove
bootstrap completion, production invocation, image qualification or live TLS/DNS.
