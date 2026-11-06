Current dependency selection (#234): accepted Core
`7afef43f3d3b981094e37dcb3062b6e3a4f3d674`, test Secrets
`a3ca9634574484a0018bf73b375d94fab70f169a`, and its accepted SDK
`220f63169e4bac79653937e97727406255279f7b`. This changes only dependency and
existing provenance coordinates. Runtime source, the #232 policy client, test
assertions, three-value provider fixture, extras and owning runner are unchanged.
The normal pinned Docker gate must establish this cohort's compatibility;
[issue #234](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/234)
owns its evidence. No E fixture adoption, live acceptance or image publication is
implied. Earlier selections and evidence below retain their historical coordinates.

# Exact metadata and resolution (#190)

Historical Interpreters #230 selects accepted Core
`fec0816281aeb83ede98616adcc4f96dfe5777a8`. New product-directory HTTP/parity/projection read contracts
do not change this adapter's metadata/grant inputs, exact-version resolution,
bounded redaction or no-retry semantics. Accepted Secrets/SDK pin-only changes
select the same Core; the normal Interpreter gate still must prove installation.

Historical Interpreters #214 selects accepted Core
`955666898218e4f2956b6e9fcd33bdba97ffdb06`. The added pure retained-image
compiler does not change this adapter's consumed metadata/grant contracts,
exact-version resolution, redaction or no-retry semantics. SDK/Secrets
predecessors are accepted; Interpreter installation still requires its own gate.

Historical Interpreters #211 selects accepted Core
`ec61e2b17c3a3f1bdea1dd6bc8fc64ac1b9528b0`. Declared configuration requirements
do not replace actual metadata/grant contracts or grant provider authority.
This adapter's validation, exact-version resolution, bounded errors and no-retry
semantics are unchanged. Selected Secrets/SDK dependency compatibility awaits
the unchanged owning gate; no new provider or live evidence is claimed.

Historical Interpreters #207 dependency adoption selects Core #2005 merge
`73d87e99bf711ff8a88112ca56c5eee8055ac5b7`. Its private declaration relation
and controller selection/planning changes leave consumed metadata/grant
contracts unchanged. This adapter's validation, exact-version resolution,
bounded errors and no-retry behavior are unchanged; the ordinary owning gate
must establish dependency compatibility.

Historical Interpreters #205 dependency adoption selects Core/Operations #1998 merge
`9861e536e79314005499ae07379f627bfb1599a2`. Only the Core managed-update
compiler changes; the metadata/grant contracts and this implementation remain
unchanged. The original #190 source and evidence below retain their coordinates.

The original accepted Core/Operations dependency is PR1988 merge
`87e231c661879e44816ba71ff9320c040c868d60`. This slice changes provider IO;
Docker immutable installation/recipient evidence remains #191, and the typed
Operations-port bridge plus production injection remains Servers #252.

`client.read_metadata` validates an explicit lookup before credential loading,
uses the existing bounded transport for a bodyless authenticated GET, and checks
the exact returned workspace/reference/version and closed metadata envelope.
It can report revoked metadata without resolving bytes. The bootstrap-configured
`ControlPlaneKitSecretsMetadataReader` additionally requires active status and
the selected durable `labels.intent`. All input validation precedes bootstrap
lookup. No Operations import, new DTO, registry, cached approval, or fallback is
introduced. The bridge's associated request IDs will not be provider-signed
correlation evidence: the existing provider metadata route audits the credential
subject and `not-provided` correlation.

`resolver.resolve` validates the closed Core grant union before bootstrap IO.
Operational grants retain their current reference/intent resolution. Consumer
grants send the exact selected version, caller and original correlation; the
client rejects a different returned version or use before decoding material.
Missing and revoked outcomes retain the existing bounded missing/denied values.
No automatic retry, provider rotation, or installation attestation occurs here.

Tests reuse the existing provider-client transport fixtures and real isolated
provider process. Metadata GET/auth/query/bodylessness, unavailable/substituted
metadata, malformed-input preflight, bounded errors/no retry, exact consumer
grant propagation, missing/revoked refusal, original replay and redaction are
owner laws. Existing package import and no-Operations dependency tests remain.

Causal evidence: local test-only commit
`c8b2ac73d2e6d58cab236e6e692523388f8a3b10`, unchanged pinned `./test.sh`,
26 support tests passed; 495 package tests ran in 70.147 seconds with 22
assertion failures confined to the seven new metadata/version methods and no
errors. The causes were missing metadata client/reader behavior and an explicit
wrong-version response incorrectly accepted. Compilation completed before the
package phase; clean import and real Docker witness were unreached. Later
assertions behind the missing-reader failures were not executed. New grant and
real-provider assertions added after accepted Core adoption still need green
evidence with the coherent paired implementation; this source is not yet an
accepted or deployed adapter.

Independent source review passed for the bounded metadata transport, validation
before bootstrap lookup, selected version/use checks before decoding, closed
grant validation, operational compatibility, and absence of an Operations
dependency. The malformed-input test observes no credential/transport access;
bootstrap ordering was source-reviewed rather than directly instrumented. This
review is source evidence only, not a substitute for the pending package gate,
Servers bridge proof, or Docker recipient verification.
