Source: [tests/test_health_signing.py](../../../tests/test_health_signing.py).

Interpreters #222 selects actual Secrets #69 merge
`78a2ed7c8abee6da31f8661993ed4c5426edd7ee` and SDK #69 merge
`43838fd0f4391428cfffa87f8c4dbd5cc6d5eab1`, sharing accepted Core
`879efb9576ac0580a6236d0a7372c036537b4dfe`. Only the two owner coordinate
constants change; exact installed archive equality, candidate source origin,
real signing/composition and denial assertions remain intact. The historical
Servers fixture is unchanged. Normal owner CI must establish actual installed
compatibility; metadata alone is not live provider or deployment evidence.

Historical Interpreters #220 advances the installed Secrets owner expectation to accepted
Secrets #66 merge `b73cfc183931c019c786885297d458a9a43c5039` and retains SDK #67 merge
`cad5cc3dacbff1da79e6cc8b4c0c88526363e033`, sharing accepted Core
`955666898218e4f2956b6e9fcd33bdba97ffdb06`. Only the Secrets URL constant changes;
archive equality, candidate origin, real signing/composition and denial
assertions remain intact. The existing Servers fixture boundary is unchanged.
The full pinned owning gate must prove installation; these expectations alone
establish neither retained-image observation nor live behavior.

Historical Interpreters #211 advances installed-owner expectations to accepted Secrets #63
merge `b30e62664da50cfdda347509a17fa70888cb169a` and SDK #65 merge
`eff09090755eb21028695f0224eec7b81f2db535`, sharing accepted Core
`ec61e2b17c3a3f1bdea1dd6bc8fc64ac1b9528b0`. Only the two coordinate constants
change. Exact installed archive equality, candidate origin, signing/composition
and denial assertions remain intact. The historical Servers fixture and its
existing `--no-deps` boundary are unchanged. Owning validation remains pending;
selected manifests alone do not prove installed compatibility or live behavior.

Historical Interpreters #207 advances installed-owner expectations to actual Secrets #61
merge `7ff1e771874e5963ee840d7148d2d4052278baa1` and SDK #63 merge
`1657cb91b143931bafcdb32108950d2bbbb66d95`, sharing Core
`73d87e99bf711ff8a88112ca56c5eee8055ac5b7`. Exact installed provenance,
candidate origin, real signing/composition and denial assertions remain intact.
The existing test-only Servers fixture and installation boundary are unchanged;
no runtime, gate or provider-opt-in change accompanies this adoption.

Historical Interpreters #205 advances installed-owner expectations to actual Secrets #59
merge `165a7dc7abd75e1ba50b9494d0f0aabf0aa3c33c` and SDK #61 merge
`d4e7c4d91c054f139e2971774ae5e37fc741262d`, sharing Core
`9861e536e79314005499ae07379f627bfb1599a2`. Exact installed provenance,
candidate origin, real signing/composition and denial assertions remain intact.
The test-only Servers fixture is unchanged; no production or gate change.

Historical Interpreters #190/#191 advances the existing installed-owner expectations to
actual accepted Secrets #53 merge `b3e6d21f1f53c3ad2fe9ec33900ddde0611e2b5a`
and SDK #55 merge `ad0582937d7e41f1e7a41295fa1de58c2ce4cba2`, both selecting Core
`87e231c661879e44816ba71ff9320c040c868d60`. Exact direct_url comparisons,
candidate-origin, real signing/composition and denial assertions are unchanged.
Test-only Servers `9921911d3939855a4f7c1989acdf7683fc8961da` remains under its
existing fixture boundary. This repairs the selected dependency closure; the
unchanged owning gate must establish Interpreter compatibility.

Historical Interpreters #198 / Servers #251 advances only installed-owner
expectations to actual accepted Secrets `28c9045c5d0aecf7471c151cae90ebb9ac88a123`
and SDK `9aa01ef7b2df6106f6ad87c1625a7feb93394b88`, selecting Core
`05b5f28a624e6e03f1dadbe6ad77ece2bec09601`. The actual signing/composition,
provenance, denial and candidate-origin assertions are unchanged. Test-only
Servers `9921911d3939855a4f7c1989acdf7683fc8961da` remains under its existing
fixture installation boundary. No override or new harness is introduced.
The owning gate proves Interpreter package compatibility; normal Servers
dependency resolution and live deployment remain separate evidence.

Historical I186 advances only installed-owner expectations to accepted Secrets
`d8849bbfe12b9c613ace71ed86531baab2695236` and SDK
`23500b1445dc6a748bd92a441e781d7f9ed90299`, both selecting Core
`ba0bd45e7fa7673b837366f7f5da5f9159b0dee8`. Existing assertion and real
composition semantics stay intact. Test-only Servers selection is unchanged.

Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

Historical #180 advances installed Secrets/SDK provenance expectations to accepted
`4242953b8e1d33a0901645fb47ebc1b18b53375f` and
`447a3c4c5a20b5c56402c813f6cfde1685eefda0`, selecting the same Core da17efb
as package metadata. All existing provenance, candidate-origin, health signing,
actual receiver composition and denial assertions stay unchanged. Servers
`9921911d3939855a4f7c1989acdf7683fc8961da` and the existing fixture installation
are unchanged. The whole owning gate must establish compatibility; metadata
adoption is not configuration replacement/cleanup or live-provider evidence.

Historical #175 I-C selected actual Servers S-B
`9921911d3939855a4f7c1989acdf7683fc8961da` only in the existing Docker test
stage and its exact installed-provenance expectation. Servers' unchanged whole
gate 36938731434 passed and received independent complete-green review.
Accepted Secrets Z `edfb8c0` and SDK U `5dc93b9` remain selected. All shipped
Interpreter source, resources, entrypoints and runtime dependency metadata stay
byte-equal to I-A `8c88dda505c1aa6c7490c0bb16c541bf524644fd`.

The existing `--no-deps` installation preserves the local candidate Interpreter
under test while exercising actual S-B gateway code; it is not evidence of
normal Servers dependency resolution. S-B's own gate proves its I-A closure.
The unchanged whole Interpreter gate must still validate this I-C candidate.
Final Servers adoption must select actual accepted I-M and rerun its whole gate;
the approved finite exception retains this S-B test witness. Target-red and
static-review history below record prior stages, not current executable green.

#175 target checkpoint preserves the complete accepted old dependency closure
and all 403 existing package methods. One new migration method requires the
actual signer to reject a lawful obsolete V1 pair before resolver, JWT signing
or HTTP effects. `tests/obsolete_health_signing_fixtures.py` owns the independent
negative specimen: historical Core values, ephemeral real keys and original
resolution links, with no Secrets configuration import or alternate signer.
Construction is outside `assertRaises(HealthCredentialSigningError)`; only
`signer.sign` is inside. Its wire meaning must survive later fixture translation.

The successor half of that same admission method addresses one retained full
receiver under two independently supplied authority contexts through the actual
gateway and SDK helpers. It is authored before source but cannot execute until
obsolete admission is refused and the released K/U/Z plus SB closure is selected.
It earns no canonical-positive red credit. All foreign-scope, deadline, denial,
bootstrap and effect laws remain in their existing owning tests, with translation
required before production implementation. The normal whole Docker runner is
unchanged; no collection failure, skip or replaced receiver may supply evidence.

This checkpoint changes targets only. Source/interface selection follows the
reviewed I175/receiving237 plan: full gateway/workload receiver targets, separate
request authority context, independent observer authority input, and canonical
V2 transit. No runtime implementation or dependency adoption is claimed here.

The subsequent #175 preimplementation target translation uses the actual common
receiver configuration for Secrets and workload fixtures, receiver HEALTH V2
requests/grants, full independent gateway targets and receiver audiences. The
process fixture selects `CPK_WRAPPER_CONFIGURATION_FILE` with public mode0444;
its private key/credential files stay0600. Real provider/SDK/gateway owners and
all existing signer assertions remain. The immutable obsolete negative helper
is unchanged. One added method strengthens full gateway scope and both authority
context mismatch refusals before material resolution. Declared archive constants
will advance only with the actual candidate pins; no nonexistent SB is invented.

The initial #175 ordinary red at70a3503 ran404 tests: all403 prior methods pass
and exactly the new obsolete-signing refusal fails with no errors. That evidence
does not execute these later translated fixtures or new canonical assertions.
They require the actual K/U/Z + SB/IC whole gate; this target translation is
reviewed before production and is not separately run against knowingly mixed
dependencies.

Static target review also corrected both configuration fixtures to import
`NodeControlVerificationConfiguration` from its actual `wrapper_configuration`
owner; accepted Core does not export it at the package root. No Core export or
compatibility facade is added. This was caught before executable validation.

The #173 dependency adoption touches only the existing installed-owner
provenance expectations in HealthSigningPrerequisiteTests. Secrets now selects
the reviewed #40 merge `7a26fdc174ceb08657ed23062bf3323f62e48f4b`; its SDK
dependency is the reviewed #42 merge `e19b7ed205d492bdae3abe7c2449732bcc4d53dc`.
The Servers verifier fixture remains at
`77deffd9b32698a1deb2fa173f6c958e6c441f9b`, installed only in the Docker test
stage with its existing no-deps boundary. Exact direct_url comparisons and the
local candidate Interpreter origin/source checks remain unchanged.

The suite uses the actual Secrets provider, SDK workload verifier and Servers
gateway verifier alongside controlled resolver/client observations. Existing
signing, denial, selected-artifact and owner-boundary assertions are untouched;
this note records the narrow dependency review, not an exhaustive new audit of
every signing case. The ordinary pinned test.sh owns executable evidence and
the separate local witness. These tests do not qualify a published image,
native supervisor or live grandparent deployment.
