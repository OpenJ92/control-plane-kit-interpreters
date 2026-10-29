Interpreters #232 selects accepted Core
`c7b16007467085be997f8dc3025e90e78649b00a` and normal fixture Secrets
`cf2827a73c6b7b082aa5942904fd7b8f92da690d` / SDK
`3192360c36934feadc37bb9ae3733ce7da755c31`. Existing runner and fixture behavior
are preserved. See [the policy client contract](../../../secret-provider-policy.md) for the separate
E wire mapping and bounded validation status. Older entries below are history.

Source: [test_support/tests/test_gate_contract.py](../../../../test_support/tests/test_gate_contract.py).

Interpreters #230 advances CORE_REQUIREMENT to accepted Core
`fec0816281aeb83ede98616adcc4f96dfe5777a8`. Exact equality, normal pinned
resolution, runner and provider-opt-in assertions are unchanged. Existing
Docker validation establishes dependency adoption; no pin-mirror test or
artificial target-red is added.

Historical Interpreters #214 advances CORE_REQUIREMENT to accepted Core
`955666898218e4f2956b6e9fcd33bdba97ffdb06`, matching the sole metadata-owned
Core URL. Exact equality, pinned resolution, runner and provider-opt-in
assertions remain unchanged. This pin-only prerequisite is not semantic red;
the new observation targets must establish that independently.

Historical Interpreters #211 advances only CORE_REQUIREMENT to accepted Core
`ec61e2b17c3a3f1bdea1dd6bc8fc64ac1b9528b0`, matching the direct dependency.
Exact equality, pinned resolution, gate and provider-opt-in assertions remain
unchanged. This mechanical alignment needs no artificial target-red.
Ordinary owning-gate validation remains pending at this source checkpoint.

Historical Interpreters #207 advances only CORE_REQUIREMENT to accepted Core
`73d87e99bf711ff8a88112ca56c5eee8055ac5b7`. Exact equality, pinned resolution,
gate and provider-opt-in assertions are unchanged. The ordinary owning gate
must validate the new dependency combination; no artificial red is required.

Historical Interpreters #205 advances only CORE_REQUIREMENT to accepted Core
`9861e536e79314005499ae07379f627bfb1599a2`. Existing exact equality, pinned
resolution, gate and provider-opt-in assertions remain unchanged. This is a
coordinate adoption; normal owning-gate evidence remains required.

Historical Interpreters #190/#191 advances CORE_REQUIREMENT to actual accepted Core
`87e231c661879e44816ba71ff9320c040c868d60`. Exact equality, gate assertions,
normal pinned mode and provider opt-in semantics remain unchanged. The first
attempt caught the stale prior expected coordinate before package collection;
its reviewed correction is a fixture premise, not behavioral red evidence.

Historical Interpreters #198 / Servers #251 advances only CORE_REQUIREMENT
to accepted Core `05b5f28a624e6e03f1dadbe6ad77ece2bec09601`, matching package
metadata. All existing gate assertions, normal pinned resolution and provider
opt-in semantics are unchanged. Mechanical pin alignment needs no artificial
red; the unchanged owning gate must establish package compatibility.

Historical I186 advances only CORE_REQUIREMENT to accepted shared Core
`ba0bd45e7fa7673b837366f7f5da5f9159b0dee8`, alongside actual metadata.
All gate assertions and the owning runner remain unchanged. This mechanical
prerequisite supports causal missing-receipt targets; it is not itself red evidence.

Historical #180 changes only CORE_REQUIREMENT to accepted Core
`da17efb1303ed2176374548dd998d19a655055bf`. All five existing contract tests
and assertions remain unchanged. The old metadata fails the coordinate assertion
before adoption; package and real-witness phases are not reached in that red
run. Green must come through the unchanged pinned Docker gate, including its
final completion and cleanup marker. No new gate, installer or provider opt-in
is introduced.

Historical #175 adoption changed only CORE_REQUIREMENT to the accepted Core
`250d65e19dc748ebe840f705be77eb732dab3cb3` archive. All five existing contract
tests and their assertions remain intact; no installer, fixture, gate or
provider-opt-in change. Earlier adoption coordinates below are historical.
This I-A source candidate is not yet executable-green; actual paired S-B/I-C
whole gates remain required. No runner or gate-contract assertion is changed.

The early #149 compatibility prerequisite updates only the expected Core coordinate to `b79a02d1ac8ef987dd34abeb2297a231b109f7a6`. Existing assertions and gate semantics stay intact. The ordinary pinned Docker suite must establish actual installation and behavioral compatibility; this selected-coordinate witness does not implement health signing, transport or deployment.
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This support suite reads gate/Dockerfile/package metadata to establish repository-root anchoring, default pinned proof, explicit local-Core override, one metadata-owned Core coordinate and the expected integrity/import stages. It contains an intentional selected-Core requirement assertion, which must move with a real dependency adoption.

The tests mostly inspect source text; they do not execute every shell branch or establish that an EXIT trap preserves failure. The actual final controller and completion marker remain necessary runtime gate evidence. Update this suite with a reviewed gate contract change, not to bless an accidental alternative runner.

Source and governing references: [test.sh](../../../../test.sh), [Dockerfile](../../../../Dockerfile), [pyproject.toml](../../../../pyproject.toml).

The selected-Core witness follows issue #150's adoption of reviewed Core merge `95452249d0340707a5cdffe737e34669e9d53165`. Only its expected coordinate changes: pyproject still owns the sole exact Core requirement, Dockerfile installs the declared test extra, and no second pin is introduced into the gate or Dockerfile. All existing assertions remain intact. This metadata assertion does not replace successful dependency installation, retained behavioral tests or the owning gate's final completion/cleanup evidence. It does not claim that new Core health contracts have an implemented interpreter transport.
