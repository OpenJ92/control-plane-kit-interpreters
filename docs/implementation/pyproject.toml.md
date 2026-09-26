Source: [pyproject.toml](../../pyproject.toml).

Current #169 adoption selects Core `f1e6cf2420bf2ec381aab745f462d4e64baef5fc`
and test-only Secrets `43b742d1ecb4b7b1fbabb62890a4045afa7a2fec`. That reviewed
Secrets #36 merge selects SDK `22f1267bde5015efe2fea4f07be4ce8ddf83bc0c`
and the identical Core URL. Existing exact metadata/installed-provenance
expectations move together; functional source, provider opt-in and the ordinary
Docker gate are unchanged. The test-only Servers installation remains
`77deffd9b32698a1deb2fa173f6c958e6c441f9b` with `--no-deps`, as declared in
Dockerfile; earlier fixture and dependency coordinates below are historical.
Core's e074→f1e delta concerns operations reobserve/waiting/restart and saga
journal handling. Those owners are not implemented or imported here; this
adoption preserves existing health signing, gateway/managed observation and
native connection effects. Only the ordinary owning gate can establish package
compatibility. Servers must separately adopt this reviewed merge.

The early compatibility slice of #149 selects Core `b79a02d1ac8ef987dd34abeb2297a231b109f7a6`, replacing #150's coordinate below. This aligns the exact URL with accepted SDK2c5b588 and Secrets8273b7d for Servers #208's receiver-trust join. Operationsbc559a0 contains the identical Core subtree, but Servers must select its Operations archive independently and prove that installation in its own gate. This metadata change does not implement #149 signing or establish live health transport.

Issue #155 now adopts Secrets `8273b7de86dcaac254a8fcaca22b2769c5e16a4d` in the test extra to exercise both accepted health signing families. Its declared SDK `[fastapi]` dependency selects `2c5b588237fbe289c965029b4bc2f072715c42f3`, with the same Core coordinate. Existing provider fixtures supply the now-required synthetic public control configuration; their legacy readiness check and behavioral assertions remain intact.

The Docker test stage alone installs Servers `4d781b5b87464d522bd157bab491456e52449a9f` with `--no-deps` for the canonical gateway verifier. Its imported Core/crypto/FastAPI/uvicorn dependencies are supplied by the declared test composition. Tests assert exact owner `direct_url` metadata and local candidate Interpreter origin. This limited fixture installation deliberately does not claim complete Servers dependency compatibility: resolving its pinned Interpreter would replace the candidate under test. Servers and Operations are not runtime Interpreter dependencies. The ordinary Docker gate remains unchanged; actual selected-artifact mounting is held under #156 and is not proved by recording-client tests.
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This is the package distribution and dependency-selection boundary. The base dependency is the exact Core archive selected here; runtime backends are optional extras. The Docker extra accepts a range rather than pinning Docker7.2.0, and the test extra also imports a selected Secrets test distribution. Check the actual installed environment before attributing version-specific SDK behavior.

Do not duplicate Core archive coordinates in the Dockerfile or gate. A dependency-pin or optional-extra change requires reviewing affected source companions even without editing their Python files. Keep the root package lightweight and the py.typed marker included. Package/version metadata and an installed dependency do not by themselves establish public compatibility or provider success.

Source and governing references: [Dockerfile](../../Dockerfile), [test_support/tests/test_gate_contract.py](../../test_support/tests/test_gate_contract.py), [src/control_plane_kit_interpreters/__init__.py](../../src/control_plane_kit_interpreters/__init__.py).

Issue #150 adopts reviewed Core merge `95452249d0340707a5cdffe737e34669e9d53165`, replacing issue #145's `e3e29995` coordinate. This aligns the exact Core URL with SDK `2b10d5a` for the subsequent Servers #193 dependency adoption; Interpreters itself gains no SDK dependency.

The inspected Core interval adds optional health reads, V2 declarations/results, dedicated health request/result/transit contracts, routes and key purposes. Legacy surfaces default to no health reads and retain V1 shape; health declarations require the explicit health-checkable capability. Operations source is unchanged across this interval, and Interpreters has no Operations dependency. Availability of new enum values is not implemented health transport, signing or issuer-selection authority. Existing gateway canonical signing, key/audience binding, denial before I/O, Docker uncertainty/cleanup classification and secret-delivery behavior remain owned by their existing interpreter tests.

Historically, #150/#154 retained Secrets `96e86dc3248d578780d64d5d7fc5d6359631d1d6`, whose base/test metadata introduced no conflicting Core requirement. #155's test-only adoption above supersedes that selection. Ordinary pinned-suite evidence includes the established local synthetic-secret witness and exact owning cleanup, with StartNode provider opt-in disabled. It does not establish external provider or published-product acceptance. Servers must separately adopt the accepted Interpreters commit through its coordinate generator; this change alone does not complete downstream consumption or authorize image publication.

Issue #164 resumed after the separately reviewed SDK #34 and Secrets #33
adoptions: the test extra then selected Secrets
`f781f59c2610c63be76716380f34e2d8c9fe8805`, which selects SDK
`d8b72e52c8ebca65bf21a2a2ae51df663b1c8a77` and the same Core
`e074bda49fa0c46f420d675e45a93f787b460c02` as this package. The existing
health-signing provenance test advances both installed-owner expectations.
The earlier #155/#149 coordinates above are historical. This corrects the
incompatible direct Core URLs that stopped package collection; the ordinary
owner gate must still establish genuine observer target-red. No installer,
fixture, functional source, unrelated pin or authority changes accompany it.
