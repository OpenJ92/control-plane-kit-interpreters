Source: [test_support/package_integrity.py](../../../test_support/package_integrity.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This AST-based gate support scans source/tests and declared gate files, reports collected test identities and mock locations, and rejects hidden collection, placeholder tests, disallowed skips, mutable legacy imports and proof-changing gate options. Its report is repository test-integrity evidence; it does not execute tests or prove their assertions adequate.

Approved dynamic skips come from the explicit identity/reason document and must correspond to actual tests. Mocks are reported as evidence context, not automatically condemned. Preserve these distinctions when adjusting the scanner; do not let stricter syntax rules become a substitute for understanding test ownership. The CLI emits findings and fails on an invalid report. Gate invocation supplies the actual repository/source/test roots.

Source and governing references: [test.sh](../../../test.sh), [tests/approved_skips.json](../../../tests/approved_skips.json), [test_support/tests/test_package_integrity.py](../../../test_support/tests/test_package_integrity.py).
