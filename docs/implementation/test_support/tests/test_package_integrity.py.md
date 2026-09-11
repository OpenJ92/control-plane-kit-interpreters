Source: [test_support/tests/test_package_integrity.py](../../../../test_support/tests/test_package_integrity.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This file uses temporary source/gate/approval specimens to test the integrity scanner itself. Its laws distinguish visible unittest collection from hidden/nested/aliased forms, justified dynamic skips from unconditional/literal/stale entries, real test bodies from placeholders or swallowed exceptions, and reported mocks from invalid findings.

The specimens intentionally contain rejected patterns; they are inputs to the scanner, not implementation policy to imitate. Positive scanner evidence is not package-test execution, test completeness or provider acceptance. Preserve both permitted ordinary helper constructs and rejected proof-changing forms when changing AST logic.

Source and governing references: [test_support/package_integrity.py](../../../../test_support/package_integrity.py), [tests/approved_skips.json](../../../../tests/approved_skips.json).
