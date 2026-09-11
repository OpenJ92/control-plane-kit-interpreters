Source: [tests/approved_skips.json](../../../tests/approved_skips.json).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This authored declaration is currently an empty list: it grants no conditional test skips. The integrity scanner validates any future identity/reason entry and rejects stale or duplicate approvals. An entry is evidence policy that needs its owning decision, not a shortcut to make a failing gate green.

Unconditional and literal-condition skips remain rejected by the scanner. Preserve the distinction between a justified dynamic conditional skip and silently dropping collection or weakening assertions.

Source and governing references: [test_support/package_integrity.py](../../../test_support/package_integrity.py), [test_support/tests/test_package_integrity.py](../../../test_support/tests/test_package_integrity.py).
