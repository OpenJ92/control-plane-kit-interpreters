Source: [tests/test_package_boundary.py](../../../tests/test_package_boundary.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This file checks repository ownership using parsed import roots and a literal product-name scan. It rejects source imports of Operations, Secrets implementation, server process packages and FastAPI, confines psycopg imports to verification.py, and keeps the package root free of Docker SDK imports.

These are static evidence checks. The literal-name test is a deliberately narrow repository rule, not semantic proof that arbitrary dynamic code is generic. Preserve ownership constraints without treating fixture strings as universal Core laws; supplement import-time behavior with the scaffold tests rather than assuming AST inspection observes runtime effects.

Source and governing references: [src/control_plane_kit_interpreters/boundaries.py](../../../src/control_plane_kit_interpreters/boundaries.py), [tests/test_scaffold.py](../../../tests/test_scaffold.py).
