Source: [test_support/tests/test_gate_contract.py](../../../../test_support/tests/test_gate_contract.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This support suite reads gate/Dockerfile/package metadata to establish repository-root anchoring, default pinned proof, explicit local-Core override, one metadata-owned Core coordinate and the expected integrity/import stages. It contains an intentional selected-Core requirement assertion, which must move with a real dependency adoption.

The tests mostly inspect source text; they do not execute every shell branch or establish that an EXIT trap preserves failure. The actual final controller and completion marker remain necessary runtime gate evidence. Update this suite with a reviewed gate contract change, not to bless an accidental alternative runner.

Source and governing references: [test.sh](../../../../test.sh), [Dockerfile](../../../../Dockerfile), [pyproject.toml](../../../../pyproject.toml).

The selected-Core witness follows issue #150's adoption of reviewed Core merge `95452249d0340707a5cdffe737e34669e9d53165`. Only its expected coordinate changes: pyproject still owns the sole exact Core requirement, Dockerfile installs the declared test extra, and no second pin is introduced into the gate or Dockerfile. All existing assertions remain intact. This metadata assertion does not replace successful dependency installation, retained behavioral tests or the owning gate's final completion/cleanup evidence. It does not claim that new Core health contracts have an implemented interpreter transport.
