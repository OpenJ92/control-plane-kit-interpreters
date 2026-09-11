Source: [.github/workflows/tests.yml](../../../../.github/workflows/tests.yml).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This workflow delegates validation to the repository's existing `./test.sh` on pull requests, main/develop pushes and explicit dispatch. It grants only contents-read permission and cancels older runs in the same workflow/ref group. The job timeout limits the hosted job; it is not a proof of provider cleanup after cancellation.

Keep the gate as the evidence owner instead of copying stages into workflow YAML. The ordinary invocation does not set the synthetic provider opt-in. A hosted green result must be attributed to its exact source/dependency selection; it does not authorize live tests or mean a published image was exercised.

Source and governing references: [test.sh](../../../../test.sh), [test_support/tests/test_gate_contract.py](../../../../test_support/tests/test_gate_contract.py).
