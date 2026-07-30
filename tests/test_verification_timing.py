from __future__ import annotations

import unittest
from unittest.mock import call, patch

from control_plane_kit_core.verification import VerificationPolicy

from control_plane_kit_interpreters.timing import verification_attempts


class VerificationAttemptTimingTests(unittest.TestCase):
    def test_policy_cadence_occurs_only_between_attempts(self) -> None:
        policy = VerificationPolicy(
            interval_seconds=1.25,
            maximum_attempts=3,
        )

        with patch("control_plane_kit_interpreters.timing.time.sleep") as sleep:
            attempts = tuple(verification_attempts(policy))

        self.assertEqual(attempts, (1, 2, 3))
        self.assertEqual(sleep.call_args_list, [call(1.25), call(1.25)])

    def test_stopping_after_success_adds_no_trailing_delay(self) -> None:
        policy = VerificationPolicy(
            interval_seconds=2.5,
            maximum_attempts=3,
        )

        with patch("control_plane_kit_interpreters.timing.time.sleep") as sleep:
            attempts = verification_attempts(policy)
            self.assertEqual(next(attempts), 1)
            attempts.close()

        sleep.assert_not_called()

    def test_requires_typed_policy(self) -> None:
        with self.assertRaisesRegex(TypeError, "VerificationPolicy"):
            tuple(verification_attempts(object()))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
