"""Shared timing laws for bounded verification attempts."""

from __future__ import annotations

import time
from collections.abc import Iterator

from control_plane_kit_core.verification import VerificationPolicy


def verification_attempts(policy: VerificationPolicy) -> Iterator[int]:
    """Yield bounded attempt ordinals with policy cadence between attempts."""

    if not isinstance(policy, VerificationPolicy):
        raise TypeError("verification attempts require VerificationPolicy")
    for attempt in range(1, policy.maximum_attempts + 1):
        if attempt > 1:
            time.sleep(policy.interval_seconds)
        yield attempt
