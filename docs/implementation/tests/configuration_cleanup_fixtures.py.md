Source: [configuration_cleanup_fixtures.py](../../../tests/configuration_cleanup_fixtures.py).
Maintain this document alongside its source file. When source or relevant imported contracts change, verify and update this companion in the same change.

The fixture supplies provider volume metadata, exact non-forced removals and all-state mounted-volume rows over the existing fake provider. It uses real Core cleanup requests and B2 physical naming/ownership; it does not implement cleanup classification, admission, reservations or a second lifecycle. API conflicts use Docker's actual APIError type. No daemon is reachable in these package tests.
