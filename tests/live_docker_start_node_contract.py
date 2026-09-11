"""Opt-in provider contract fixture; contains no production runtime behavior."""


class ProviderContractObservation:
    """Observe one recipient create and forbid pulls during its fixture phase."""

    def __init__(self, sdk, recipient_name, record=None):
        self.sdk = sdk
        self.recipient_name = recipient_name
        self.record = record

    def __enter__(self):
        raise NotImplementedError("provider contract observation is not implemented")

    def __exit__(self, exc_type, exc, traceback):
        return False

    def report(self):
        raise NotImplementedError("provider contract report is not implemented")
