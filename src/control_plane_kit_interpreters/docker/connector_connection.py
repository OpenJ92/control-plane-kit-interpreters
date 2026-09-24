"""Opt-in native reader-v1 observation; target interface scaffold for #167.

Construction is not admission. Operations owns current authority and folding.
"""
from dataclasses import dataclass


@dataclass(frozen=True, repr=False)
class DockerConnectorConnectionObserver:
    client: object
    product_reference: object
    image_reference: str
    clock: object

    def observe(self, request, *, plan, current, desired):
        raise NotImplementedError("#167 native connection observation is not implemented")
