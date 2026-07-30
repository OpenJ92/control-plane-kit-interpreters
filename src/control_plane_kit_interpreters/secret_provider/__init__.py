"""Concrete durable secret-provider client and bootstrap composition."""

from .bootstrap import (
    SecretProviderBootstrapError,
    SecretProviderBootstrapRegistry,
    SecretProviderClientConfiguration,
)
from .client import (
    ControlPlaneKitSecretsClient,
    SecretProviderClientCode,
    SecretProviderClientError,
    SecretProviderClientPolicy,
    SecretProviderOutcomeCertainty,
    SecretProviderResolved,
    SecretProviderRevoked,
    SecretProviderVersionMetadata,
    canonical_provider_secret_id,
)
from .custody import ControlPlaneKitSecretsCustodian


__all__ = [
    "ControlPlaneKitSecretsClient",
    "ControlPlaneKitSecretsCustodian",
    "SecretProviderBootstrapError",
    "SecretProviderBootstrapRegistry",
    "SecretProviderClientCode",
    "SecretProviderClientConfiguration",
    "SecretProviderClientError",
    "SecretProviderClientPolicy",
    "SecretProviderOutcomeCertainty",
    "SecretProviderResolved",
    "SecretProviderRevoked",
    "SecretProviderVersionMetadata",
    "canonical_provider_secret_id",
]
