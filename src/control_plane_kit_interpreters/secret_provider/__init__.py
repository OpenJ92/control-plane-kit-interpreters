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
    SecretProviderGeneratedDelegationKey,
    SecretProviderOutcomeCertainty,
    SecretProviderResolved,
    SecretProviderRevoked,
    SecretProviderVersionMetadata,
    canonical_provider_secret_id,
)
from .custody import ControlPlaneKitSecretsCustodian
from .resolver import ControlPlaneKitSecretsResolver
from .metadata import ControlPlaneKitSecretsMetadataReader


__all__ = [
    "ControlPlaneKitSecretsClient",
    "ControlPlaneKitSecretsCustodian",
    "ControlPlaneKitSecretsResolver",
    "ControlPlaneKitSecretsMetadataReader",
    "SecretProviderBootstrapError",
    "SecretProviderBootstrapRegistry",
    "SecretProviderClientCode",
    "SecretProviderClientConfiguration",
    "SecretProviderClientError",
    "SecretProviderClientPolicy",
    "SecretProviderGeneratedDelegationKey",
    "SecretProviderOutcomeCertainty",
    "SecretProviderResolved",
    "SecretProviderRevoked",
    "SecretProviderVersionMetadata",
    "canonical_provider_secret_id",
]
