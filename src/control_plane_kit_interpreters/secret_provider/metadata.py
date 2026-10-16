"""Concrete provider metadata IO; composition owns Operations port adaptation."""
from dataclasses import dataclass, field

import httpx

from control_plane_kit_core.secrets import (
    SecretProviderEndpointReference, SecretReference, SecretUseIntent,
)
from .bootstrap import SecretProviderBootstrapRegistry
from .client import (
    ControlPlaneKitSecretsClient, SecretProviderClientCode, SecretProviderClientError,
    SecretProviderClientPolicy, SecretProviderVersionMetadata, _metadata_request,
)


@dataclass(frozen=True, repr=False)
class ControlPlaneKitSecretsMetadataReader:
    """Read an exact active version/use without choosing or authorizing it."""
    bootstrap_registry: SecretProviderBootstrapRegistry
    policy: SecretProviderClientPolicy = field(default_factory=SecretProviderClientPolicy)
    transport: httpx.BaseTransport | None = field(default=None, repr=False)

    def __post_init__(self):
        if (type(self.bootstrap_registry) is not SecretProviderBootstrapRegistry
                or type(self.policy) is not SecretProviderClientPolicy):
            raise SecretProviderClientError(SecretProviderClientCode.MALFORMED_CONFIGURATION)

    def read_version(self, *, workspace_id: str,
            endpoint_reference: SecretProviderEndpointReference,
            credential_reference: SecretReference, reference: SecretReference,
            version_id: str, intent: SecretUseIntent) -> SecretProviderVersionMetadata:
        _metadata_request(workspace_id, reference, version_id)
        if (type(endpoint_reference) is not SecretProviderEndpointReference
                or type(credential_reference) is not SecretReference
                or type(intent) is not SecretUseIntent):
            raise SecretProviderClientError(SecretProviderClientCode.MALFORMED_REQUEST)
        valid = False
        try:
            valid = (SecretProviderEndpointReference(endpoint_reference.reference_id) == endpoint_reference
                and SecretReference(credential_reference.reference_id) == credential_reference)
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise SecretProviderClientError(SecretProviderClientCode.MALFORMED_REQUEST)
        configuration = self.bootstrap_registry.configuration_for(
            endpoint_reference=endpoint_reference, credential_reference=credential_reference)
        observed = ControlPlaneKitSecretsClient(configuration, policy=self.policy,
            transport=self.transport).read_metadata(
                workspace_id=workspace_id, reference=reference, version_id=version_id)
        if observed.status != "active":
            raise SecretProviderClientError(SecretProviderClientCode.REVOKED)
        if observed.labels.get("intent") != intent.value:
            raise SecretProviderClientError(SecretProviderClientCode.DENIED)
        return observed

    def __repr__(self):
        return "ControlPlaneKitSecretsMetadataReader(<redacted>)"
