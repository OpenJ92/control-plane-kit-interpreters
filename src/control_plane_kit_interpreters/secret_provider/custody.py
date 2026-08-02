"""Generated-secret custody at the concrete provider IO boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from control_plane_kit_core.secrets import (
    SecretCustodyGrant,
    SecretCustodyReceipt,
    SecretCustodyStatus,
    SecretProviderEndpointReference,
    SecretReference,
    SecretValue,
    SecretVersionRevocationGrant,
    SecretVersionRevocationReceipt,
)

from .bootstrap import SecretProviderBootstrapRegistry
from .client import (
    ControlPlaneKitSecretsClient,
    SecretProviderClientCode,
    SecretProviderClientError,
    SecretProviderClientPolicy,
)


@dataclass(frozen=True, repr=False)
class ControlPlaneKitSecretsCustodian:
    """Write generated values directly to admitted provider custody."""

    bootstrap_registry: SecretProviderBootstrapRegistry
    policy: SecretProviderClientPolicy = field(
        default_factory=SecretProviderClientPolicy
    )
    transport: Any | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(
            self.bootstrap_registry,
            SecretProviderBootstrapRegistry,
        ):
            raise TypeError("secret custodian requires bootstrap registry")
        if not isinstance(self.policy, SecretProviderClientPolicy):
            raise TypeError("secret custodian requires provider client policy")

    def store(
        self,
        grant: SecretCustodyGrant,
        value: SecretValue,
    ) -> SecretCustodyReceipt:
        if not isinstance(grant, SecretCustodyGrant):
            raise TypeError("secret custody requires SecretCustodyGrant")
        if not isinstance(value, SecretValue):
            raise TypeError("secret custody requires SecretValue")
        metadata = self._client(grant).write(
            workspace_id=grant.workspace_id,
            reference=grant.reference,
            value=value,
            intent=grant.intent,
            caller_subject=grant.actor_subject,
            correlation_id=grant.correlation_id,
        )
        return SecretCustodyReceipt(
            custody_id=grant.custody_id,
            provider_registration_id=grant.provider_registration_id,
            reference=metadata.reference,
            version_id=metadata.version_id,
            version_number=metadata.version_number,
            status=SecretCustodyStatus(metadata.status),
        )

    def revoke(self, grant: SecretCustodyGrant) -> None:
        if not isinstance(grant, SecretCustodyGrant):
            raise TypeError("secret custody revocation requires SecretCustodyGrant")
        try:
            revoked = self._client(grant).revoke(
                workspace_id=grant.workspace_id,
                reference=grant.reference,
                caller_subject=grant.actor_subject,
                correlation_id=f"{grant.correlation_id}:revoke",
            )
        except SecretProviderClientError as error:
            if error.code is SecretProviderClientCode.MISSING:
                return
            raise
        if revoked.reference != grant.reference:
            raise RuntimeError("secret custody revocation returned mismatched reference")

    def revoke_version(
        self,
        grant: SecretVersionRevocationGrant,
    ) -> SecretVersionRevocationReceipt:
        if not isinstance(grant, SecretVersionRevocationGrant):
            raise TypeError(
                "exact secret revocation requires SecretVersionRevocationGrant"
            )
        metadata = self._client_for(
            endpoint_reference=grant.endpoint_reference,
            credential_reference=grant.credential_reference,
        ).revoke_version(
            workspace_id=grant.workspace_id,
            reference=grant.reference,
            version_id=grant.version_id,
            version_number=grant.version_number,
            caller_subject=grant.actor_subject,
            correlation_id=grant.correlation_id,
        )
        return SecretVersionRevocationReceipt(
            revocation_id=grant.revocation_id,
            provider_registration_id=grant.provider_registration_id,
            reference=metadata.reference,
            version_id=metadata.version_id,
            version_number=metadata.version_number,
            status=SecretCustodyStatus(metadata.status),
        )

    def _client(
        self,
        grant: SecretCustodyGrant,
    ) -> ControlPlaneKitSecretsClient:
        return self._client_for(
            endpoint_reference=grant.endpoint_reference,
            credential_reference=grant.credential_reference,
        )

    def _client_for(
        self,
        *,
        endpoint_reference: SecretProviderEndpointReference,
        credential_reference: SecretReference,
    ) -> ControlPlaneKitSecretsClient:
        configuration = self.bootstrap_registry.configuration_for(
            endpoint_reference=endpoint_reference,
            credential_reference=credential_reference,
        )
        return ControlPlaneKitSecretsClient(
            configuration,
            policy=self.policy,
            transport=self.transport,
        )

    def __repr__(self) -> str:
        return "ControlPlaneKitSecretsCustodian(<redacted>)"
