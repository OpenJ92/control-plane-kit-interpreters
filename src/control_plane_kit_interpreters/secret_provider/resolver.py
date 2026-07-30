"""Grant-bound secret resolution through the durable provider client."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from control_plane_kit_core.secrets import (
    SecretDenied,
    SecretMissing,
    SecretResolution,
    SecretResolutionGrant,
    SecretResolved,
)

from .bootstrap import SecretProviderBootstrapRegistry
from .client import (
    ControlPlaneKitSecretsClient,
    SecretProviderClientCode,
    SecretProviderClientError,
    SecretProviderClientPolicy,
)


@dataclass(frozen=True, repr=False)
class ControlPlaneKitSecretsResolver:
    """Resolve one exact operations grant at the interpreter IO boundary."""

    bootstrap_registry: SecretProviderBootstrapRegistry
    policy: SecretProviderClientPolicy = field(
        default_factory=SecretProviderClientPolicy
    )
    transport: httpx.BaseTransport | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(
            self.bootstrap_registry,
            SecretProviderBootstrapRegistry,
        ):
            raise TypeError("secret resolver requires bootstrap registry")
        if not isinstance(self.policy, SecretProviderClientPolicy):
            raise TypeError("secret resolver requires provider client policy")

    def resolve(self, grant: SecretResolutionGrant) -> SecretResolution:
        if not isinstance(grant, SecretResolutionGrant):
            raise TypeError("secret resolution requires SecretResolutionGrant")
        configuration = self.bootstrap_registry.configuration_for(
            endpoint_reference=grant.endpoint_reference,
            credential_reference=grant.credential_reference,
        )
        client = ControlPlaneKitSecretsClient(
            configuration,
            policy=self.policy,
            transport=self.transport,
        )
        try:
            resolved = client.resolve(
                workspace_id=grant.workspace_id,
                reference=grant.reference,
                intent=grant.intent,
                caller_subject=grant.actor_subject,
                correlation_id=grant.correlation_id,
            )
        except SecretProviderClientError as error:
            if error.code is SecretProviderClientCode.MISSING:
                return SecretMissing(grant.reference)
            if error.code in {
                SecretProviderClientCode.DENIED,
                SecretProviderClientCode.REVOKED,
            }:
                return SecretDenied(grant.reference)
            raise
        return SecretResolved(resolved.metadata.reference, resolved.value)

    def __repr__(self) -> str:
        return "ControlPlaneKitSecretsResolver(<redacted>)"
