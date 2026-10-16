"""Grant-bound secret resolution through the durable provider client."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from control_plane_kit_core.secrets import (
    SecretDenied,
    SecretMissing,
    SecretResolution,
    SecretResolved,
)
from control_plane_kit_core.secret_version_grants import (
    ResolutionGrant, SecretVersionResolutionGrant, validate_resolution_grant,
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

    def resolve(self, grant: ResolutionGrant) -> SecretResolution:
        valid = False
        try:
            validate_resolution_grant(grant)
            valid = True
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise SecretProviderClientError(SecretProviderClientCode.MALFORMED_REQUEST)
        selected = type(grant) is SecretVersionResolutionGrant
        reference = grant.selection.reference if selected else grant.reference
        intent = grant.selection.intent if selected else grant.intent
        version_id = grant.selection.version_id if selected else None
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
                reference=reference,
                intent=intent,
                caller_subject=grant.actor_subject,
                correlation_id=grant.correlation_id,
                version_id=version_id,
            )
        except SecretProviderClientError as error:
            if error.code is SecretProviderClientCode.MISSING:
                return SecretMissing(reference)
            if error.code in {
                SecretProviderClientCode.DENIED,
                SecretProviderClientCode.REVOKED,
            }:
                return SecretDenied(reference)
            raise
        return SecretResolved(resolved.metadata.reference, resolved.value)

    def __repr__(self) -> str:
        return "ControlPlaneKitSecretsResolver(<redacted>)"
