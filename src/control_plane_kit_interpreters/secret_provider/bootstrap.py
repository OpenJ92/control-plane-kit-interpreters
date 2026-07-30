"""Explicit process-bootstrap configuration for durable secret providers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

from control_plane_kit_core.secrets import (
    SecretProviderEndpointReference,
    SecretReference,
)


class SecretProviderBootstrapError(ValueError):
    """Bounded bootstrap failure without endpoint or credential material."""

    def __init__(self) -> None:
        super().__init__("secret provider bootstrap configuration is unavailable")


@dataclass(frozen=True, repr=False)
class SecretProviderClientConfiguration:
    """Resolved IO configuration selected by two opaque admitted references."""

    endpoint_reference: SecretProviderEndpointReference
    base_url: str
    credential_reference: SecretReference
    credential_file: Path

    def __post_init__(self) -> None:
        if not isinstance(
            self.endpoint_reference,
            SecretProviderEndpointReference,
        ):
            raise SecretProviderBootstrapError()
        if not isinstance(self.credential_reference, SecretReference):
            raise SecretProviderBootstrapError()
        object.__setattr__(self, "base_url", _normalized_base_url(self.base_url))
        credential_file = Path(self.credential_file)
        if not credential_file.is_absolute():
            raise SecretProviderBootstrapError()
        object.__setattr__(self, "credential_file", credential_file)

    def __repr__(self) -> str:
        return "SecretProviderClientConfiguration(<redacted>)"


@dataclass(frozen=True, repr=False)
class SecretProviderBootstrapRegistry:
    """Map opaque endpoint and credential references to process configuration."""

    endpoints: Mapping[SecretProviderEndpointReference, str]
    credential_files: Mapping[SecretReference, Path]

    def __post_init__(self) -> None:
        try:
            endpoints = {
                reference: _normalized_base_url(base_url)
                for reference, base_url in self.endpoints.items()
            }
            credential_files = {
                reference: Path(path)
                for reference, path in self.credential_files.items()
            }
        except (AttributeError, TypeError, ValueError):
            raise SecretProviderBootstrapError() from None
        if (
            not endpoints
            or not credential_files
            or not all(
                isinstance(reference, SecretProviderEndpointReference)
                for reference in endpoints
            )
            or not all(
                isinstance(reference, SecretReference)
                and path.is_absolute()
                for reference, path in credential_files.items()
            )
        ):
            raise SecretProviderBootstrapError()
        object.__setattr__(self, "endpoints", MappingProxyType(endpoints))
        object.__setattr__(
            self,
            "credential_files",
            MappingProxyType(credential_files),
        )

    def configuration_for(
        self,
        *,
        endpoint_reference: SecretProviderEndpointReference,
        credential_reference: SecretReference,
    ) -> SecretProviderClientConfiguration:
        try:
            base_url = self.endpoints[endpoint_reference]
            credential_file = self.credential_files[credential_reference]
        except (KeyError, TypeError):
            raise SecretProviderBootstrapError() from None
        return SecretProviderClientConfiguration(
            endpoint_reference=endpoint_reference,
            base_url=base_url,
            credential_reference=credential_reference,
            credential_file=credential_file,
        )

    def __repr__(self) -> str:
        return (
            "SecretProviderBootstrapRegistry("
            f"endpoint_count={len(self.endpoints)}, "
            f"credential_count={len(self.credential_files)})"
        )


def _normalized_base_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise SecretProviderBootstrapError()
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise SecretProviderBootstrapError()
    try:
        port = parsed.port
    except ValueError:
        raise SecretProviderBootstrapError() from None
    if port is not None and not 1 <= port <= 65_535:
        raise SecretProviderBootstrapError()
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
