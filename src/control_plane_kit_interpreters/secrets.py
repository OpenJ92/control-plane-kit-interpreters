"""Runtime-only interpretation for core secret delivery values."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from control_plane_kit_core.secrets import (
    SecretDelivery,
    SecretEnvironmentDelivery,
    SecretFileDelivery,
    SecretFileMode,
    SecretReference,
    SecretReferenceEnvironmentDelivery,
    SecretResolutionCode,
    SecretResolutionError,
    SecretResolver,
    SecretValue,
    require_resolved_secret,
)


@dataclass(frozen=True)
class SecretFileRuntimeMaterial:
    reference: SecretReference
    target_path: str
    value: SecretValue
    file_mode: SecretFileMode
    path_environment_name: str | None = None


@dataclass(frozen=True)
class ResolvedSecretDeliveries:
    environment: Mapping[str, str]
    files: tuple[SecretFileRuntimeMaterial, ...]

    def __repr__(self) -> str:
        return (
            "ResolvedSecretDeliveries("
            f"environment_names={tuple(sorted(self.environment))!r}, "
            f"files={self.files!r})"
        )


def resolve_secret_deliveries(
    deliveries: tuple[SecretDelivery, ...],
    *,
    resolver: SecretResolver | None,
) -> ResolvedSecretDeliveries:
    if deliveries and resolver is None:
        raise SecretResolutionError(
            SecretResolutionCode.MISSING,
            "secret resolver is not configured",
        )

    environment: dict[str, str] = {}
    files: list[SecretFileRuntimeMaterial] = []
    for delivery in deliveries:
        match delivery:
            case SecretEnvironmentDelivery(
                environment_name=name,
                reference=reference,
            ):
                assert resolver is not None
                _put_environment(
                    environment,
                    name,
                    require_resolved_secret(resolver, reference).reveal(),
                )
            case SecretReferenceEnvironmentDelivery(
                environment_name=name,
                reference=reference,
            ):
                _put_environment(environment, name, reference.reference_id)
            case SecretFileDelivery(
                target_path=target_path,
                reference=reference,
                file_mode=file_mode,
                path_binding=path_binding,
            ):
                assert resolver is not None
                files.append(
                    SecretFileRuntimeMaterial(
                        reference,
                        target_path,
                        require_resolved_secret(resolver, reference),
                        file_mode,
                        None
                        if path_binding is None
                        else path_binding.environment_name,
                    )
                )
                if path_binding is not None:
                    _put_environment(
                        environment,
                        path_binding.environment_name,
                        target_path,
                    )
    return ResolvedSecretDeliveries(environment, tuple(files))


def _put_environment(values: dict[str, str], name: str, value: str) -> None:
    previous = values.setdefault(name, value)
    if previous != value:
        raise SecretResolutionError(
            SecretResolutionCode.MALFORMED_REFERENCE,
            "secret delivery environment names conflict",
        )
