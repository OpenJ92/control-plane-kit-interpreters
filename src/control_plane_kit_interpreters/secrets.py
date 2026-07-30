"""Runtime-only interpretation for core secret delivery values."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Mapping, Protocol, TypeAlias

from control_plane_kit_core.runtime_effects import ImagePullAuthority
from control_plane_kit_core.secrets import (
    AuthorizedSecretResolver,
    SecretDelivery,
    SecretEnvironmentDelivery,
    SecretFileDelivery,
    SecretFileMode,
    SecretReference,
    SecretReferenceEnvironmentDelivery,
    SecretResolutionCode,
    SecretResolutionError,
    SecretResolutionGrant,
    SecretResolver,
    SecretUseIntent,
    SecretValue,
    require_authorized_secret,
    require_resolved_secret,
)


_MAX_OCI_CREDENTIAL_BYTES = 16_384
_MAX_OCI_CREDENTIAL_FIELD_BYTES = 4_096


@dataclass(frozen=True, repr=False)
class ResolvedImagePullCredential:
    """Ephemeral OCI registry credential resolved only by runtime interpreters."""

    username: str | None = None
    password: SecretValue | None = None
    identitytoken: SecretValue | None = None

    def __post_init__(self) -> None:
        if self.identitytoken is not None:
            if not isinstance(self.identitytoken, SecretValue):
                raise SecretResolutionError(
                    SecretResolutionCode.INVALID_RESOLVER_RESULT,
                    "image pull identity token is malformed",
                )
            if self.username is not None or self.password is not None:
                raise SecretResolutionError(
                    SecretResolutionCode.INVALID_RESOLVER_RESULT,
                    "image pull credential must use either identity token or username/password",
                )
            return
        if not isinstance(self.username, str) or not self.username.strip():
            raise SecretResolutionError(
                SecretResolutionCode.INVALID_RESOLVER_RESULT,
                "image pull credential username is malformed",
            )
        if not isinstance(self.password, SecretValue):
            raise SecretResolutionError(
                SecretResolutionCode.INVALID_RESOLVER_RESULT,
                "image pull credential password is malformed",
            )

    def __repr__(self) -> str:
        return "ResolvedImagePullCredential(<redacted>)"


@dataclass(frozen=True)
class ImagePullCredentialResolved:
    credential: ResolvedImagePullCredential

    def __post_init__(self) -> None:
        if not isinstance(self.credential, ResolvedImagePullCredential):
            raise SecretResolutionError(
                SecretResolutionCode.INVALID_RESOLVER_RESULT,
                "image pull credential resolver returned malformed credential",
            )


@dataclass(frozen=True)
class ImagePullCredentialMissing:
    reference: SecretReference

    def __post_init__(self) -> None:
        if not isinstance(self.reference, SecretReference):
            raise TypeError("missing image pull credential requires SecretReference")


@dataclass(frozen=True)
class ImagePullCredentialDenied:
    reference: SecretReference

    def __post_init__(self) -> None:
        if not isinstance(self.reference, SecretReference):
            raise TypeError("denied image pull credential requires SecretReference")


ImagePullCredentialResolution: TypeAlias = (
    ImagePullCredentialResolved | ImagePullCredentialMissing | ImagePullCredentialDenied
)


class ImagePullCredentialResolver(Protocol):
    """Runtime authority for resolving OCI pull credentials at interpreter IO."""

    def resolve(self, authority: ImagePullAuthority) -> ImagePullCredentialResolution: ...


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


def secret_resolution_grant_for(
    grants: tuple[SecretResolutionGrant, ...],
    reference: SecretReference,
    intent: SecretUseIntent,
) -> SecretResolutionGrant:
    """Select one exact committed grant without revealing reference material."""

    matches = tuple(
        grant
        for grant in grants
        if grant.permits(reference, intent)
    )
    if len(matches) != 1:
        raise SecretResolutionError(
            SecretResolutionCode.DENIED,
            "secret resolution requires one exact committed grant",
        )
    return matches[0]


def resolve_authorized_secret_deliveries(
    deliveries: tuple[SecretDelivery, ...],
    *,
    grants: tuple[SecretResolutionGrant, ...],
    resolver: AuthorizedSecretResolver,
) -> ResolvedSecretDeliveries:
    """Resolve value-bearing deliveries through their exact committed grants."""

    environment: dict[str, str] = {}
    files: list[SecretFileRuntimeMaterial] = []
    for delivery in deliveries:
        match delivery:
            case SecretEnvironmentDelivery(
                environment_name=name,
                reference=reference,
                intent=intent,
            ):
                grant = secret_resolution_grant_for(grants, reference, intent)
                _put_environment(
                    environment,
                    name,
                    require_authorized_secret(resolver, grant).reveal(),
                )
            case SecretReferenceEnvironmentDelivery(
                environment_name=name,
                reference=reference,
            ):
                _put_environment(environment, name, reference.reference_id)
            case SecretFileDelivery(
                target_path=target_path,
                reference=reference,
                intent=intent,
                file_mode=file_mode,
                path_binding=path_binding,
            ):
                grant = secret_resolution_grant_for(grants, reference, intent)
                files.append(
                    SecretFileRuntimeMaterial(
                        reference,
                        target_path,
                        require_authorized_secret(resolver, grant),
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


def parse_image_pull_credential(value: SecretValue) -> ResolvedImagePullCredential:
    """Decode one bounded provider secret into the two supported OCI auth shapes."""

    if not isinstance(value, SecretValue):
        raise SecretResolutionError(
            SecretResolutionCode.INVALID_RESOLVER_RESULT,
            "image pull credential is malformed",
        )
    encoded = value.reveal().encode("utf-8")
    if not encoded or len(encoded) > _MAX_OCI_CREDENTIAL_BYTES:
        raise SecretResolutionError(
            SecretResolutionCode.INVALID_RESOLVER_RESULT,
            "image pull credential is malformed",
        )
    try:
        decoded = json.loads(
            encoded,
            object_pairs_hook=_unique_json_object,
        )
    except (TypeError, ValueError, UnicodeDecodeError):
        raise SecretResolutionError(
            SecretResolutionCode.INVALID_RESOLVER_RESULT,
            "image pull credential is malformed",
        ) from None
    if not isinstance(decoded, dict):
        raise SecretResolutionError(
            SecretResolutionCode.INVALID_RESOLVER_RESULT,
            "image pull credential is malformed",
        )
    if set(decoded) == {"identitytoken"}:
        return ResolvedImagePullCredential(
            identitytoken=SecretValue(_credential_field(decoded["identitytoken"])),
        )
    if set(decoded) == {"username", "password"}:
        return ResolvedImagePullCredential(
            username=_credential_field(decoded["username"]),
            password=SecretValue(_credential_field(decoded["password"])),
        )
    raise SecretResolutionError(
        SecretResolutionCode.INVALID_RESOLVER_RESULT,
        "image pull credential is malformed",
    )


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("duplicate key")
        values[key] = value
    return values


def _credential_field(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_OCI_CREDENTIAL_FIELD_BYTES
    ):
        raise SecretResolutionError(
            SecretResolutionCode.INVALID_RESOLVER_RESULT,
            "image pull credential is malformed",
        )
    return value


def _put_environment(values: dict[str, str], name: str, value: str) -> None:
    previous = values.setdefault(name, value)
    if previous != value:
        raise SecretResolutionError(
            SecretResolutionCode.MALFORMED_REFERENCE,
            "secret delivery environment names conflict",
        )
