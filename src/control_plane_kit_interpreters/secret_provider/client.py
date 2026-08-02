"""Bounded HTTP client for the control-plane-kit-secrets provider protocol."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
import json
from pathlib import Path
import re
import time
from types import MappingProxyType
from typing import Any
from urllib.parse import quote

import httpx

from control_plane_kit_core.delegation_keys import (
    DelegationKeyAlgorithm,
    DelegationKeyPurpose,
    DelegationPublicKey,
)
from control_plane_kit_core.secrets import (
    SecretReference,
    SecretUseIntent,
    SecretValue,
)

from .bootstrap import SecretProviderClientConfiguration


_MAX_SECRET_BYTES = 64 * 1024
_MAX_REFERENCE_BYTES = 1_024
_MAX_CREDENTIAL_BYTES = 4_096
_MAX_REQUEST_BYTES = 96 * 1024
_MAX_RESPONSE_BYTES = 128 * 1024
_METADATA_KEYS = frozenset(
    {
        "workspace_id",
        "secret_id",
        "version_id",
        "version_number",
        "status",
        "algorithm",
        "key_fingerprint",
        "key_version",
        "labels",
        "created_at",
        "revoked_at",
    }
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")


class SecretProviderClientCode(StrEnum):
    MALFORMED_CONFIGURATION = "malformed-configuration"
    MALFORMED_REQUEST = "malformed-request"
    DENIED = "denied"
    MISSING = "missing"
    REVOKED = "revoked"
    ALREADY_EXISTS = "already-exists"
    CONFLICT = "conflict"
    REDIRECTED = "redirected"
    TIMED_OUT = "timed-out"
    TRANSPORT_FAILED = "transport-failed"
    RESPONSE_TOO_LARGE = "response-too-large"
    MALFORMED_RESPONSE = "malformed-response"
    INTEGRITY_FAILURE = "integrity-failure"
    UNAVAILABLE = "unavailable"


class SecretProviderOutcomeCertainty(StrEnum):
    DEFINITE = "definite"
    UNCERTAIN = "uncertain"


class SecretProviderClientError(RuntimeError):
    """Bounded provider failure without endpoint, credential, or secret material."""

    def __init__(
        self,
        code: SecretProviderClientCode,
        *,
        certainty: SecretProviderOutcomeCertainty = (
            SecretProviderOutcomeCertainty.DEFINITE
        ),
    ) -> None:
        self.code = code
        self.certainty = certainty
        super().__init__(f"secret provider request failed: {code.value}")


@dataclass(frozen=True)
class SecretProviderVersionMetadata:
    reference: SecretReference
    version_id: str
    version_number: int
    status: str
    labels: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.reference, SecretReference):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            )
        if (
            not isinstance(self.version_id, str)
            or not _IDENTIFIER.fullmatch(self.version_id)
            or type(self.version_number) is not int
            or self.version_number < 1
            or self.status not in {"active", "revoked"}
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            )
        labels = _string_mapping(self.labels)
        object.__setattr__(self, "labels", MappingProxyType(labels))


@dataclass(frozen=True, repr=False)
class SecretProviderResolved:
    metadata: SecretProviderVersionMetadata
    value: SecretValue

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, SecretProviderVersionMetadata):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            )
        if not isinstance(self.value, SecretValue):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            )

    def __repr__(self) -> str:
        return (
            "SecretProviderResolved("
            f"reference={self.metadata.reference!r}, "
            f"version_id={self.metadata.version_id!r}, "
            "value=<redacted>)"
        )


@dataclass(frozen=True)
class SecretProviderRevoked:
    reference: SecretReference
    version_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.reference, SecretReference)
            or not self.version_ids
            or any(
                not isinstance(version_id, str)
                or not _IDENTIFIER.fullmatch(version_id)
                for version_id in self.version_ids
            )
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            )


@dataclass(frozen=True)
class SecretProviderGeneratedDelegationKey:
    reference: SecretReference
    metadata: SecretProviderVersionMetadata
    purpose: DelegationKeyPurpose
    issuer: str
    correlation_id: str
    public_key: DelegationPublicKey
    replayed: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.reference, SecretReference)
            or not isinstance(self.metadata, SecretProviderVersionMetadata)
            or self.metadata.reference != self.reference
            or not isinstance(self.purpose, DelegationKeyPurpose)
            or not isinstance(self.issuer, str)
            or not _IDENTIFIER.fullmatch(self.issuer)
            or not isinstance(self.correlation_id, str)
            or not _IDENTIFIER.fullmatch(self.correlation_id)
            or not isinstance(self.public_key, DelegationPublicKey)
            or type(self.replayed) is not bool
            or self.metadata.labels.get("intent")
            != SecretUseIntent.GATEWAY_PROBE_SIGNING_KEY.value
            or self.metadata.labels.get("purpose") != self.purpose.value
            or self.metadata.labels.get("issuer") != self.issuer
            or self.metadata.labels.get("key_id") != self.public_key.key_id
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )


@dataclass(frozen=True)
class SecretProviderClientPolicy:
    connect_timeout_seconds: float = 2.0
    read_timeout_seconds: float = 5.0
    total_timeout_seconds: float = 10.0
    maximum_request_bytes: int = _MAX_REQUEST_BYTES
    maximum_response_bytes: int = _MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        for value in (
            self.connect_timeout_seconds,
            self.read_timeout_seconds,
            self.total_timeout_seconds,
        ):
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not 0 < float(value) <= 60
            ):
                raise SecretProviderClientError(
                    SecretProviderClientCode.MALFORMED_CONFIGURATION
                )
        if self.total_timeout_seconds < max(
            self.connect_timeout_seconds,
            self.read_timeout_seconds,
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_CONFIGURATION
            )
        if (
            type(self.maximum_request_bytes) is not int
            or not 1 <= self.maximum_request_bytes <= _MAX_REQUEST_BYTES
            or type(self.maximum_response_bytes) is not int
            or not 1 <= self.maximum_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_CONFIGURATION
            )


@dataclass(repr=False)
class ControlPlaneKitSecretsClient:
    """Concrete provider client; plaintext exists only in returned SecretValue."""

    configuration: SecretProviderClientConfiguration
    policy: SecretProviderClientPolicy = field(
        default_factory=SecretProviderClientPolicy
    )
    transport: httpx.BaseTransport | None = field(default=None, repr=False)
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.configuration, SecretProviderClientConfiguration):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_CONFIGURATION
            )
        if not isinstance(self.policy, SecretProviderClientPolicy):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_CONFIGURATION
            )
        if not callable(self.clock):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_CONFIGURATION
            )

    def write(
        self,
        *,
        workspace_id: str,
        reference: SecretReference,
        value: SecretValue,
        intent: SecretUseIntent,
        caller_subject: str,
        correlation_id: str,
    ) -> SecretProviderVersionMetadata:
        _request_identity(workspace_id, caller_subject, correlation_id)
        _require_reference(reference)
        if not isinstance(value, SecretValue) or not isinstance(intent, SecretUseIntent):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_REQUEST
            )
        material = value.reveal().encode("utf-8")
        if len(material) > _MAX_SECRET_BYTES:
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_REQUEST
            )
        secret_id = canonical_provider_secret_id(reference)
        response = self._request_json(
            "POST",
            _secret_path(workspace_id, secret_id),
            {
                "value_base64": base64.b64encode(material).decode("ascii"),
                "intent": intent.value,
                "labels": {},
                "caller_subject": caller_subject,
                "correlation_id": correlation_id,
            },
            mutation=True,
        )
        if set(response) != {"outcome", "metadata"} or response.get(
            "outcome"
        ) != "stored":
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )
        return _metadata(
            response["metadata"],
            workspace_id=workspace_id,
            secret_id=secret_id,
            reference=reference,
            expected_status="active",
            certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
        )

    def generate_delegation_key(
        self,
        *,
        workspace_id: str,
        reference: SecretReference,
        purpose: DelegationKeyPurpose,
        issuer: str,
        caller_subject: str,
        correlation_id: str,
    ) -> SecretProviderGeneratedDelegationKey:
        _request_identity(workspace_id, caller_subject, correlation_id)
        _require_reference(reference)
        if (
            not isinstance(purpose, DelegationKeyPurpose)
            or not isinstance(issuer, str)
            or not _IDENTIFIER.fullmatch(issuer)
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_REQUEST
            )
        secret_id = canonical_provider_secret_id(reference)
        response = self._request_json(
            "POST",
            _delegation_key_path(workspace_id, secret_id),
            {
                "secret_reference": reference.reference_id,
                "purpose": purpose.value,
                "issuer": issuer,
                "caller_subject": caller_subject,
                "correlation_id": correlation_id,
            },
            mutation=True,
        )
        expected_keys = {
            "outcome",
            "secret_reference",
            "metadata",
            "purpose",
            "issuer",
            "correlation_id",
            "key_id",
            "algorithm",
            "public_key_pem",
            "fingerprint_sha256",
            "replayed",
        }
        if (
            set(response) != expected_keys
            or response.get("outcome") != "generated"
            or response.get("secret_reference") != reference.reference_id
            or response.get("purpose") != purpose.value
            or response.get("issuer") != issuer
            or response.get("correlation_id") != correlation_id
            or type(response.get("replayed")) is not bool
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )
        metadata = _metadata(
            response["metadata"],
            workspace_id=workspace_id,
            secret_id=secret_id,
            reference=reference,
            expected_status="active",
            certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
        )
        try:
            public_key = DelegationPublicKey(
                key_id=response["key_id"],
                algorithm=DelegationKeyAlgorithm(response["algorithm"]),
                public_key_pem=response["public_key_pem"],
            )
        except (TypeError, ValueError):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            ) from None
        if response.get("fingerprint_sha256") != public_key.fingerprint_sha256:
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )
        return SecretProviderGeneratedDelegationKey(
            reference=reference,
            metadata=metadata,
            purpose=purpose,
            issuer=issuer,
            correlation_id=correlation_id,
            public_key=public_key,
            replayed=response["replayed"],
        )

    def resolve(
        self,
        *,
        workspace_id: str,
        reference: SecretReference,
        intent: SecretUseIntent,
        caller_subject: str,
        correlation_id: str,
        version_id: str | None = None,
    ) -> SecretProviderResolved:
        _request_identity(workspace_id, caller_subject, correlation_id)
        _require_reference(reference)
        if not isinstance(intent, SecretUseIntent):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_REQUEST
            )
        if version_id is not None and (
            not isinstance(version_id, str) or not _IDENTIFIER.fullmatch(version_id)
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_REQUEST
            )
        secret_id = canonical_provider_secret_id(reference)
        response = self._request_json(
            "POST",
            f"{_secret_path(workspace_id, secret_id)}/resolve",
            {
                "intent": intent.value,
                "caller_subject": caller_subject,
                "correlation_id": correlation_id,
                "version_id": version_id,
            },
            mutation=False,
        )
        if set(response) != {"outcome", "metadata", "value_base64"} or response.get(
            "outcome"
        ) != "resolved":
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            )
        metadata = _metadata(
            response["metadata"],
            workspace_id=workspace_id,
            secret_id=secret_id,
            reference=reference,
            expected_status="active",
        )
        encoded = response["value_base64"]
        if not isinstance(encoded, str):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            )
        try:
            material = base64.b64decode(encoded.encode("ascii"), validate=True)
            value = material.decode("utf-8")
        except (binascii.Error, UnicodeEncodeError, UnicodeDecodeError):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            ) from None
        if not material or len(material) > _MAX_SECRET_BYTES:
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE
            )
        return SecretProviderResolved(metadata, SecretValue(value))

    def revoke(
        self,
        *,
        workspace_id: str,
        reference: SecretReference,
        caller_subject: str,
        correlation_id: str,
    ) -> SecretProviderRevoked:
        _request_identity(workspace_id, caller_subject, correlation_id)
        _require_reference(reference)
        secret_id = canonical_provider_secret_id(reference)
        response = self._request_json(
            "POST",
            f"{_secret_path(workspace_id, secret_id)}/revoke",
            {
                "caller_subject": caller_subject,
                "correlation_id": correlation_id,
            },
            mutation=True,
        )
        if set(response) != {"outcome", "metadata"} or response.get(
            "outcome"
        ) != "revoked":
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )
        items = response["metadata"]
        if not isinstance(items, list) or not items:
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )
        metadata = tuple(
            _metadata(
                item,
                workspace_id=workspace_id,
                secret_id=secret_id,
                reference=reference,
                expected_status="revoked",
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )
            for item in items
        )
        return SecretProviderRevoked(
            reference,
            tuple(item.version_id for item in metadata),
        )

    def revoke_version(
        self,
        *,
        workspace_id: str,
        reference: SecretReference,
        version_id: str,
        version_number: int,
        caller_subject: str,
        correlation_id: str,
    ) -> SecretProviderVersionMetadata:
        """Revoke one exact provider version without affecting its siblings."""

        _request_identity(workspace_id, caller_subject, correlation_id)
        _require_reference(reference)
        if (
            not isinstance(version_id, str)
            or not _IDENTIFIER.fullmatch(version_id)
            or type(version_number) is not int
            or version_number < 1
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_REQUEST
            )
        secret_id = canonical_provider_secret_id(reference)
        response = self._request_json(
            "POST",
            (
                f"{_secret_path(workspace_id, secret_id)}/versions/"
                f"{quote(version_id, safe='')}/revoke"
            ),
            {
                "version_number": version_number,
                "caller_subject": caller_subject,
                "correlation_id": correlation_id,
            },
            mutation=True,
        )
        if set(response) != {"outcome", "metadata"} or response.get(
            "outcome"
        ) != "revoked":
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )
        metadata = _metadata(
            response["metadata"],
            workspace_id=workspace_id,
            secret_id=secret_id,
            reference=reference,
            expected_status="revoked",
            certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
        )
        if (
            metadata.version_id != version_id
            or metadata.version_number != version_number
        ):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=SecretProviderOutcomeCertainty.UNCERTAIN,
            )
        return metadata

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object],
        *,
        mutation: bool,
    ) -> dict[str, Any]:
        try:
            body = json.dumps(
                payload,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_REQUEST
            ) from None
        if len(body) > self.policy.maximum_request_bytes:
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_REQUEST
            )
        token = _read_credential(self.configuration.credential_file)
        timeout = httpx.Timeout(
            connect=self.policy.connect_timeout_seconds,
            read=self.policy.read_timeout_seconds,
            write=self.policy.read_timeout_seconds,
            pool=self.policy.connect_timeout_seconds,
        )
        started_at = self.clock()
        response: httpx.Response | None = None
        try:
            with httpx.Client(
                base_url=self.configuration.base_url,
                timeout=timeout,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                request = client.build_request(
                    method,
                    path,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    content=body,
                )
                response = client.send(request, stream=True)
                content = bytearray()
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        if int(declared) > self.policy.maximum_response_bytes:
                            raise SecretProviderClientError(
                                SecretProviderClientCode.RESPONSE_TOO_LARGE,
                                certainty=_certainty(mutation),
                            )
                    except ValueError:
                        raise SecretProviderClientError(
                            SecretProviderClientCode.MALFORMED_RESPONSE,
                            certainty=_certainty(mutation),
                        ) from None
                try:
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > self.policy.maximum_response_bytes:
                            raise SecretProviderClientError(
                                SecretProviderClientCode.RESPONSE_TOO_LARGE,
                                certainty=_certainty(mutation),
                            )
                        if (
                            self.clock() - started_at
                            > self.policy.total_timeout_seconds
                        ):
                            raise SecretProviderClientError(
                                SecretProviderClientCode.TIMED_OUT,
                                certainty=_certainty(mutation),
                            )
                    if (
                        self.clock() - started_at
                        > self.policy.total_timeout_seconds
                    ):
                        raise SecretProviderClientError(
                            SecretProviderClientCode.TIMED_OUT,
                            certainty=_certainty(mutation),
                        )
                finally:
                    response.close()
        except SecretProviderClientError:
            raise
        except httpx.TimeoutException:
            raise SecretProviderClientError(
                SecretProviderClientCode.TIMED_OUT,
                certainty=_certainty(mutation),
            ) from None
        except httpx.HTTPError:
            raise SecretProviderClientError(
                SecretProviderClientCode.TRANSPORT_FAILED,
                certainty=_certainty(mutation),
            ) from None
        if response is None:
            raise SecretProviderClientError(
                SecretProviderClientCode.TRANSPORT_FAILED,
                certainty=_certainty(mutation),
            )
        if 300 <= response.status_code < 400:
            raise SecretProviderClientError(
                SecretProviderClientCode.REDIRECTED,
                certainty=_certainty(mutation),
            )
        if _content_type(response) != "application/json":
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=_certainty(mutation),
            )
        decoded = _decode_json(bytes(content), certainty=_certainty(mutation))
        if not 200 <= response.status_code < 300:
            _raise_provider_error(
                response.status_code,
                decoded,
                mutation=mutation,
            )
        return decoded

    def __repr__(self) -> str:
        return "ControlPlaneKitSecretsClient(<redacted>)"


def canonical_provider_secret_id(reference: SecretReference) -> str:
    """Injectively encode the complete reference into one provider path segment."""

    _require_reference(reference)
    encoded = reference.reference_id.encode("utf-8")
    if len(encoded) > _MAX_REFERENCE_BYTES:
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_REQUEST
        )
    payload = base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")
    return f"cpk1_{payload}"


def _secret_path(workspace_id: str, secret_id: str) -> str:
    return (
        f"/v1/workspaces/{quote(workspace_id, safe='')}/"
        f"secrets/{quote(secret_id, safe='')}"
    )


def _delegation_key_path(workspace_id: str, secret_id: str) -> str:
    return (
        f"/v1/workspaces/{quote(workspace_id, safe='')}/"
        f"delegation-keys/{quote(secret_id, safe='')}/generate"
    )


def _request_identity(
    workspace_id: str,
    caller_subject: str,
    correlation_id: str,
) -> None:
    if any(
        not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)
        for value in (workspace_id, caller_subject, correlation_id)
    ):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_REQUEST
        )


def _require_reference(reference: SecretReference) -> None:
    if not isinstance(reference, SecretReference):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_REQUEST
        )


def _read_credential(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            value = handle.read(_MAX_CREDENTIAL_BYTES + 1)
    except OSError:
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_CONFIGURATION
        ) from None
    if len(value) > _MAX_CREDENTIAL_BYTES:
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_CONFIGURATION
        )
    try:
        token = value.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError:
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_CONFIGURATION
        ) from None
    if (
        not token
        or token != token.strip()
        or any(not 0x21 <= ord(character) <= 0x7E for character in token)
    ):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_CONFIGURATION
        )
    return token


def _content_type(response: httpx.Response) -> str:
    return response.headers.get("content-type", "").split(";", maxsplit=1)[0].strip()


def _decode_json(
    content: bytes,
    *,
    certainty: SecretProviderOutcomeCertainty,
) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_RESPONSE,
            certainty=certainty,
        ) from None
    if not isinstance(value, dict):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_RESPONSE,
            certainty=certainty,
        )
    return value


def _raise_provider_error(
    status_code: int,
    payload: Mapping[str, object],
    *,
    mutation: bool,
) -> None:
    detail = payload.get("detail")
    if (
        set(payload) != {"detail"}
        or not isinstance(detail, dict)
        or set(detail) != {"outcome", "code"}
        or not isinstance(detail.get("outcome"), str)
        or not isinstance(detail.get("code"), str)
    ):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_RESPONSE,
            certainty=_certainty(mutation),
        )
    outcome = detail["outcome"]
    code = detail["code"]
    if status_code in {401, 403} and outcome == "denied":
        mapped = SecretProviderClientCode.DENIED
    elif status_code == 404 and outcome == "missing":
        mapped = SecretProviderClientCode.MISSING
    elif status_code == 409 and outcome == "revoked":
        mapped = SecretProviderClientCode.REVOKED
    elif status_code == 409 and outcome == "already-exists":
        mapped = SecretProviderClientCode.ALREADY_EXISTS
    elif status_code == 409 and outcome == "conflict":
        mapped = SecretProviderClientCode.CONFLICT
    elif status_code == 400 and outcome == "malformed":
        mapped = SecretProviderClientCode.MALFORMED_REQUEST
    elif status_code == 503 and code == "integrity-failure":
        mapped = SecretProviderClientCode.INTEGRITY_FAILURE
    elif status_code >= 500:
        mapped = SecretProviderClientCode.UNAVAILABLE
    else:
        mapped = SecretProviderClientCode.MALFORMED_RESPONSE
    raise SecretProviderClientError(
        mapped,
        certainty=_certainty(mutation and status_code >= 500),
    )


def _metadata(
    value: object,
    *,
    workspace_id: str,
    secret_id: str,
    reference: SecretReference,
    expected_status: str,
    certainty: SecretProviderOutcomeCertainty = (
        SecretProviderOutcomeCertainty.DEFINITE
    ),
) -> SecretProviderVersionMetadata:
    if not isinstance(value, dict) or set(value) != _METADATA_KEYS:
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_RESPONSE,
            certainty=certainty,
        )
    if (
        value.get("workspace_id") != workspace_id
        or value.get("secret_id") != secret_id
        or value.get("status") != expected_status
    ):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_RESPONSE,
            certainty=certainty,
        )
    for key in (
        "algorithm",
        "key_fingerprint",
        "key_version",
        "created_at",
    ):
        if not isinstance(value.get(key), str) or not value[key]:
            raise SecretProviderClientError(
                SecretProviderClientCode.MALFORMED_RESPONSE,
                certainty=certainty,
            )
    if value.get("revoked_at") is not None and not isinstance(
        value["revoked_at"],
        str,
    ):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_RESPONSE,
            certainty=certainty,
        )
    try:
        return SecretProviderVersionMetadata(
            reference=reference,
            version_id=value.get("version_id"),
            version_number=value.get("version_number"),
            status=expected_status,
            labels=value.get("labels"),
        )
    except SecretProviderClientError:
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_RESPONSE,
            certainty=certainty,
        ) from None


def _string_mapping(value: object) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or len(value) > 16
        or any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or len(key) > 64
            or len(item) > 256
            for key, item in value.items()
        )
    ):
        raise SecretProviderClientError(
            SecretProviderClientCode.MALFORMED_RESPONSE
        )
    return dict(value)


def _certainty(mutation: bool) -> SecretProviderOutcomeCertainty:
    return (
        SecretProviderOutcomeCertainty.UNCERTAIN
        if mutation
        else SecretProviderOutcomeCertainty.DEFINITE
    )
