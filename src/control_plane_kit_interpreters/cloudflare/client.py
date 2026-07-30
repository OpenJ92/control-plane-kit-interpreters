"""Cloudflare named public ingress interpretation.

This module owns provider-specific Cloudflare API calls. Core remains provider
neutral, and operations owns durable authority admission and resource evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
import re
from typing import Any, Mapping, Protocol

from control_plane_kit_core.public_ingress import (
    NamedPublicIngress,
    PublicIngressContractError,
)
from control_plane_kit_core.secrets import (
    AuthorizedSecretResolver,
    SecretCustodian,
    SecretCustodyGrant,
    SecretCustodyReceipt,
    SecretReference,
    SecretResolutionCode,
    SecretResolutionError,
    SecretResolutionGrant,
    SecretUseIntent,
    SecretValue,
    require_authorized_secret,
)


_BASE_URL = "https://api.cloudflare.com/client/v4"
_IDENTIFIER = re.compile(r"^[a-zA-Z0-9._:-]{1,128}$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HOST_PATTERN_LABEL = re.compile(r"^[a-z0-9*](?:[a-z0-9-*]{0,61}[a-z0-9*])?$")


class CloudflareApiError(RuntimeError):
    """Raised when Cloudflare API interpretation fails with bounded evidence."""


class CloudflareHttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> "CloudflareHttpResponse": ...


@dataclass(frozen=True)
class CloudflareHttpResponse:
    status_code: int
    body: Mapping[str, object]


@dataclass(frozen=True)
class CloudflareZoneAuthority:
    """Secret-safe authority material for one Cloudflare zone."""

    account_id: str
    zone_id: str
    zone_name: str
    api_token_ref: SecretReference
    allowed_hostname_pattern: str

    def __post_init__(self) -> None:
        _validate_identifier(self.account_id, "account_id")
        _validate_identifier(self.zone_id, "zone_id")
        _validate_zone_name(self.zone_name)
        if not isinstance(self.api_token_ref, SecretReference):
            raise CloudflareApiError("api_token_ref must be SecretReference")
        _validate_hostname_pattern(
            self.allowed_hostname_pattern,
            zone_name=self.zone_name,
        )

    def allows_hostname(self, hostname: str) -> bool:
        try:
            _validate_hostname(hostname)
        except CloudflareApiError:
            return False
        pattern = re.escape(self.allowed_hostname_pattern.lower()).replace(
            r"\*",
            r"[a-z0-9-]+",
        )
        return re.fullmatch(pattern, hostname.lower()) is not None


@dataclass(frozen=True, repr=False)
class CloudflareIngressAllocation:
    """Secret-free Cloudflare and provider-custody allocation result."""

    tunnel_id: str
    tunnel_name: str
    secret_custody_receipt: SecretCustodyReceipt
    dns_record_id: str
    hostname: str
    endpoint_url: str

    def __post_init__(self) -> None:
        _validate_identifier(self.tunnel_id, "tunnel_id")
        _validate_identifier(self.dns_record_id, "dns_record_id")
        _validate_identifier(self.tunnel_name, "tunnel_name")
        _validate_hostname(self.hostname)
        if not self.endpoint_url.startswith("https://"):
            raise CloudflareApiError("endpoint_url must be https")
        if not isinstance(self.secret_custody_receipt, SecretCustodyReceipt):
            raise CloudflareApiError(
                "allocation requires secret custody receipt"
            )

    def __repr__(self) -> str:
        return (
            "CloudflareIngressAllocation("
            f"tunnel_id={self.tunnel_id!r}, "
            f"tunnel_name={self.tunnel_name!r}, "
            f"secret_custody_receipt={self.secret_custody_receipt!r}, "
            f"dns_record_id={self.dns_record_id!r}, "
            f"hostname={self.hostname!r})"
        )


@dataclass(frozen=True)
class CloudflareOwnedIngressResources:
    """Owned resource ids required before destructive Cloudflare teardown."""

    tunnel_id: str
    dns_record_id: str
    tunnel_name: str
    hostname: str

    def __post_init__(self) -> None:
        _validate_identifier(self.tunnel_id, "tunnel_id")
        _validate_identifier(self.dns_record_id, "dns_record_id")
        _validate_identifier(self.tunnel_name, "tunnel_name")
        _validate_hostname(self.hostname)


@dataclass(frozen=True)
class CloudflareNamedIngressInterpreter:
    """Interpreter for provider-neutral named ingress requests."""

    transport: CloudflareHttpTransport | None = None
    authorized_secret_resolver: AuthorizedSecretResolver | None = None
    secret_custodian: SecretCustodian | None = None

    def create(
        self,
        ingress: NamedPublicIngress,
        *,
        authority: CloudflareZoneAuthority,
        allocation_name: str,
        origin_service_url: str,
        secret_resolution_grant: SecretResolutionGrant,
        secret_custody_grant: SecretCustodyGrant,
    ) -> CloudflareIngressAllocation:
        if not isinstance(ingress, NamedPublicIngress):
            raise CloudflareApiError("create requires NamedPublicIngress")
        if not isinstance(authority, CloudflareZoneAuthority):
            raise CloudflareApiError("create requires CloudflareZoneAuthority")
        _validate_identifier(allocation_name, "allocation_name")
        _validate_origin_service(origin_service_url)
        if not authority.allows_hostname(ingress.hostname):
            raise CloudflareApiError("hostname is outside admitted authority policy")
        if self.authorized_secret_resolver is None:
            raise SecretResolutionError(
                SecretResolutionCode.MISSING,
                "Cloudflare API token resolver is not configured",
            )
        if self.secret_custodian is None:
            raise SecretResolutionError(
                SecretResolutionCode.MISSING,
                "generated secret custodian is not configured",
            )
        if (
            not isinstance(secret_custody_grant, SecretCustodyGrant)
            or not secret_custody_grant.permits(
                secret_custody_grant.reference,
                SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
            )
        ):
            raise CloudflareApiError("tunnel token custody grant is invalid")

        api_token = _resolve_api_token(
            self.authorized_secret_resolver,
            authority,
            secret_resolution_grant,
        )
        client = CloudflareApiClient(
            authority,
            api_token=api_token,
            transport=self.transport,
        )
        tunnel_name = allocation_name
        tunnel_id: str | None = None
        dns_record_id: str | None = None
        custody_receipt: SecretCustodyReceipt | None = None
        custody_write_attempted = False
        try:
            tunnel_id = client.create_tunnel(tunnel_name)
            client.configure_tunnel(
                tunnel_id,
                hostname=ingress.hostname,
                origin_service_url=origin_service_url,
            )
            dns_record_id = client.upsert_dns_cname(
                hostname=ingress.hostname,
                tunnel_id=tunnel_id,
            )
            tunnel_token = client.get_tunnel_token(tunnel_id)
            custody_write_attempted = True
            custody_receipt = self.secret_custodian.store(
                secret_custody_grant,
                tunnel_token,
            )
            if not custody_receipt.matches(secret_custody_grant):
                raise CloudflareApiError(
                    "secret custodian returned mismatched receipt"
                )
        except Exception as error:
            compensation_failed = False
            if custody_write_attempted:
                try:
                    self.secret_custodian.revoke(secret_custody_grant)
                except Exception:
                    compensation_failed = True
            if dns_record_id is not None:
                try:
                    client.delete_dns_record(dns_record_id)
                except Exception:
                    compensation_failed = True
            if tunnel_id is not None:
                try:
                    client.delete_tunnel(tunnel_id)
                except Exception:
                    compensation_failed = True
            if compensation_failed:
                raise CloudflareApiError(
                    "Cloudflare allocation failed and exact compensation is uncertain"
                ) from error
            raise
        assert tunnel_id is not None
        assert dns_record_id is not None
        assert custody_receipt is not None
        return CloudflareIngressAllocation(
            tunnel_id=tunnel_id,
            tunnel_name=tunnel_name,
            secret_custody_receipt=custody_receipt,
            dns_record_id=dns_record_id,
            hostname=ingress.hostname,
            endpoint_url=f"https://{ingress.hostname}",
        )

    def observe(
        self,
        *,
        authority: CloudflareZoneAuthority,
        resources: CloudflareOwnedIngressResources,
        secret_resolution_grant: SecretResolutionGrant,
    ) -> Mapping[str, object]:
        return self._client(
            authority,
            secret_resolution_grant,
        ).get_tunnel(resources.tunnel_id)

    def teardown(
        self,
        *,
        authority: CloudflareZoneAuthority,
        resources: CloudflareOwnedIngressResources,
        secret_resolution_grant: SecretResolutionGrant,
        secret_custody_grant: SecretCustodyGrant,
    ) -> None:
        if not authority.allows_hostname(resources.hostname):
            raise CloudflareApiError("owned hostname is outside admitted authority policy")
        if self.secret_custodian is None:
            raise SecretResolutionError(
                SecretResolutionCode.MISSING,
                "generated secret custodian is not configured",
            )
        client = self._client(authority, secret_resolution_grant)
        self.secret_custodian.revoke(secret_custody_grant)
        client.delete_dns_record(resources.dns_record_id)
        client.delete_tunnel(resources.tunnel_id)

    def _client(
        self,
        authority: CloudflareZoneAuthority,
        secret_resolution_grant: SecretResolutionGrant,
    ) -> "CloudflareApiClient":
        if self.authorized_secret_resolver is None:
            raise SecretResolutionError(
                SecretResolutionCode.MISSING,
                "Cloudflare API token resolver is not configured",
            )
        api_token = _resolve_api_token(
            self.authorized_secret_resolver,
            authority,
            secret_resolution_grant,
        )
        return CloudflareApiClient(
            authority,
            api_token=api_token,
            transport=self.transport,
        )


def _resolve_api_token(
    resolver: AuthorizedSecretResolver,
    authority: CloudflareZoneAuthority,
    grant: SecretResolutionGrant,
) -> SecretValue:
    if (
        not isinstance(grant, SecretResolutionGrant)
        or not grant.permits(
            authority.api_token_ref,
            SecretUseIntent.CLOUDFLARE_API_TOKEN,
        )
    ):
        raise SecretResolutionError(
            SecretResolutionCode.DENIED,
            "Cloudflare API token requires exact committed authorization",
        )
    try:
        return require_authorized_secret(resolver, grant)
    except SecretResolutionError as error:
        raise SecretResolutionError(
            error.code,
            "Cloudflare API token could not be resolved",
        ) from None
    except Exception:
        raise CloudflareApiError(
            "Cloudflare API token resolution failed",
        ) from None


@dataclass(frozen=True)
class CloudflareApiClient:
    authority: CloudflareZoneAuthority
    api_token: SecretValue
    transport: CloudflareHttpTransport | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.authority, CloudflareZoneAuthority):
            raise CloudflareApiError("Cloudflare client requires zone authority")
        if not isinstance(self.api_token, SecretValue):
            raise CloudflareApiError("Cloudflare client requires SecretValue token")

    def create_tunnel(self, name: str) -> str:
        _validate_identifier(name, "tunnel name")
        result = self._request(
            "POST",
            f"/accounts/{self.authority.account_id}/cfd_tunnel",
            json={"name": name, "config_src": "cloudflare"},
        )
        return _result_text(result, "id")

    def configure_tunnel(
        self,
        tunnel_id: str,
        *,
        hostname: str,
        origin_service_url: str,
    ) -> None:
        _validate_identifier(tunnel_id, "tunnel_id")
        _validate_hostname(hostname)
        _validate_origin_service(origin_service_url)
        self._request(
            "PUT",
            f"/accounts/{self.authority.account_id}/cfd_tunnel/{tunnel_id}/configurations",
            json={
                "config": {
                    "ingress": [
                        {
                            "hostname": hostname,
                            "service": origin_service_url,
                            "originRequest": {},
                        },
                        {"service": "http_status:404"},
                    ]
                }
            },
        )

    def upsert_dns_cname(self, *, hostname: str, tunnel_id: str) -> str:
        _validate_hostname(hostname)
        _validate_identifier(tunnel_id, "tunnel_id")
        content = f"{tunnel_id}.cfargotunnel.com"
        records = self._request(
            "GET",
            f"/zones/{self.authority.zone_id}/dns_records",
            params={"type": "CNAME", "name": hostname},
        ).get("result")
        if isinstance(records, list) and records:
            record = records[0]
            if not isinstance(record, Mapping):
                raise CloudflareApiError("Cloudflare DNS record response malformed")
            record_id = _mapping_text(record, "id")
            self._request(
                "PATCH",
                f"/zones/{self.authority.zone_id}/dns_records/{record_id}",
                json=_dns_record_body(hostname, content),
            )
            return record_id
        created = self._request(
            "POST",
            f"/zones/{self.authority.zone_id}/dns_records",
            json=_dns_record_body(hostname, content),
        )
        return _result_text(created, "id")

    def get_tunnel_token(self, tunnel_id: str) -> SecretValue:
        _validate_identifier(tunnel_id, "tunnel_id")
        result = self._request(
            "GET",
            f"/accounts/{self.authority.account_id}/cfd_tunnel/{tunnel_id}/token",
        )
        token = result.get("result")
        if not isinstance(token, str) or not token.strip():
            raise CloudflareApiError("Cloudflare tunnel token response malformed")
        return SecretValue(token)

    def get_tunnel(self, tunnel_id: str) -> Mapping[str, object]:
        _validate_identifier(tunnel_id, "tunnel_id")
        result = self._request(
            "GET",
            f"/accounts/{self.authority.account_id}/cfd_tunnel/{tunnel_id}",
        ).get("result")
        if not isinstance(result, Mapping):
            raise CloudflareApiError("Cloudflare tunnel response malformed")
        return result

    def delete_dns_record(self, record_id: str) -> None:
        _validate_identifier(record_id, "dns_record_id")
        self._request(
            "DELETE",
            f"/zones/{self.authority.zone_id}/dns_records/{record_id}",
        )

    def delete_tunnel(self, tunnel_id: str) -> None:
        _validate_identifier(tunnel_id, "tunnel_id")
        self._request(
            "DELETE",
            f"/accounts/{self.authority.account_id}/cfd_tunnel/{tunnel_id}",
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> Mapping[str, object]:
        response = (self.transport or HttpxCloudflareTransport()).request(
            method,
            f"{_BASE_URL}{path}",
            headers={
                "Authorization": f"Bearer {self.api_token.reveal()}",
                "Content-Type": "application/json",
            },
            json=json,
            params=params,
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise CloudflareApiError(
                f"Cloudflare API request failed with status {response.status_code}"
            )
        if response.body.get("success") is False:
            raise CloudflareApiError("Cloudflare API request failed")
        return response.body


@dataclass
class HttpxCloudflareTransport:
    timeout: float = 20.0
    httpx_module: Any | None = None

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> CloudflareHttpResponse:
        httpx = self.httpx_module
        if httpx is None:
            httpx = import_module("httpx")
            self.httpx_module = httpx
        with httpx.Client(timeout=self.timeout) as client:
            response = client.request(
                method,
                url,
                headers=dict(headers),
                json=None if json is None else dict(json),
                params=None if params is None else dict(params),
            )
        return CloudflareHttpResponse(response.status_code, response.json())


def _dns_record_body(hostname: str, content: str) -> dict[str, object]:
    return {
        "type": "CNAME",
        "proxied": True,
        "name": hostname,
        "content": content,
    }


def _result_text(body: Mapping[str, object], key: str) -> str:
    result = body.get("result")
    if not isinstance(result, Mapping):
        raise CloudflareApiError("Cloudflare API result is malformed")
    return _mapping_text(result, key)


def _mapping_text(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CloudflareApiError(f"Cloudflare API result missing {key}")
    return value


def _validate_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise CloudflareApiError(f"{label} is invalid")
    _reject_secret_text(value, label)


def _validate_hostname(value: str) -> None:
    if not isinstance(value, str):
        raise CloudflareApiError("hostname is invalid")
    labels = value.lower().split(".")
    if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise CloudflareApiError("hostname is invalid")
    _reject_secret_text(value, "hostname")


def _validate_zone_name(value: str) -> None:
    _validate_hostname(value)


def _validate_hostname_pattern(value: str, *, zone_name: str) -> None:
    if not isinstance(value, str) or not value.endswith(f".{zone_name}"):
        raise CloudflareApiError("allowed hostname pattern must belong to zone")
    labels = value.lower().split(".")
    if sum(1 for label in labels if label == "*") > 1:
        raise CloudflareApiError("allowed hostname pattern may contain one wildcard")
    for label in labels:
        if not _HOST_PATTERN_LABEL.fullmatch(label):
            raise CloudflareApiError("allowed hostname pattern is invalid")
    _reject_secret_text(value, "allowed hostname pattern")


def _validate_origin_service(value: str) -> None:
    if not isinstance(value, str) or not value.startswith("http://"):
        raise CloudflareApiError("origin service must be internal http URL")
    if "://" not in value or value.startswith("http://127.0.0.1"):
        raise CloudflareApiError("origin service must target runtime-local service")
    _reject_secret_text(value, "origin service")


def _reject_secret_text(value: str, label: str) -> None:
    lowered = value.lower()
    if any(marker in lowered for marker in ("token", "secret", "password", "key")):
        raise CloudflareApiError(f"{label} must not contain secret material")
