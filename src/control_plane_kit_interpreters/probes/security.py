"""Fail-closed address authorization for runtime probes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

from control_plane_kit_core.probe_intents import (
    EndpointContext,
    LiteralEndpointMaterial,
    RuntimeEndpointObservation,
    SecretEndpointMaterial,
    protocol_endpoint_schemes,
)


class ProbeSecurityCode(StrEnum):
    INVALID_ENDPOINT = "invalid-endpoint"
    UNRESOLVED_ENDPOINT = "unresolved-endpoint"
    UNTRUSTED_ADDRESS = "untrusted-address"
    UNSAFE_URL = "unsafe-url"


class ProbeSecurityError(ValueError):
    """Bounded authorization failure that never includes an endpoint value."""

    def __init__(self, code: ProbeSecurityCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class ProbeEndpointSecretResolver(Protocol):
    """Resolve an opaque endpoint reference only at the transport boundary."""

    def resolve_endpoint(self, reference_id: str) -> str: ...


class ProbePublicAddressResolver(Protocol):
    """Resolve a public hostname for same-request address pinning."""

    def resolve(self, hostname: str) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class ProbeAddressPolicy:
    """Explicit trust roots for private, host-local, and public probes."""

    runtime_private_authorities: frozenset[str] = frozenset()
    public_hosts: frozenset[str] = frozenset()
    allow_host_local: bool = False
    allow_plaintext_public_http: bool = False

    def __post_init__(self) -> None:
        for values, label in (
            (self.runtime_private_authorities, "runtime-private authorities"),
            (self.public_hosts, "public hosts"),
        ):
            if not isinstance(values, frozenset) or not all(
                isinstance(value, str) and value.strip() for value in values
            ):
                raise TypeError(f"probe {label} must be a frozenset of text")


@dataclass(frozen=True, repr=False)
class AuthorizedProbeTarget:
    """One authorized connect target; its authority is deliberately opaque."""

    context: EndpointContext
    _base_url: str
    connect_host: str
    port: int
    host_header: str | None = None
    sni_hostname: str | None = None

    def request_url(self, path: str) -> str:
        parsed = urlsplit(path)
        if (
            not path.startswith("/")
            or path.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
        ):
            raise ProbeSecurityError(
                ProbeSecurityCode.UNSAFE_URL,
                "probe path must be absolute and authority-free",
            )
        return f"{self._base_url}{path}"

    def __repr__(self) -> str:
        return (
            "AuthorizedProbeTarget("
            f"context={self.context!r}, authority=<redacted>)"
        )


def authorize_probe_endpoint(
    observation: RuntimeEndpointObservation,
    policy: ProbeAddressPolicy,
    *,
    secret_resolver: ProbeEndpointSecretResolver | None = None,
    public_resolver: ProbePublicAddressResolver | None = None,
) -> AuthorizedProbeTarget:
    """Authorize and, for public DNS, pin one runtime-observed endpoint."""

    value = _resolve_address(observation, secret_resolver)
    try:
        parsed = urlsplit(value)
        _validate_shape(parsed, observation)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise _unsafe() from error
    assert parsed.hostname is not None and port is not None
    origin = _origin(parsed)

    match observation.context:
        case EndpointContext.RUNTIME_PRIVATE:
            if origin not in policy.runtime_private_authorities:
                raise _untrusted()
            return AuthorizedProbeTarget(
                observation.context,
                origin,
                parsed.hostname,
                port,
            )
        case EndpointContext.HOST_LOCAL:
            if not policy.allow_host_local or not _is_loopback(parsed.hostname):
                raise _untrusted()
            return AuthorizedProbeTarget(
                observation.context,
                origin,
                parsed.hostname,
                port,
            )
        case EndpointContext.PUBLIC:
            if (
                parsed.hostname not in policy.public_hosts
                or (parsed.scheme != "https" and not policy.allow_plaintext_public_http)
                or public_resolver is None
            ):
                raise _untrusted()
            pinned = _pinned_public_address(parsed.hostname, public_resolver)
            rendered = f"[{pinned}]" if ":" in pinned else pinned
            base_url = f"{parsed.scheme}://{rendered}:{port}"
            return AuthorizedProbeTarget(
                observation.context,
                base_url,
                pinned,
                port,
                host_header=f"{parsed.hostname}:{port}",
                sni_hostname=parsed.hostname,
            )
    raise _untrusted()


def _resolve_address(
    observation: RuntimeEndpointObservation,
    resolver: ProbeEndpointSecretResolver | None,
) -> str:
    match observation.address:
        case LiteralEndpointMaterial(value=value):
            return value
        case SecretEndpointMaterial(reference_id=reference):
            if resolver is None:
                raise ProbeSecurityError(
                    ProbeSecurityCode.UNRESOLVED_ENDPOINT,
                    "probe endpoint reference has no resolver",
                )
            try:
                value = resolver.resolve_endpoint(reference)
            except ProbeSecurityError:
                raise
            except Exception as error:
                raise ProbeSecurityError(
                    ProbeSecurityCode.UNRESOLVED_ENDPOINT,
                    "probe endpoint reference could not be resolved",
                ) from error
            if not isinstance(value, str) or not value:
                raise ProbeSecurityError(
                    ProbeSecurityCode.UNRESOLVED_ENDPOINT,
                    "probe endpoint resolver returned an invalid value",
                )
            return value
    raise ProbeSecurityError(
        ProbeSecurityCode.INVALID_ENDPOINT,
        "probe endpoint material is unsupported",
    )


def _validate_shape(
    parsed: SplitResult,
    observation: RuntimeEndpointObservation,
) -> None:
    if (
        parsed.scheme not in protocol_endpoint_schemes(observation.protocol)
        or parsed.hostname is None
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise _unsafe()


def _origin(parsed: SplitResult) -> str:
    assert parsed.hostname is not None and parsed.port is not None
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme}://{host}:{parsed.port}"


def _pinned_public_address(
    hostname: str,
    resolver: ProbePublicAddressResolver,
) -> str:
    try:
        values = resolver.resolve(hostname)
        addresses = tuple(ip_address(value) for value in values)
    except Exception as error:
        raise _untrusted() from error
    if not addresses or any(not value.is_global for value in addresses):
        raise _untrusted()
    selected = sorted(addresses, key=lambda value: (value.version, int(value)))[0]
    return str(selected)


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _unsafe() -> ProbeSecurityError:
    return ProbeSecurityError(
        ProbeSecurityCode.UNSAFE_URL,
        "probe endpoint is not a safe authority",
    )


def _untrusted() -> ProbeSecurityError:
    return ProbeSecurityError(
        ProbeSecurityCode.UNTRUSTED_ADDRESS,
        "probe endpoint is not trusted by address policy",
    )
