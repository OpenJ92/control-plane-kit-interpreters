"""Cloudflare named public ingress interpretation.

This module owns provider-specific Cloudflare API calls. Core remains provider
neutral, and operations owns durable authority admission and resource evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib import import_module
import re
from typing import Any, Callable, Mapping, Protocol

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


class CloudflareApiNotFound(CloudflareApiError):
    """Raised when an exact Cloudflare resource is absent."""


class CloudflareApiTransportError(CloudflareApiError):
    """Raised when a request outcome is ambiguous at the transport boundary."""


class CloudflareProviderFailureStage(StrEnum):
    DNS_PRE_OBSERVATION = "dns-pre-observation"
    TUNNEL_ALLOCATION = "tunnel-allocation"
    TUNNEL_CONFIGURATION = "tunnel-configuration"
    DNS_PRE_MUTATION_OBSERVATION = "dns-pre-mutation-observation"
    DNS_CREATE = "dns-create"
    DNS_RECONCILIATION = "dns-reconciliation"
    TUNNEL_TOKEN = "tunnel-token"
    SECRET_CUSTODY = "secret-custody"
    CLEANUP = "cleanup"


class CloudflareProviderFailureCategory(StrEnum):
    HOSTNAME_OCCUPIED = "hostname-occupied"
    DNS_CONFLICT = "dns-conflict"
    MALFORMED_RESPONSE = "malformed-response"
    PROVIDER_STATUS = "provider-status"
    TRANSPORT = "transport"
    SECRET_CUSTODY = "secret-custody"
    CLEANUP = "cleanup"


class CloudflareProviderMutationCertainty(StrEnum):
    NONE = "none"
    TUNNEL_CREATED = "tunnel-created"
    DNS_AND_TUNNEL_CREATED = "dns-and-tunnel-created"
    UNCERTAIN = "uncertain"


class CloudflareProviderCleanupResult(StrEnum):
    NOT_REQUIRED = "not-required"
    COMPLETE = "complete"
    WITHHELD = "withheld"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class CloudflareProviderFailureEvidence:
    stage: CloudflareProviderFailureStage
    category: CloudflareProviderFailureCategory
    mutation_certainty: CloudflareProviderMutationCertainty
    tunnel_id: str | None
    dns_record_id: str | None
    cleanup_result: CloudflareProviderCleanupResult

    def __post_init__(self) -> None:
        if not isinstance(self.stage, CloudflareProviderFailureStage):
            raise CloudflareApiError("provider failure stage must be closed")
        if not isinstance(self.category, CloudflareProviderFailureCategory):
            raise CloudflareApiError("provider failure category must be closed")
        if not isinstance(
            self.mutation_certainty,
            CloudflareProviderMutationCertainty,
        ):
            raise CloudflareApiError("provider mutation certainty must be closed")
        if not isinstance(self.cleanup_result, CloudflareProviderCleanupResult):
            raise CloudflareApiError("provider cleanup result must be closed")
        if self.tunnel_id is not None:
            _validate_identifier(self.tunnel_id, "tunnel_id")
        if self.dns_record_id is not None:
            _validate_identifier(self.dns_record_id, "dns_record_id")


class CloudflareProviderOperationError(CloudflareApiError):
    """Bounded provider failure suitable for durable Operations evidence."""

    def __init__(
        self,
        message: str,
        provider_failure: CloudflareProviderFailureEvidence,
    ) -> None:
        super().__init__(message)
        self.provider_failure = provider_failure


class _CloudflareMalformedResponse(CloudflareApiError):
    pass


class _CloudflareHostnameState(StrEnum):
    ABSENT = "absent"
    OCCUPIED = "occupied"
    TARGETS_TUNNEL = "targets-tunnel"
    DUPLICATE = "duplicate"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class _CloudflareHostnameObservation:
    state: _CloudflareHostnameState
    dns_record_id: str | None = None


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


class CloudflareResourcePresence(StrEnum):
    """Closed exact-resource observation states."""

    PRESENT = "present"
    ABSENT = "absent"


@dataclass(frozen=True)
class CloudflareOwnedHostnameReservation:
    """Exact provider coordinates for one operations-owned hostname reservation."""

    dns_record_id: str
    hostname: str
    expected_tunnel_id: str

    def __post_init__(self) -> None:
        _validate_identifier(self.dns_record_id, "dns_record_id")
        _validate_hostname(self.hostname)
        _validate_identifier(self.expected_tunnel_id, "expected_tunnel_id")


@dataclass(frozen=True)
class CloudflareHostnameReservationObservation:
    """Secret-free observation of one exact DNS reservation."""

    dns_record_id: str
    hostname: str
    presence: CloudflareResourcePresence
    tunnel_id: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.dns_record_id, "dns_record_id")
        _validate_hostname(self.hostname)
        if not isinstance(self.presence, CloudflareResourcePresence):
            raise CloudflareApiError("reservation presence must be closed")
        if self.presence is CloudflareResourcePresence.PRESENT:
            if self.tunnel_id is None:
                raise CloudflareApiError(
                    "present reservation observation requires tunnel_id"
                )
            _validate_identifier(self.tunnel_id, "tunnel_id")
        elif self.tunnel_id is not None:
            raise CloudflareApiError(
                "absent reservation observation cannot include tunnel_id"
            )


@dataclass(frozen=True)
class CloudflareTunnelObservation:
    """Secret-free presence observation for one exact tunnel."""

    tunnel_id: str
    presence: CloudflareResourcePresence

    def __post_init__(self) -> None:
        _validate_identifier(self.tunnel_id, "tunnel_id")
        if not isinstance(self.presence, CloudflareResourcePresence):
            raise CloudflareApiError("tunnel presence must be closed")


@dataclass(frozen=True)
class CloudflareRetainedIngressDeactivation:
    """Verified postconditions after removing a tunnel but retaining DNS."""

    reservation: CloudflareHostnameReservationObservation
    tunnel: CloudflareTunnelObservation

    def __post_init__(self) -> None:
        if self.reservation.presence is not CloudflareResourcePresence.PRESENT:
            raise CloudflareApiError(
                "retained deactivation requires a present reservation"
            )
        if self.tunnel.presence is not CloudflareResourcePresence.ABSENT:
            raise CloudflareApiError("retained deactivation requires tunnel absence")


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
        _require_tunnel_token_custody_grant(secret_custody_grant)

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
        try:
            pre_observation = _observe_exact_hostname(
                client,
                ingress.hostname,
            )
        except Exception as error:
            if not _is_provider_operation_failure(error):
                raise
            raise _provider_operation_error(
                str(error),
                stage=CloudflareProviderFailureStage.DNS_PRE_OBSERVATION,
                category=_provider_failure_category(error),
                mutation_certainty=CloudflareProviderMutationCertainty.NONE,
                cleanup_result=CloudflareProviderCleanupResult.NOT_REQUIRED,
            ) from None
        if pre_observation.state is not _CloudflareHostnameState.ABSENT:
            raise _hostname_observation_error(
                pre_observation,
                stage=CloudflareProviderFailureStage.DNS_PRE_OBSERVATION,
                tunnel_id=None,
                mutation_certainty=CloudflareProviderMutationCertainty.NONE,
                cleanup_result=CloudflareProviderCleanupResult.NOT_REQUIRED,
            ) from None

        try:
            tunnel_id = client.create_tunnel(tunnel_name)
        except Exception as error:
            if not _is_provider_operation_failure(error):
                raise
            raise _provider_operation_error(
                str(error),
                stage=CloudflareProviderFailureStage.TUNNEL_ALLOCATION,
                category=_provider_failure_category(error),
                mutation_certainty=CloudflareProviderMutationCertainty.UNCERTAIN,
                cleanup_result=CloudflareProviderCleanupResult.WITHHELD,
            ) from None

        try:
            client.configure_tunnel(
                tunnel_id,
                hostname=ingress.hostname,
                origin_service_url=origin_service_url,
            )
        except Exception as error:
            cleanup_result = _delete_known_tunnel(client, tunnel_id)
            if not _is_provider_operation_failure(error):
                if cleanup_result is CloudflareProviderCleanupResult.UNCERTAIN:
                    raise CloudflareApiError(
                        "Cloudflare exact cleanup is uncertain: tunnel"
                    ) from None
                raise
            certainty = CloudflareProviderMutationCertainty.TUNNEL_CREATED
            if isinstance(error, CloudflareApiTransportError):
                certainty = CloudflareProviderMutationCertainty.UNCERTAIN
            raise _provider_operation_error(
                str(error),
                stage=CloudflareProviderFailureStage.TUNNEL_CONFIGURATION,
                category=_provider_failure_category(error),
                mutation_certainty=certainty,
                tunnel_id=tunnel_id,
                cleanup_result=cleanup_result,
            ) from None

        try:
            pre_mutation_observation = _observe_exact_hostname(
                client,
                ingress.hostname,
                tunnel_id=tunnel_id,
            )
        except Exception as error:
            cleanup_result = _delete_known_tunnel(client, tunnel_id)
            if not _is_provider_operation_failure(error):
                if cleanup_result is CloudflareProviderCleanupResult.UNCERTAIN:
                    raise CloudflareApiError(
                        "Cloudflare exact cleanup is uncertain: tunnel"
                    ) from None
                raise
            raise _provider_operation_error(
                str(error),
                stage=(
                    CloudflareProviderFailureStage.DNS_PRE_MUTATION_OBSERVATION
                ),
                category=_provider_failure_category(error),
                mutation_certainty=(
                    CloudflareProviderMutationCertainty.TUNNEL_CREATED
                ),
                tunnel_id=tunnel_id,
                cleanup_result=cleanup_result,
            ) from None
        if pre_mutation_observation.state is not _CloudflareHostnameState.ABSENT:
            if pre_mutation_observation.state is _CloudflareHostnameState.OCCUPIED:
                cleanup_result = _delete_known_tunnel(client, tunnel_id)
                certainty = CloudflareProviderMutationCertainty.TUNNEL_CREATED
            else:
                cleanup_result = CloudflareProviderCleanupResult.WITHHELD
                certainty = CloudflareProviderMutationCertainty.UNCERTAIN
            raise _hostname_observation_error(
                pre_mutation_observation,
                stage=(
                    CloudflareProviderFailureStage.DNS_PRE_MUTATION_OBSERVATION
                ),
                tunnel_id=tunnel_id,
                mutation_certainty=certainty,
                cleanup_result=cleanup_result,
            ) from None

        try:
            dns_record_id = client._create_dns_cname_unchecked(
                hostname=ingress.hostname,
                tunnel_id=tunnel_id,
            )
        except Exception as dns_create_error:
            try:
                reconciliation = _observe_reconciled_exact_hostname(
                    client,
                    ingress.hostname,
                    tunnel_id=tunnel_id,
                )
            except Exception as reconciliation_error:
                if not _is_provider_operation_failure(reconciliation_error):
                    raise
                raise _provider_operation_error(
                    "Cloudflare DNS reconciliation failed",
                    stage=CloudflareProviderFailureStage.DNS_RECONCILIATION,
                    category=_provider_failure_category(reconciliation_error),
                    mutation_certainty=(
                        CloudflareProviderMutationCertainty.UNCERTAIN
                    ),
                    tunnel_id=tunnel_id,
                    cleanup_result=CloudflareProviderCleanupResult.WITHHELD,
                ) from None
            if (
                isinstance(dns_create_error, CloudflareApiTransportError)
                and reconciliation.state
                is _CloudflareHostnameState.TARGETS_TUNNEL
                and reconciliation.dns_record_id is not None
            ):
                dns_record_id = reconciliation.dns_record_id
            else:
                if reconciliation.state in {
                    _CloudflareHostnameState.ABSENT,
                    _CloudflareHostnameState.OCCUPIED,
                }:
                    cleanup_result = _delete_known_tunnel(client, tunnel_id)
                else:
                    cleanup_result = CloudflareProviderCleanupResult.WITHHELD
                if not _is_provider_operation_failure(dns_create_error):
                    if (
                        cleanup_result
                        is CloudflareProviderCleanupResult.UNCERTAIN
                    ):
                        raise CloudflareApiError(
                            "Cloudflare exact cleanup is uncertain: tunnel"
                        ) from None
                    raise dns_create_error
                raise _provider_operation_error(
                    str(dns_create_error),
                    stage=CloudflareProviderFailureStage.DNS_CREATE,
                    category=_provider_failure_category(dns_create_error),
                    mutation_certainty=(
                        CloudflareProviderMutationCertainty.UNCERTAIN
                    ),
                    tunnel_id=tunnel_id,
                    dns_record_id=reconciliation.dns_record_id,
                    cleanup_result=cleanup_result,
                ) from None

        try:
            tunnel_token = client.get_tunnel_token(tunnel_id)
        except Exception as error:
            cleanup_result, failed_stages = _cleanup_created_ingress(
                client,
                tunnel_id=tunnel_id,
                dns_record_id=dns_record_id,
            )
            if not _is_provider_operation_failure(error):
                if failed_stages:
                    raise CloudflareApiError(
                        "Cloudflare exact cleanup is uncertain: "
                        + ",".join(failed_stages)
                    ) from None
                raise
            if failed_stages:
                message = (
                    "Cloudflare exact cleanup is uncertain: "
                    + ",".join(failed_stages)
                )
                stage = CloudflareProviderFailureStage.CLEANUP
                category = CloudflareProviderFailureCategory.CLEANUP
            else:
                message = str(error)
                stage = CloudflareProviderFailureStage.TUNNEL_TOKEN
                category = _provider_failure_category(error)
            raise _provider_operation_error(
                message,
                stage=stage,
                category=category,
                mutation_certainty=(
                    CloudflareProviderMutationCertainty.DNS_AND_TUNNEL_CREATED
                    if not failed_stages
                    else CloudflareProviderMutationCertainty.UNCERTAIN
                ),
                tunnel_id=tunnel_id,
                dns_record_id=dns_record_id,
                cleanup_result=cleanup_result,
            ) from None

        custody_write_attempted = True
        try:
            custody_receipt = self.secret_custodian.store(
                secret_custody_grant,
                tunnel_token,
            )
            if not custody_receipt.matches(secret_custody_grant):
                raise CloudflareApiError(
                    "secret custodian returned mismatched receipt"
                )
        except Exception:
            cleanup_result, failed_stages = _cleanup_created_ingress(
                client,
                tunnel_id=tunnel_id,
                dns_record_id=dns_record_id,
                custody=(
                    "custody",
                    lambda: self.secret_custodian.revoke(secret_custody_grant),
                )
                if custody_write_attempted
                else None,
            )
            message = "Cloudflare generated secret custody failed"
            stage = CloudflareProviderFailureStage.SECRET_CUSTODY
            category = CloudflareProviderFailureCategory.SECRET_CUSTODY
            certainty = (
                CloudflareProviderMutationCertainty.DNS_AND_TUNNEL_CREATED
            )
            if failed_stages:
                message = (
                    "Cloudflare exact cleanup is uncertain: "
                    + ",".join(failed_stages)
                )
                stage = CloudflareProviderFailureStage.CLEANUP
                category = CloudflareProviderFailureCategory.CLEANUP
                certainty = CloudflareProviderMutationCertainty.UNCERTAIN
            raise _provider_operation_error(
                message,
                stage=stage,
                category=category,
                mutation_certainty=certainty,
                tunnel_id=tunnel_id,
                dns_record_id=dns_record_id,
                cleanup_result=cleanup_result,
            ) from None

        return CloudflareIngressAllocation(
            tunnel_id=tunnel_id,
            tunnel_name=tunnel_name,
            secret_custody_receipt=custody_receipt,
            dns_record_id=dns_record_id,
            hostname=ingress.hostname,
            endpoint_url=f"https://{ingress.hostname}",
        )

    def rebind(
        self,
        ingress: NamedPublicIngress,
        *,
        authority: CloudflareZoneAuthority,
        reservation: CloudflareOwnedHostnameReservation,
        allocation_name: str,
        origin_service_url: str,
        secret_resolution_grant: SecretResolutionGrant,
        secret_custody_grant: SecretCustodyGrant,
    ) -> CloudflareIngressAllocation:
        """Bind a new tunnel epoch to one exact retained DNS reservation."""

        if not isinstance(ingress, NamedPublicIngress):
            raise CloudflareApiError("rebind requires NamedPublicIngress")
        _require_reservation_authority(authority, reservation)
        if ingress.hostname != reservation.hostname:
            raise CloudflareApiError("ingress and reservation hostname mismatch")
        _validate_identifier(allocation_name, "allocation_name")
        _validate_origin_service(origin_service_url)
        if self.secret_custodian is None:
            raise SecretResolutionError(
                SecretResolutionCode.MISSING,
                "generated secret custodian is not configured",
            )
        _require_tunnel_token_custody_grant(secret_custody_grant)

        client = self._client(authority, secret_resolution_grant)
        tunnel_id: str | None = None
        custody_receipt: SecretCustodyReceipt | None = None
        custody_write_attempted = False
        dns_update_attempted = False
        try:
            tunnel_id = client.create_tunnel(allocation_name)
            client.configure_tunnel(
                tunnel_id,
                hostname=reservation.hostname,
                origin_service_url=origin_service_url,
            )
            _require_expected_reservation(
                _observe_hostname_reservation(client, reservation),
                reservation,
            )
            dns_update_attempted = True
            client.update_dns_cname(
                reservation.dns_record_id,
                hostname=reservation.hostname,
                tunnel_id=tunnel_id,
            )
            _require_observed_tunnel(
                _observe_hostname_reservation(client, reservation),
                tunnel_id,
            )
            tunnel_token = client.get_tunnel_token(tunnel_id)
            custody_write_attempted = True
            try:
                custody_receipt = self.secret_custodian.store(
                    secret_custody_grant,
                    tunnel_token,
                )
            except Exception:
                raise CloudflareApiError(
                    "Cloudflare generated secret custody failed"
                ) from None
            if not custody_receipt.matches(secret_custody_grant):
                raise CloudflareApiError(
                    "secret custodian returned mismatched receipt"
                )
            _require_observed_tunnel(
                _observe_hostname_reservation(client, reservation),
                tunnel_id,
            )
        except Exception as error:
            cleanup: list[tuple[str, Callable[[], None]]] = []
            if custody_write_attempted:
                cleanup.append(
                    (
                        "custody",
                        lambda: self.secret_custodian.revoke(secret_custody_grant),
                    )
                )
            if dns_update_attempted and tunnel_id is not None:
                cleanup.append(
                    (
                        "dns",
                        lambda: _restore_rebind_reservation(
                            client,
                            reservation,
                            new_tunnel_id=tunnel_id,
                        ),
                    )
                )
            if tunnel_id is not None:
                cleanup.append(
                    ("tunnel", lambda: client.delete_tunnel(tunnel_id))
                )
            failed_stages = _attempt_exact_cleanup(cleanup)
            if failed_stages:
                raise CloudflareApiError(
                    "Cloudflare exact rebind cleanup is uncertain: "
                    + ",".join(failed_stages)
                ) from None
            if dns_update_attempted and isinstance(
                error,
                CloudflareApiTransportError,
            ):
                raise CloudflareApiError(
                    "Cloudflare exact rebind is uncertain"
                ) from None
            raise

        assert tunnel_id is not None
        assert custody_receipt is not None
        return CloudflareIngressAllocation(
            tunnel_id=tunnel_id,
            tunnel_name=allocation_name,
            secret_custody_receipt=custody_receipt,
            dns_record_id=reservation.dns_record_id,
            hostname=reservation.hostname,
            endpoint_url=f"https://{reservation.hostname}",
        )

    def observe_reservation(
        self,
        *,
        authority: CloudflareZoneAuthority,
        reservation: CloudflareOwnedHostnameReservation,
        secret_resolution_grant: SecretResolutionGrant,
    ) -> CloudflareHostnameReservationObservation:
        """Observe one exact reservation without name-based discovery."""

        _require_reservation_authority(authority, reservation)
        observation = _observe_hostname_reservation(
            self._client(authority, secret_resolution_grant),
            reservation,
        )
        if observation.presence is CloudflareResourcePresence.PRESENT:
            _require_expected_reservation(observation, reservation)
        return observation

    def deactivate_preserving_reservation(
        self,
        *,
        authority: CloudflareZoneAuthority,
        reservation: CloudflareOwnedHostnameReservation,
        resources: CloudflareOwnedIngressResources,
        secret_resolution_grant: SecretResolutionGrant,
        secret_custody_grant: SecretCustodyGrant,
    ) -> CloudflareRetainedIngressDeactivation:
        """Remove one tunnel epoch while preserving its exact DNS reservation."""

        _require_reservation_authority(authority, reservation)
        _require_reservation_resource_agreement(reservation, resources)
        if self.secret_custodian is None:
            raise SecretResolutionError(
                SecretResolutionCode.MISSING,
                "generated secret custodian is not configured",
            )
        _require_tunnel_token_custody_grant(secret_custody_grant)
        client = self._client(authority, secret_resolution_grant)
        _require_expected_reservation(
            _observe_hostname_reservation(client, reservation),
            reservation,
        )

        failed: list[str] = []
        reservation_observation: CloudflareHostnameReservationObservation | None = None
        tunnel_observation: CloudflareTunnelObservation | None = None
        stages: tuple[tuple[str, Callable[[], None]], ...] = (
            (
                "custody",
                lambda: self.secret_custodian.revoke(secret_custody_grant),
            ),
            (
                "connections",
                lambda: client.delete_tunnel_connections(resources.tunnel_id),
            ),
            ("tunnel", lambda: client.delete_tunnel(resources.tunnel_id)),
        )
        failed.extend(_attempt_exact_cleanup(stages))
        try:
            reservation_observation = _require_expected_reservation(
                _observe_hostname_reservation(client, reservation),
                reservation,
            )
        except Exception:
            failed.append("reservation-observation")
        try:
            tunnel_observation = _observe_tunnel(client, resources.tunnel_id)
            if tunnel_observation.presence is not CloudflareResourcePresence.ABSENT:
                raise CloudflareApiError("exact tunnel remains present")
        except Exception:
            failed.append("tunnel-observation")
        if failed:
            raise CloudflareApiError(
                "Cloudflare retained deactivation is uncertain: "
                + ",".join(failed)
            ) from None
        assert reservation_observation is not None
        assert tunnel_observation is not None
        return CloudflareRetainedIngressDeactivation(
            reservation=reservation_observation,
            tunnel=tunnel_observation,
        )

    def release_reservation(
        self,
        *,
        authority: CloudflareZoneAuthority,
        reservation: CloudflareOwnedHostnameReservation,
        secret_resolution_grant: SecretResolutionGrant,
    ) -> CloudflareHostnameReservationObservation:
        """Delete one exact reservation and verify its absence."""

        _require_reservation_authority(authority, reservation)
        client = self._client(authority, secret_resolution_grant)
        _require_expected_reservation(
            _observe_hostname_reservation(client, reservation),
            reservation,
        )
        failed: list[str] = []
        try:
            client.delete_dns_record(reservation.dns_record_id)
        except Exception:
            failed.append("dns")
        observation: CloudflareHostnameReservationObservation | None = None
        try:
            observation = _observe_hostname_reservation(client, reservation)
            if observation.presence is not CloudflareResourcePresence.ABSENT:
                failed.append("absence")
        except Exception:
            failed.append("absence")
        if failed:
            raise CloudflareApiError(
                "Cloudflare reservation release is uncertain: "
                + ",".join(failed)
            ) from None
        assert observation is not None
        return observation

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
        _require_tunnel_token_custody_grant(secret_custody_grant)
        client = self._client(authority, secret_resolution_grant)
        failed_stages = _attempt_exact_cleanup(
            (
                (
                    "custody",
                    lambda: self.secret_custodian.revoke(secret_custody_grant),
                ),
                (
                    "dns",
                    lambda: client.delete_dns_record(resources.dns_record_id),
                ),
                (
                    "connections",
                    lambda: client.delete_tunnel_connections(resources.tunnel_id),
                ),
                (
                    "tunnel",
                    lambda: client.delete_tunnel(resources.tunnel_id),
                ),
            )
        )
        if failed_stages:
            raise CloudflareApiError(
                "Cloudflare exact cleanup is uncertain: "
                + ",".join(failed_stages)
            )

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


def _observe_exact_hostname(
    client: "CloudflareApiClient",
    hostname: str,
    *,
    tunnel_id: str | None = None,
) -> _CloudflareHostnameObservation:
    records = client.list_dns_records_for_hostname(hostname)
    if not records:
        return _CloudflareHostnameObservation(_CloudflareHostnameState.ABSENT)
    if len(records) != 1:
        return _CloudflareHostnameObservation(_CloudflareHostnameState.DUPLICATE)
    record = records[0]
    if not isinstance(record, Mapping):
        return _CloudflareHostnameObservation(_CloudflareHostnameState.MALFORMED)
    try:
        record_id = _mapping_text(record, "id")
        _validate_identifier(record_id, "dns_record_id")
        record_type = _mapping_text(record, "type")
        record_name = _mapping_text(record, "name")
        content = _mapping_text(record, "content")
    except CloudflareApiError:
        return _CloudflareHostnameObservation(_CloudflareHostnameState.MALFORMED)
    if record_name.lower() != hostname.lower():
        return _CloudflareHostnameObservation(_CloudflareHostnameState.MALFORMED)
    if (
        tunnel_id is not None
        and record_type == "CNAME"
        and content == _tunnel_target(tunnel_id)
    ):
        return _CloudflareHostnameObservation(
            _CloudflareHostnameState.TARGETS_TUNNEL,
            dns_record_id=record_id,
        )
    return _CloudflareHostnameObservation(
        _CloudflareHostnameState.OCCUPIED,
        dns_record_id=record_id,
    )


def _observe_reconciled_exact_hostname(
    client: "CloudflareApiClient",
    hostname: str,
    *,
    tunnel_id: str,
) -> _CloudflareHostnameObservation:
    page = client._read_dns_reconciliation_page(hostname)
    records = page.get("result")
    if not isinstance(records, list):
        raise _CloudflareMalformedResponse(
            "Cloudflare DNS reconciliation response malformed"
        )

    observation = _classify_reconciled_dns_records(
        records,
        hostname=hostname,
        tunnel_id=tunnel_id,
    )
    result_info = page.get("result_info")
    if not isinstance(result_info, Mapping):
        return _CloudflareHostnameObservation(
            _CloudflareHostnameState.MALFORMED,
            dns_record_id=observation.dns_record_id,
        )
    page_number = result_info.get("page")
    per_page = result_info.get("per_page")
    count = result_info.get("count")
    if (
        page.get("success") is not True
        or type(page_number) is not int
        or page_number != 1
        or type(per_page) is not int
        or per_page != 2
        or type(count) is not int
        or count != len(records)
        or len(records) > 2
    ):
        return _CloudflareHostnameObservation(
            _CloudflareHostnameState.MALFORMED,
            dns_record_id=observation.dns_record_id,
        )
    return observation


def _classify_reconciled_dns_records(
    records: list[object],
    *,
    hostname: str,
    tunnel_id: str,
) -> _CloudflareHostnameObservation:
    if not records:
        return _CloudflareHostnameObservation(_CloudflareHostnameState.ABSENT)
    if len(records) != 1:
        return _CloudflareHostnameObservation(_CloudflareHostnameState.DUPLICATE)
    record = records[0]
    if not isinstance(record, Mapping):
        return _CloudflareHostnameObservation(_CloudflareHostnameState.MALFORMED)
    try:
        record_id = _mapping_text(record, "id")
        _validate_identifier(record_id, "dns_record_id")
        record_type = _mapping_text(record, "type")
        record_name = _mapping_text(record, "name")
        content = _mapping_text(record, "content")
    except CloudflareApiError:
        return _CloudflareHostnameObservation(_CloudflareHostnameState.MALFORMED)
    if record_name != hostname:
        return _CloudflareHostnameObservation(_CloudflareHostnameState.MALFORMED)
    if record_type != "CNAME" or record.get("proxied") is not True:
        return _CloudflareHostnameObservation(
            _CloudflareHostnameState.MALFORMED,
            dns_record_id=record_id,
        )
    if content == _tunnel_target(tunnel_id):
        return _CloudflareHostnameObservation(
            _CloudflareHostnameState.TARGETS_TUNNEL,
            dns_record_id=record_id,
        )
    return _CloudflareHostnameObservation(
        _CloudflareHostnameState.OCCUPIED,
        dns_record_id=record_id,
    )


def _provider_failure_category(
    error: Exception,
) -> CloudflareProviderFailureCategory:
    if isinstance(
        error,
        (_CloudflareMalformedResponse, PublicIngressContractError),
    ):
        return CloudflareProviderFailureCategory.MALFORMED_RESPONSE
    if isinstance(error, CloudflareApiTransportError):
        return CloudflareProviderFailureCategory.TRANSPORT
    return CloudflareProviderFailureCategory.PROVIDER_STATUS


def _is_provider_operation_failure(error: Exception) -> bool:
    return isinstance(
        error,
        (CloudflareApiError, PublicIngressContractError),
    )


def _provider_operation_error(
    message: str,
    *,
    stage: CloudflareProviderFailureStage,
    category: CloudflareProviderFailureCategory,
    mutation_certainty: CloudflareProviderMutationCertainty,
    tunnel_id: str | None = None,
    dns_record_id: str | None = None,
    cleanup_result: CloudflareProviderCleanupResult,
) -> CloudflareProviderOperationError:
    return CloudflareProviderOperationError(
        message,
        CloudflareProviderFailureEvidence(
            stage=stage,
            category=category,
            mutation_certainty=mutation_certainty,
            tunnel_id=tunnel_id,
            dns_record_id=dns_record_id,
            cleanup_result=cleanup_result,
        ),
    )


def _hostname_observation_error(
    observation: _CloudflareHostnameObservation,
    *,
    stage: CloudflareProviderFailureStage,
    tunnel_id: str | None,
    mutation_certainty: CloudflareProviderMutationCertainty,
    cleanup_result: CloudflareProviderCleanupResult,
) -> CloudflareProviderOperationError:
    if observation.state is _CloudflareHostnameState.OCCUPIED:
        category = CloudflareProviderFailureCategory.HOSTNAME_OCCUPIED
        message = "Cloudflare DNS hostname is already allocated"
    elif observation.state is _CloudflareHostnameState.MALFORMED:
        category = CloudflareProviderFailureCategory.MALFORMED_RESPONSE
        message = "Cloudflare DNS observation is malformed"
    else:
        category = CloudflareProviderFailureCategory.DNS_CONFLICT
        message = "Cloudflare DNS hostname observation is conflicting"
    return _provider_operation_error(
        message,
        stage=stage,
        category=category,
        mutation_certainty=mutation_certainty,
        tunnel_id=tunnel_id,
        dns_record_id=observation.dns_record_id,
        cleanup_result=cleanup_result,
    )


def _delete_known_tunnel(
    client: "CloudflareApiClient",
    tunnel_id: str,
) -> CloudflareProviderCleanupResult:
    failed = _attempt_exact_cleanup(
        (("tunnel", lambda: client.delete_tunnel(tunnel_id)),)
    )
    if failed:
        return CloudflareProviderCleanupResult.UNCERTAIN
    return CloudflareProviderCleanupResult.COMPLETE


def _cleanup_created_ingress(
    client: "CloudflareApiClient",
    *,
    tunnel_id: str,
    dns_record_id: str,
    custody: tuple[str, Callable[[], None]] | None = None,
) -> tuple[CloudflareProviderCleanupResult, tuple[str, ...]]:
    cleanup: list[tuple[str, Callable[[], None]]] = []
    if custody is not None:
        cleanup.append(custody)
    cleanup.extend(
        (
            ("dns", lambda: client.delete_dns_record(dns_record_id)),
            ("tunnel", lambda: client.delete_tunnel(tunnel_id)),
        )
    )
    failed = _attempt_exact_cleanup(cleanup)
    if failed:
        return CloudflareProviderCleanupResult.UNCERTAIN, failed
    return CloudflareProviderCleanupResult.COMPLETE, ()


def _attempt_exact_cleanup(
    stages: tuple[tuple[str, Callable[[], None]], ...]
    | list[tuple[str, Callable[[], None]]],
) -> tuple[str, ...]:
    """Attempt every exact cleanup stage and return bounded failed stage names."""

    failed: list[str] = []
    for stage, cleanup in stages:
        try:
            cleanup()
        except Exception:
            failed.append(stage)
    return tuple(failed)


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
        try:
            return _result_text(result, "id")
        except CloudflareApiError:
            raise _CloudflareMalformedResponse(
                "Cloudflare tunnel allocation response malformed"
            ) from None

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

    def create_dns_cname(self, *, hostname: str, tunnel_id: str) -> str:
        _validate_hostname(hostname)
        _validate_identifier(tunnel_id, "tunnel_id")
        records = self.list_dns_records_for_hostname(hostname)
        if records:
            raise CloudflareApiError(
                "Cloudflare DNS hostname is already allocated"
            )
        return self._create_dns_cname_unchecked(
            hostname=hostname,
            tunnel_id=tunnel_id,
        )

    def list_dns_records_for_hostname(
        self,
        hostname: str,
    ) -> list[object]:
        _validate_hostname(hostname)
        records = self._request(
            "GET",
            f"/zones/{self.authority.zone_id}/dns_records",
            params={"name": hostname},
        ).get("result")
        if not isinstance(records, list):
            raise _CloudflareMalformedResponse(
                "Cloudflare DNS lookup response malformed"
            )
        return records

    def _read_dns_reconciliation_page(
        self,
        hostname: str,
    ) -> Mapping[str, object]:
        _validate_hostname(hostname)
        return self._request(
            "GET",
            f"/zones/{self.authority.zone_id}/dns_records",
            params={"name": hostname, "page": "1", "per_page": "2"},
        )

    def _create_dns_cname_unchecked(
        self,
        *,
        hostname: str,
        tunnel_id: str,
    ) -> str:
        _validate_hostname(hostname)
        _validate_identifier(tunnel_id, "tunnel_id")
        created = self._request(
            "POST",
            f"/zones/{self.authority.zone_id}/dns_records",
            json=_dns_record_body(hostname, _tunnel_target(tunnel_id)),
        )
        try:
            return _result_text(created, "id")
        except CloudflareApiError:
            raise _CloudflareMalformedResponse(
                "Cloudflare DNS create response malformed"
            ) from None

    def get_dns_record(self, record_id: str) -> Mapping[str, object]:
        _validate_identifier(record_id, "dns_record_id")
        result = self._request(
            "GET",
            f"/zones/{self.authority.zone_id}/dns_records/{record_id}",
        ).get("result")
        if not isinstance(result, Mapping):
            raise CloudflareApiError("Cloudflare DNS record response malformed")
        return result

    def update_dns_cname(
        self,
        record_id: str,
        *,
        hostname: str,
        tunnel_id: str,
    ) -> None:
        _validate_identifier(record_id, "dns_record_id")
        _validate_hostname(hostname)
        _validate_identifier(tunnel_id, "tunnel_id")
        self._request(
            "PATCH",
            f"/zones/{self.authority.zone_id}/dns_records/{record_id}",
            json=_dns_record_body(hostname, _tunnel_target(tunnel_id)),
        )

    def get_tunnel_token(self, tunnel_id: str) -> SecretValue:
        _validate_identifier(tunnel_id, "tunnel_id")
        result = self._request(
            "GET",
            f"/accounts/{self.authority.account_id}/cfd_tunnel/{tunnel_id}/token",
        )
        token = result.get("result")
        if not isinstance(token, str) or not token.strip():
            raise _CloudflareMalformedResponse(
                "Cloudflare tunnel token response malformed"
            )
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

    def delete_tunnel_connections(self, tunnel_id: str) -> None:
        _validate_identifier(tunnel_id, "tunnel_id")
        self._request(
            "DELETE",
            f"/accounts/{self.authority.account_id}/cfd_tunnel/"
            f"{tunnel_id}/connections",
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
        try:
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
        except Exception:
            raise CloudflareApiTransportError(
                "Cloudflare API transport failed"
            ) from None
        if response.status_code == 404:
            raise CloudflareApiNotFound("Cloudflare API resource was not found")
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


def _require_reservation_authority(
    authority: CloudflareZoneAuthority,
    reservation: CloudflareOwnedHostnameReservation,
) -> None:
    if not isinstance(authority, CloudflareZoneAuthority):
        raise CloudflareApiError("reservation requires CloudflareZoneAuthority")
    if not isinstance(reservation, CloudflareOwnedHostnameReservation):
        raise CloudflareApiError(
            "reservation requires CloudflareOwnedHostnameReservation"
        )
    if not authority.allows_hostname(reservation.hostname):
        raise CloudflareApiError("owned hostname is outside admitted authority policy")


def _require_tunnel_token_custody_grant(
    grant: SecretCustodyGrant,
) -> None:
    if (
        not isinstance(grant, SecretCustodyGrant)
        or not grant.permits(
            grant.reference,
            SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
        )
    ):
        raise CloudflareApiError("tunnel token custody grant is invalid")


def _require_reservation_resource_agreement(
    reservation: CloudflareOwnedHostnameReservation,
    resources: CloudflareOwnedIngressResources,
) -> None:
    if not isinstance(resources, CloudflareOwnedIngressResources):
        raise CloudflareApiError(
            "deactivation requires CloudflareOwnedIngressResources"
        )
    if (
        resources.dns_record_id != reservation.dns_record_id
        or resources.hostname != reservation.hostname
        or resources.tunnel_id != reservation.expected_tunnel_id
    ):
        raise CloudflareApiError(
            "reservation and tunnel realization coordinates disagree"
        )


def _observe_hostname_reservation(
    client: CloudflareApiClient,
    reservation: CloudflareOwnedHostnameReservation,
) -> CloudflareHostnameReservationObservation:
    try:
        record = client.get_dns_record(reservation.dns_record_id)
    except CloudflareApiNotFound:
        return CloudflareHostnameReservationObservation(
            dns_record_id=reservation.dns_record_id,
            hostname=reservation.hostname,
            presence=CloudflareResourcePresence.ABSENT,
        )
    record_id = _mapping_text(record, "id")
    record_type = _mapping_text(record, "type")
    hostname = _mapping_text(record, "name")
    content = _mapping_text(record, "content")
    if record_id != reservation.dns_record_id:
        raise CloudflareApiError("Cloudflare DNS record id mismatch")
    if record_type != "CNAME":
        raise CloudflareApiError("Cloudflare DNS reservation type mismatch")
    if hostname.lower() != reservation.hostname.lower():
        raise CloudflareApiError("Cloudflare DNS reservation hostname mismatch")
    if record.get("proxied") is not True:
        raise CloudflareApiError("Cloudflare DNS reservation proxy mismatch")
    suffix = ".cfargotunnel.com"
    if not content.endswith(suffix):
        raise CloudflareApiError("Cloudflare DNS reservation target mismatch")
    tunnel_id = content.removesuffix(suffix)
    _validate_identifier(tunnel_id, "DNS reservation tunnel_id")
    return CloudflareHostnameReservationObservation(
        dns_record_id=record_id,
        hostname=hostname,
        presence=CloudflareResourcePresence.PRESENT,
        tunnel_id=tunnel_id,
    )


def _require_expected_reservation(
    observation: CloudflareHostnameReservationObservation,
    reservation: CloudflareOwnedHostnameReservation,
) -> CloudflareHostnameReservationObservation:
    if observation.presence is CloudflareResourcePresence.ABSENT:
        raise CloudflareApiError("Cloudflare DNS reservation is missing")
    return _require_observed_tunnel(observation, reservation.expected_tunnel_id)


def _require_observed_tunnel(
    observation: CloudflareHostnameReservationObservation,
    tunnel_id: str,
) -> CloudflareHostnameReservationObservation:
    if (
        observation.presence is not CloudflareResourcePresence.PRESENT
        or observation.tunnel_id != tunnel_id
    ):
        raise CloudflareApiError("Cloudflare DNS reservation target mismatch")
    return observation


def _restore_rebind_reservation(
    client: CloudflareApiClient,
    reservation: CloudflareOwnedHostnameReservation,
    *,
    new_tunnel_id: str,
) -> None:
    observation = _observe_hostname_reservation(client, reservation)
    if observation.presence is CloudflareResourcePresence.ABSENT:
        raise CloudflareApiError("Cloudflare DNS reservation is missing")
    if observation.tunnel_id == reservation.expected_tunnel_id:
        return
    if observation.tunnel_id != new_tunnel_id:
        raise CloudflareApiError("Cloudflare DNS reservation target mismatch")
    client.update_dns_cname(
        reservation.dns_record_id,
        hostname=reservation.hostname,
        tunnel_id=reservation.expected_tunnel_id,
    )
    _require_expected_reservation(
        _observe_hostname_reservation(client, reservation),
        reservation,
    )


def _observe_tunnel(
    client: CloudflareApiClient,
    tunnel_id: str,
) -> CloudflareTunnelObservation:
    try:
        result = client.get_tunnel(tunnel_id)
    except CloudflareApiNotFound:
        return CloudflareTunnelObservation(
            tunnel_id=tunnel_id,
            presence=CloudflareResourcePresence.ABSENT,
        )
    if _mapping_text(result, "id") != tunnel_id:
        raise CloudflareApiError("Cloudflare tunnel id mismatch")
    deleted_at = result.get("deleted_at")
    if deleted_at is not None:
        if not isinstance(deleted_at, str) or not deleted_at.strip():
            raise CloudflareApiError(
                "Cloudflare tunnel deletion marker is malformed"
            )
        return CloudflareTunnelObservation(
            tunnel_id=tunnel_id,
            presence=CloudflareResourcePresence.ABSENT,
        )
    return CloudflareTunnelObservation(
        tunnel_id=tunnel_id,
        presence=CloudflareResourcePresence.PRESENT,
    )


def _tunnel_target(tunnel_id: str) -> str:
    _validate_identifier(tunnel_id, "tunnel_id")
    return f"{tunnel_id}.cfargotunnel.com"


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
