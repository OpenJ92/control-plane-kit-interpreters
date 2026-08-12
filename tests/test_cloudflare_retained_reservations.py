from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
import unittest

from control_plane_kit_core.public_ingress import (
    IngressAuthorityReference,
    NamedPublicIngress,
    PublicIngressTarget,
)
from control_plane_kit_core.secrets import (
    SecretCustodyGrant,
    SecretCustodyReceipt,
    SecretProviderEndpointReference,
    SecretReference,
    SecretResolution,
    SecretResolutionGrant,
    SecretResolved,
    SecretUseIntent,
    SecretValue,
)

from control_plane_kit_interpreters import cloudflare


API_TOKEN = "cf-api-token-value"
TUNNEL_TOKEN = "eyJ-cloudflare-tunnel-token"
HOSTNAME = "cpk-gateway-001.openj92.dev"
DNS_RECORD_ID = "dns-001"
OLD_TUNNEL_ID = "tunnel-old"
NEW_TUNNEL_ID = "tunnel-new"


class CloudflareRetainedReservationTests(unittest.TestCase):
    def test_rebind_verifies_and_updates_only_the_exact_owned_record(self) -> None:
        transport = StatefulCloudflareTransport()
        custodian = RecordingSecretCustodian()
        interpreter = _interpreter(transport, custodian)

        allocation = interpreter.rebind(
            _ingress(),
            authority=_authority(),
            reservation=_reservation(),
            allocation_name="cpk-gateway-001-epoch-2",
            origin_service_url="http://gateway:8000",
            secret_resolution_grant=_resolution_grant(),
            secret_custody_grant=_custody_grant(),
        )

        self.assertEqual(allocation.tunnel_id, NEW_TUNNEL_ID)
        self.assertEqual(allocation.dns_record_id, DNS_RECORD_ID)
        self.assertEqual(transport.dns_content, _target(NEW_TUNNEL_ID))
        self.assertEqual(
            [(request.method, request.path) for request in transport.requests],
            [
                ("POST", "/accounts/account-001/cfd_tunnel"),
                (
                    "PUT",
                    f"/accounts/account-001/cfd_tunnel/{NEW_TUNNEL_ID}/configurations",
                ),
                ("GET", f"/zones/zone-001/dns_records/{DNS_RECORD_ID}"),
                ("PATCH", f"/zones/zone-001/dns_records/{DNS_RECORD_ID}"),
                ("GET", f"/zones/zone-001/dns_records/{DNS_RECORD_ID}"),
                ("GET", f"/accounts/account-001/cfd_tunnel/{NEW_TUNNEL_ID}/token"),
                ("GET", f"/zones/zone-001/dns_records/{DNS_RECORD_ID}"),
            ],
        )
        self.assertFalse(any(request.path == "/zones/zone-001/dns_records" for request in transport.requests))
        dns_update = next(
            request for request in transport.requests if request.stage == "dns-update"
        )
        self.assertEqual(
            dns_update.json,
            {
                "type": "CNAME",
                "proxied": True,
                "name": HOSTNAME,
                "content": _target(NEW_TUNNEL_ID),
            },
        )
        self.assertEqual(custodian.stored_references, [_custody_grant().reference])
        self.assertNotIn(TUNNEL_TOKEN, repr(allocation))

    def test_rebind_rejects_foreign_or_stale_record_truth_before_dns_mutation(self) -> None:
        cases = (
            ("dns-foreign", "CNAME", HOSTNAME, True, _target(OLD_TUNNEL_ID)),
            (DNS_RECORD_ID, "A", HOSTNAME, True, "203.0.113.10"),
            (DNS_RECORD_ID, "CNAME", "other.openj92.dev", True, _target(OLD_TUNNEL_ID)),
            (DNS_RECORD_ID, "CNAME", HOSTNAME, False, _target(OLD_TUNNEL_ID)),
            (DNS_RECORD_ID, "CNAME", HOSTNAME, True, _target("tunnel-foreign")),
        )
        for record_id, record_type, name, proxied, content in cases:
            with self.subTest(
                record_id=record_id,
                record_type=record_type,
                name=name,
                proxied=proxied,
                content=content,
            ):
                transport = StatefulCloudflareTransport(
                    response_record_id=record_id,
                    dns_type=record_type,
                    dns_name=name,
                    dns_proxied=proxied,
                    dns_content=content,
                )
                custodian = RecordingSecretCustodian()

                with self.assertRaises(cloudflare.CloudflareApiError):
                    _interpreter(transport, custodian).rebind(
                        _ingress(),
                        authority=_authority(),
                        reservation=_reservation(),
                        allocation_name="cpk-gateway-001-epoch-2",
                        origin_service_url="http://gateway:8000",
                        secret_resolution_grant=_resolution_grant(),
                        secret_custody_grant=_custody_grant(),
                    )

                self.assertFalse(any(request.method == "PATCH" for request in transport.requests))
                self.assertIn(
                    ("DELETE", f"/accounts/account-001/cfd_tunnel/{NEW_TUNNEL_ID}"),
                    [(request.method, request.path) for request in transport.requests],
                )
                self.assertEqual(custodian.stored_references, [])

    def test_rebind_missing_record_fails_closed_without_dns_mutation(self) -> None:
        transport = StatefulCloudflareTransport(dns_present=False)

        with self.assertRaisesRegex(
            cloudflare.CloudflareApiError,
            "reservation is missing",
        ):
            _interpreter(transport).rebind(
                _ingress(),
                authority=_authority(),
                reservation=_reservation(),
                allocation_name="cpk-gateway-001-epoch-2",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertFalse(any(request.method == "PATCH" for request in transport.requests))
        self.assertFalse(transport.tunnel_present)

    def test_rebind_fault_matrix_compensates_only_the_new_tunnel_before_rebind(self) -> None:
        cases = (
            ("tunnel-allocation", []),
            ("tunnel-configuration", ["tunnel-delete"]),
            ("dns-observe", ["tunnel-delete"]),
            ("dns-update", ["tunnel-delete"]),
        )
        for fault_stage, expected_cleanup in cases:
            with self.subTest(fault_stage=fault_stage):
                transport = StatefulCloudflareTransport(
                    fault_stages={fault_stage},
                )

                with self.assertRaises(cloudflare.CloudflareApiError):
                    _interpreter(transport).rebind(
                        _ingress(),
                        authority=_authority(),
                        reservation=_reservation(),
                        allocation_name="cpk-gateway-001-epoch-2",
                        origin_service_url="http://gateway:8000",
                        secret_resolution_grant=_resolution_grant(),
                        secret_custody_grant=_custody_grant(),
                    )

                self.assertEqual(
                    [
                        request.stage
                        for request in transport.requests
                        if request.stage.endswith("delete")
                    ],
                    expected_cleanup,
                )
                self.assertFalse(
                    any(
                        request.stage == "dns-update"
                        for request in transport.requests
                        if fault_stage != "dns-update"
                    )
                )

    def test_rebind_custody_failure_revokes_attempted_version_and_restores(self) -> None:
        transport = StatefulCloudflareTransport()
        custodian = RecordingSecretCustodian(fail_store=True)

        with self.assertRaisesRegex(
            cloudflare.CloudflareApiError,
            "generated secret custody failed",
        ):
            _interpreter(transport, custodian).rebind(
                _ingress(),
                authority=_authority(),
                reservation=_reservation(),
                allocation_name="cpk-gateway-001-epoch-2",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(custodian.stored_references, [_custody_grant().reference])
        self.assertEqual(custodian.revoked_references, [_custody_grant().reference])
        self.assertEqual(transport.dns_content, _target(OLD_TUNNEL_ID))
        self.assertFalse(transport.tunnel_present)

    def test_rebind_token_failure_restores_exact_old_target_and_removes_new_tunnel(self) -> None:
        transport = StatefulCloudflareTransport(fault_stages={"tunnel-token"})

        with self.assertRaises(cloudflare.CloudflareApiError):
            _interpreter(transport).rebind(
                _ingress(),
                authority=_authority(),
                reservation=_reservation(),
                allocation_name="cpk-gateway-001-epoch-2",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(transport.dns_content, _target(OLD_TUNNEL_ID))
        self.assertFalse(transport.tunnel_present)
        self.assertEqual(
            [request.stage for request in transport.requests if request.stage.startswith("dns-")],
            ["dns-observe", "dns-update", "dns-observe", "dns-observe", "dns-update", "dns-observe"],
        )

    def test_rebind_ambiguous_update_restores_only_an_observed_new_target(self) -> None:
        transport = StatefulCloudflareTransport(
            raise_after_apply_stages={"dns-update"},
        )

        with self.assertRaisesRegex(
            cloudflare.CloudflareApiError,
            "rebind is uncertain",
        ) as raised:
            _interpreter(transport).rebind(
                _ingress(),
                authority=_authority(),
                reservation=_reservation(),
                allocation_name="cpk-gateway-001-epoch-2",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(transport.dns_content, _target(OLD_TUNNEL_ID))
        self.assertFalse(transport.tunnel_present)
        self.assertNotIn(API_TOKEN, repr(raised.exception))
        self.assertNotIn(TUNNEL_TOKEN, repr(raised.exception))

    def test_rebind_never_overwrites_an_unexpected_post_update_target(self) -> None:
        transport = StatefulCloudflareTransport(
            replacement_after_update=_target("tunnel-foreign"),
        )

        with self.assertRaisesRegex(
            cloudflare.CloudflareApiError,
            "rebind cleanup is uncertain: dns",
        ):
            _interpreter(transport).rebind(
                _ingress(),
                authority=_authority(),
                reservation=_reservation(),
                allocation_name="cpk-gateway-001-epoch-2",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(transport.dns_content, _target("tunnel-foreign"))
        self.assertEqual(
            len([request for request in transport.requests if request.method == "PATCH"]),
            1,
        )
        self.assertFalse(transport.tunnel_present)

    def test_rebind_reobserves_after_custody_and_refuses_late_foreign_target(self) -> None:
        transport = StatefulCloudflareTransport(
            replacement_after_token=_target("tunnel-foreign"),
        )
        custodian = RecordingSecretCustodian()

        with self.assertRaisesRegex(
            cloudflare.CloudflareApiError,
            "rebind cleanup is uncertain: dns",
        ):
            _interpreter(transport, custodian).rebind(
                _ingress(),
                authority=_authority(),
                reservation=_reservation(),
                allocation_name="cpk-gateway-001-epoch-2",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(custodian.revoked_references, [_custody_grant().reference])
        self.assertEqual(transport.dns_content, _target("tunnel-foreign"))
        self.assertFalse(transport.tunnel_present)

    def test_deactivation_preserves_exact_dns_and_verifies_tunnel_absence(self) -> None:
        transport = StatefulCloudflareTransport()
        custodian = RecordingSecretCustodian()

        result = _interpreter(transport, custodian).deactivate_preserving_reservation(
            authority=_authority(),
            reservation=_reservation(),
            resources=_owned_resources(),
            secret_resolution_grant=_resolution_grant(),
            secret_custody_grant=_custody_grant(),
        )

        self.assertEqual(result.reservation.presence.value, "present")
        self.assertEqual(result.reservation.tunnel_id, OLD_TUNNEL_ID)
        self.assertEqual(result.tunnel.presence.value, "absent")
        self.assertEqual(custodian.revoked_references, [_custody_grant().reference])
        self.assertEqual(transport.dns_content, _target(OLD_TUNNEL_ID))
        self.assertFalse(transport.tunnel_present)
        self.assertFalse(any(request.stage in {"dns-update", "dns-delete"} for request in transport.requests))
        self.assertEqual(
            [request.stage for request in transport.requests],
            [
                "dns-observe",
                "tunnel-connections-delete",
                "tunnel-delete",
                "dns-observe",
                "tunnel-observe",
            ],
        )

    def test_deactivation_accepts_exact_tunnel_tombstone_as_absent(self) -> None:
        transport = StatefulCloudflareTransport(tombstone_after_delete=True)

        result = _interpreter(transport).deactivate_preserving_reservation(
            authority=_authority(),
            reservation=_reservation(),
            resources=_owned_resources(),
            secret_resolution_grant=_resolution_grant(),
            secret_custody_grant=_custody_grant(),
        )

        self.assertEqual(result.tunnel.tunnel_id, OLD_TUNNEL_ID)
        self.assertEqual(result.tunnel.presence.value, "absent")

    def test_deactivation_requires_exact_reservation_realization_agreement(self) -> None:
        transport = StatefulCloudflareTransport()
        custodian = RecordingSecretCustodian()
        resources = cloudflare.CloudflareOwnedIngressResources(
            tunnel_id="tunnel-foreign",
            dns_record_id=DNS_RECORD_ID,
            tunnel_name="cpk-gateway-001",
            hostname=HOSTNAME,
        )

        with self.assertRaises(cloudflare.CloudflareApiError):
            _interpreter(transport, custodian).deactivate_preserving_reservation(
                authority=_authority(),
                reservation=_reservation(),
                resources=resources,
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(transport.requests, [])
        self.assertEqual(custodian.revoked_references, [])

    def test_deactivation_rejects_wrong_custody_grant_before_io(self) -> None:
        transport = StatefulCloudflareTransport()
        custodian = RecordingSecretCustodian()

        with self.assertRaisesRegex(
            cloudflare.CloudflareApiError,
            "custody grant is invalid",
        ):
            _interpreter(transport, custodian).deactivate_preserving_reservation(
                authority=_authority(),
                reservation=_reservation(),
                resources=_owned_resources(),
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(
                    intent=SecretUseIntent.OCI_PULL_CREDENTIAL,
                ),
            )

        self.assertEqual(transport.requests, [])
        self.assertEqual(custodian.revoked_references, [])

    def test_deactivation_attempts_all_exact_stages_and_bounds_uncertainty(self) -> None:
        transport = StatefulCloudflareTransport(
            fault_stages={"tunnel-connections-delete", "tunnel-delete"},
        )
        custodian = RecordingSecretCustodian(fail_revoke=True)

        with self.assertRaises(cloudflare.CloudflareApiError) as raised:
            _interpreter(transport, custodian).deactivate_preserving_reservation(
                authority=_authority(),
                reservation=_reservation(),
                resources=_owned_resources(),
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(
            str(raised.exception),
            "Cloudflare retained deactivation is uncertain: custody,connections,tunnel,tunnel-observation",
        )
        self.assertEqual(
            [request.stage for request in transport.requests],
            [
                "dns-observe",
                "tunnel-connections-delete",
                "tunnel-delete",
                "dns-observe",
                "tunnel-observe",
            ],
        )
        self.assertEqual(transport.dns_content, _target(OLD_TUNNEL_ID))
        self.assertNotIn(API_TOKEN, repr(raised.exception))
        self.assertNotIn(TUNNEL_TOKEN, repr(raised.exception))

    def test_deactivation_reports_lost_reservation_without_deleting_dns(self) -> None:
        transport = StatefulCloudflareTransport(
            remove_dns_after_tunnel_delete=True,
        )

        with self.assertRaisesRegex(
            cloudflare.CloudflareApiError,
            "reservation-observation",
        ):
            _interpreter(transport).deactivate_preserving_reservation(
                authority=_authority(),
                reservation=_reservation(),
                resources=_owned_resources(),
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertFalse(any(request.stage == "dns-delete" for request in transport.requests))

    def test_release_deletes_exact_record_and_verifies_absence(self) -> None:
        transport = StatefulCloudflareTransport()

        result = _interpreter(transport).release_reservation(
            authority=_authority(),
            reservation=_reservation(),
            secret_resolution_grant=_resolution_grant(),
        )

        self.assertEqual(result.presence.value, "absent")
        self.assertEqual(result.dns_record_id, DNS_RECORD_ID)
        self.assertFalse(transport.dns_present)
        self.assertEqual(
            [request.stage for request in transport.requests],
            ["dns-observe", "dns-delete", "dns-observe"],
        )

    def test_release_rejects_missing_or_mismatched_record_without_delete(self) -> None:
        transports = (
            StatefulCloudflareTransport(dns_present=False),
            StatefulCloudflareTransport(dns_content=_target("tunnel-foreign")),
        )
        for transport in transports:
            with self.subTest(dns_present=transport.dns_present, content=transport.dns_content):
                with self.assertRaises(cloudflare.CloudflareApiError):
                    _interpreter(transport).release_reservation(
                        authority=_authority(),
                        reservation=_reservation(),
                        secret_resolution_grant=_resolution_grant(),
                    )

                self.assertFalse(any(request.method == "DELETE" for request in transport.requests))

    def test_release_transport_ambiguity_remains_uncertain_after_observed_absence(self) -> None:
        transport = StatefulCloudflareTransport(
            raise_after_apply_stages={"dns-delete"},
        )

        with self.assertRaisesRegex(
            cloudflare.CloudflareApiError,
            "reservation release is uncertain: dns",
        ) as raised:
            _interpreter(transport).release_reservation(
                authority=_authority(),
                reservation=_reservation(),
                secret_resolution_grant=_resolution_grant(),
            )

        self.assertFalse(transport.dns_present)
        self.assertNotIn(API_TOKEN, repr(raised.exception))

    def test_release_known_delete_failure_preserves_record_and_reports_absence_failure(self) -> None:
        transport = StatefulCloudflareTransport(fault_stages={"dns-delete"})

        with self.assertRaises(cloudflare.CloudflareApiError) as raised:
            _interpreter(transport).release_reservation(
                authority=_authority(),
                reservation=_reservation(),
                secret_resolution_grant=_resolution_grant(),
            )

        self.assertEqual(
            str(raised.exception),
            "Cloudflare reservation release is uncertain: dns,absence",
        )
        self.assertTrue(transport.dns_present)

    def test_observe_reservation_reports_exact_present_and_absent_truth(self) -> None:
        transport = StatefulCloudflareTransport()
        interpreter = _interpreter(transport)

        present = interpreter.observe_reservation(
            authority=_authority(),
            reservation=_reservation(),
            secret_resolution_grant=_resolution_grant(),
        )
        transport.dns_present = False
        absent = interpreter.observe_reservation(
            authority=_authority(),
            reservation=_reservation(),
            secret_resolution_grant=_resolution_grant(),
        )

        self.assertEqual(present.presence.value, "present")
        self.assertEqual(present.tunnel_id, OLD_TUNNEL_ID)
        self.assertEqual(absent.presence.value, "absent")
        self.assertIsNone(absent.tunnel_id)


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    stage: str
    headers: Mapping[str, str]
    json: Mapping[str, object] | None


class StatefulCloudflareTransport:
    def __init__(
        self,
        *,
        dns_present: bool = True,
        response_record_id: str = DNS_RECORD_ID,
        dns_type: str = "CNAME",
        dns_name: str = HOSTNAME,
        dns_proxied: bool = True,
        dns_content: str = "tunnel-old.cfargotunnel.com",
        fault_stages: set[str] | None = None,
        raise_stages: set[str] | None = None,
        raise_after_apply_stages: set[str] | None = None,
        replacement_after_update: str | None = None,
        replacement_after_token: str | None = None,
        remove_dns_after_tunnel_delete: bool = False,
        tombstone_after_delete: bool = False,
    ) -> None:
        self.requests: list[RecordedRequest] = []
        self.dns_present = dns_present
        self.response_record_id = response_record_id
        self.dns_type = dns_type
        self.dns_name = dns_name
        self.dns_proxied = dns_proxied
        self.dns_content = dns_content
        self.tunnel_present = True
        self.fault_stages = set(fault_stages or ())
        self.raise_stages = set(raise_stages or ())
        self.raise_after_apply_stages = set(raise_after_apply_stages or ())
        self.replacement_after_update = replacement_after_update
        self.replacement_after_token = replacement_after_token
        self.remove_dns_after_tunnel_delete = remove_dns_after_tunnel_delete
        self.tombstone_after_delete = tombstone_after_delete

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> cloudflare.CloudflareHttpResponse:
        del params
        path = url.removeprefix("https://api.cloudflare.com/client/v4")
        stage = _request_stage(method, path)
        self.requests.append(RecordedRequest(method, path, stage, dict(headers), json))
        if stage in self.raise_stages:
            raise RuntimeError(API_TOKEN)
        if stage in self.fault_stages:
            return cloudflare.CloudflareHttpResponse(503, {"success": False})

        response = self._apply(method, path, stage, json)
        if stage in self.raise_after_apply_stages:
            self.raise_after_apply_stages.remove(stage)
            raise RuntimeError(API_TOKEN)
        return response

    def _apply(
        self,
        method: str,
        path: str,
        stage: str,
        json: Mapping[str, object] | None,
    ) -> cloudflare.CloudflareHttpResponse:
        if stage == "tunnel-allocation":
            self.tunnel_present = True
            return _success({"id": NEW_TUNNEL_ID})
        if stage == "dns-observe":
            if not self.dns_present:
                return cloudflare.CloudflareHttpResponse(404, {"success": False})
            return _success(
                {
                    "id": self.response_record_id,
                    "type": self.dns_type,
                    "name": self.dns_name,
                    "proxied": self.dns_proxied,
                    "content": self.dns_content,
                }
            )
        if stage == "dns-update":
            assert json is not None
            self.dns_content = str(json["content"])
            if self.replacement_after_update is not None:
                self.dns_content = self.replacement_after_update
            return _success(
                {
                    "id": DNS_RECORD_ID,
                    "type": "CNAME",
                    "name": HOSTNAME,
                    "proxied": True,
                    "content": self.dns_content,
                }
            )
        if stage == "dns-delete":
            self.dns_present = False
            return _success({"id": DNS_RECORD_ID})
        if stage == "tunnel-token":
            if self.replacement_after_token is not None:
                self.dns_content = self.replacement_after_token
            return _success(TUNNEL_TOKEN)
        if stage == "tunnel-delete":
            self.tunnel_present = False
            if self.remove_dns_after_tunnel_delete:
                self.dns_present = False
            return _success({"id": NEW_TUNNEL_ID})
        if stage == "tunnel-observe":
            if not self.tunnel_present:
                if self.tombstone_after_delete:
                    return _success(
                        {
                            "id": OLD_TUNNEL_ID,
                            "deleted_at": "2026-08-06T06:57:38Z",
                        }
                    )
                return cloudflare.CloudflareHttpResponse(404, {"success": False})
            return _success({"id": OLD_TUNNEL_ID, "status": "down"})
        return _success({})


@dataclass(repr=False)
class RecordingSecretCustodian:
    fail_store: bool = False
    fail_revoke: bool = False

    def __post_init__(self) -> None:
        self.stored_references: list[SecretReference] = []
        self.revoked_references: list[SecretReference] = []

    def store(
        self,
        grant: SecretCustodyGrant,
        value: SecretValue,
    ) -> SecretCustodyReceipt:
        self.stored_references.append(grant.reference)
        if self.fail_store:
            raise RuntimeError(TUNNEL_TOKEN)
        if value.reveal() != TUNNEL_TOKEN:
            raise AssertionError("unexpected test token")
        return SecretCustodyReceipt(
            custody_id=grant.custody_id,
            provider_registration_id=grant.provider_registration_id,
            reference=grant.reference,
            version_id="version-tunnel-token",
            version_number=2,
        )

    def revoke(self, grant: SecretCustodyGrant) -> None:
        self.revoked_references.append(grant.reference)
        if self.fail_revoke:
            raise RuntimeError(TUNNEL_TOKEN)

    def __repr__(self) -> str:
        return "RecordingSecretCustodian(<redacted>)"


@dataclass
class RecordingAuthorizedSecretResolver:
    result: SecretResolution

    def resolve(self, grant: SecretResolutionGrant) -> SecretResolution:
        return self.result


def _interpreter(
    transport: StatefulCloudflareTransport,
    custodian: RecordingSecretCustodian | None = None,
) -> cloudflare.CloudflareNamedIngressInterpreter:
    return cloudflare.CloudflareNamedIngressInterpreter(
        transport=transport,
        authorized_secret_resolver=RecordingAuthorizedSecretResolver(
            SecretResolved(_authority().api_token_ref, SecretValue(API_TOKEN))
        ),
        secret_custodian=custodian or RecordingSecretCustodian(),
    )


def _reservation():
    return cloudflare.CloudflareOwnedHostnameReservation(
        dns_record_id=DNS_RECORD_ID,
        hostname=HOSTNAME,
        expected_tunnel_id=OLD_TUNNEL_ID,
    )


def _authority() -> cloudflare.CloudflareZoneAuthority:
    return cloudflare.CloudflareZoneAuthority(
        account_id="account-001",
        zone_id="zone-001",
        zone_name="openj92.dev",
        api_token_ref=SecretReference("secret://local/cf/api-token"),
        allowed_hostname_pattern="cpk-gateway-*.openj92.dev",
    )


def _owned_resources() -> cloudflare.CloudflareOwnedIngressResources:
    return cloudflare.CloudflareOwnedIngressResources(
        tunnel_id=OLD_TUNNEL_ID,
        dns_record_id=DNS_RECORD_ID,
        tunnel_name="cpk-gateway-001",
        hostname=HOSTNAME,
    )


def _ingress() -> NamedPublicIngress:
    return NamedPublicIngress(
        ingress_id="gateway-001",
        authority_ref=IngressAuthorityReference("openj92-ingress"),
        target=PublicIngressTarget("gateway", "control"),
        connector_node_id="cloudflared-gateway-001",
        hostname=HOSTNAME,
    )


def _resolution_grant() -> SecretResolutionGrant:
    return SecretResolutionGrant(
        authorization_id="suse_" + "e" * 64,
        workspace_id="workspace-a",
        reference_registration_id="sref_" + "f" * 64,
        provider_registration_id="sprov_" + "b" * 64,
        endpoint_reference=SecretProviderEndpointReference("workspace-secrets"),
        credential_reference=SecretReference("secret://bootstrap/provider-token"),
        reference=_authority().api_token_ref,
        intent=SecretUseIntent.CLOUDFLARE_API_TOKEN,
        actor_subject="worker-a",
        correlation_id="secret-resolution-" + "1" * 64,
        intent_fingerprint="2" * 64,
        run_id="run-a",
        activity_id="allocate-gateway",
        effect_id="event-001",
    )


def _custody_grant(
    *,
    intent: SecretUseIntent = SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
) -> SecretCustodyGrant:
    return SecretCustodyGrant(
        custody_id="scust_" + "a" * 64,
        workspace_id="workspace-a",
        provider_registration_id="sprov_" + "b" * 64,
        endpoint_reference=SecretProviderEndpointReference("workspace-secrets"),
        credential_reference=SecretReference("secret://bootstrap/provider-token"),
        reference=SecretReference(
            "secret://generated/ingress/cloudflared-tunnel-token/token-002"
        ),
        intent=intent,
        actor_subject="worker-a",
        correlation_id="secret-custody-" + "c" * 64,
        custody_fingerprint="d" * 64,
        run_id="run-a",
        activity_id="allocate-gateway",
        effect_id="event-001",
    )


def _request_stage(method: str, path: str) -> str:
    if method == "POST" and path == "/accounts/account-001/cfd_tunnel":
        return "tunnel-allocation"
    if method == "PUT" and path.endswith("/configurations"):
        return "tunnel-configuration"
    if method == "GET" and "/dns_records/" in path:
        return "dns-observe"
    if method == "PATCH" and "/dns_records/" in path:
        return "dns-update"
    if method == "DELETE" and "/dns_records/" in path:
        return "dns-delete"
    if method == "GET" and path.endswith("/token"):
        return "tunnel-token"
    if method == "DELETE" and path.endswith("/connections"):
        return "tunnel-connections-delete"
    if method == "DELETE" and "/cfd_tunnel/" in path:
        return "tunnel-delete"
    if method == "GET" and "/cfd_tunnel/" in path:
        return "tunnel-observe"
    return "unknown"


def _success(result: object) -> cloudflare.CloudflareHttpResponse:
    return cloudflare.CloudflareHttpResponse(
        200,
        {"success": True, "result": result},
    )


def _target(tunnel_id: str) -> str:
    return f"{tunnel_id}.cfargotunnel.com"


if __name__ == "__main__":
    unittest.main()
