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
    SecretDenied,
    SecretProviderEndpointReference,
    SecretReference,
    SecretResolution,
    SecretResolutionCode,
    SecretResolutionError,
    SecretResolutionGrant,
    SecretResolved,
    SecretUseIntent,
    SecretValue,
)

from control_plane_kit_interpreters.cloudflare import (
    CloudflareApiClient,
    CloudflareApiError,
    CloudflareHttpResponse,
    CloudflareNamedIngressInterpreter,
    CloudflareOwnedIngressResources,
    CloudflareZoneAuthority,
)


API_TOKEN = "cf-api-token-value"
TUNNEL_TOKEN = "eyJ-cloudflare-tunnel-token"


class CloudflareNamedIngressInterpreterTests(unittest.TestCase):
    def test_create_constructs_tunnel_config_dns_and_token_requests(self) -> None:
        transport = FakeCloudflareTransport()
        custodian = RecordingSecretCustodian()
        resolver = _authorized_resolver()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=resolver,
            secret_custodian=custodian,
        )

        allocation = interpreter.create(
            _ingress(),
            authority=_authority(),
            allocation_name="cpk-gateway-001-c0303ba7369e",
            origin_service_url="http://gateway:8000",
            secret_resolution_grant=_resolution_grant(),
            secret_custody_grant=_custody_grant(),
        )

        self.assertEqual(allocation.tunnel_id, "tunnel-001")
        self.assertEqual(allocation.dns_record_id, "dns-001")
        self.assertEqual(allocation.tunnel_name, "cpk-gateway-001-c0303ba7369e")
        self.assertEqual(allocation.hostname, "cpk-gateway-001.openj92.dev")
        self.assertEqual(allocation.endpoint_url, "https://cpk-gateway-001.openj92.dev")
        self.assertTrue(allocation.secret_custody_receipt.matches(_custody_grant()))
        self.assertEqual(custodian.stored_references, [_custody_grant().reference])
        self.assertEqual(resolver.grants, [_resolution_grant()])
        self.assertTrue(custodian.received_expected_value)
        self.assertNotIn(TUNNEL_TOKEN, repr(allocation))
        self.assertEqual(
            [
                (request.method, request.path)
                for request in transport.requests
            ],
            [
                ("POST", "/accounts/account-001/cfd_tunnel"),
                ("PUT", "/accounts/account-001/cfd_tunnel/tunnel-001/configurations"),
                ("GET", "/zones/zone-001/dns_records"),
                ("POST", "/zones/zone-001/dns_records"),
                ("GET", "/accounts/account-001/cfd_tunnel/tunnel-001/token"),
            ],
        )
        tunnel_create = transport.requests[0]
        self.assertEqual(
            tunnel_create.json,
            {
                "name": "cpk-gateway-001-c0303ba7369e",
                "config_src": "cloudflare",
            },
        )
        tunnel_config = transport.requests[1]
        self.assertEqual(
            tunnel_config.json,
            {
                "config": {
                    "ingress": [
                        {
                            "hostname": "cpk-gateway-001.openj92.dev",
                            "service": "http://gateway:8000",
                            "originRequest": {},
                        },
                        {"service": "http_status:404"},
                    ]
                }
            },
        )
        dns_create = transport.requests[3]
        self.assertEqual(
            dns_create.json,
            {
                "type": "CNAME",
                "proxied": True,
                "name": "cpk-gateway-001.openj92.dev",
                "content": "tunnel-001.cfargotunnel.com",
            },
        )
        for request in transport.requests:
            self.assertEqual(request.headers["Authorization"], f"Bearer {API_TOKEN}")
            self.assertNotIn(TUNNEL_TOKEN, repr(request))

    def test_existing_dns_record_is_rejected_without_mutation(self) -> None:
        transport = FakeCloudflareTransport(existing_dns_record_id="dns-existing")
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
            secret_custodian=RecordingSecretCustodian(),
        )

        with self.assertRaisesRegex(
            CloudflareApiError,
            "DNS hostname is already allocated",
        ):
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(
            [(request.method, request.path) for request in transport.requests],
            [
                ("POST", "/accounts/account-001/cfd_tunnel"),
                ("PUT", "/accounts/account-001/cfd_tunnel/tunnel-001/configurations"),
                ("GET", "/zones/zone-001/dns_records"),
                ("DELETE", "/accounts/account-001/cfd_tunnel/tunnel-001"),
            ],
        )

    def test_create_fault_matrix_compensates_only_known_owned_stages(self) -> None:
        cases = (
            ("tunnel-allocation", []),
            ("tunnel-configuration", ["tunnel-delete"]),
            ("dns-lookup", ["tunnel-delete"]),
            ("dns-create", ["tunnel-delete"]),
            ("tunnel-token", ["dns-delete", "tunnel-delete"]),
        )
        for fault_stage, expected_cleanup in cases:
            with self.subTest(fault_stage=fault_stage):
                transport = FakeCloudflareTransport(fault_stages={fault_stage})
                interpreter = CloudflareNamedIngressInterpreter(
                    transport=transport,
                    authorized_secret_resolver=_authorized_resolver(),
                    secret_custodian=RecordingSecretCustodian(),
                )

                with self.assertRaises(CloudflareApiError):
                    interpreter.create(
                        _ingress(),
                        authority=_authority(),
                        allocation_name="cpk-gateway-001-c0303ba7369e",
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

    def test_create_compensation_attempts_every_known_stage_and_bounds_uncertainty(self) -> None:
        transport = FakeCloudflareTransport(
            fault_stages={"dns-delete", "tunnel-delete"},
        )
        custodian = RecordingSecretCustodian(
            fail_store=True,
            fail_revoke=True,
        )
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
            secret_custodian=custodian,
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(
            str(raised.exception),
            "Cloudflare exact cleanup is uncertain: custody,dns,tunnel",
        )
        self.assertEqual(
            [request.stage for request in transport.requests[-2:]],
            ["dns-delete", "tunnel-delete"],
        )
        self.assertNotIn(API_TOKEN, repr(raised.exception))
        self.assertNotIn(TUNNEL_TOKEN, repr(raised.exception))

    def test_missing_authorized_secret_resolver_fails_before_api_mutation(self) -> None:
        transport = FakeCloudflareTransport()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            secret_custodian=RecordingSecretCustodian(),
        )

        with self.assertRaises(SecretResolutionError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertIs(raised.exception.code, SecretResolutionCode.MISSING)
        self.assertEqual(transport.requests, [])
        self.assertNotIn(API_TOKEN, repr(raised.exception))

    def test_missing_secret_custodian_fails_before_api_mutation(self) -> None:
        transport = FakeCloudflareTransport()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
        )

        with self.assertRaises(SecretResolutionError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertIs(raised.exception.code, SecretResolutionCode.MISSING)
        self.assertEqual(transport.requests, [])

    def test_provider_custody_failure_compensates_exact_dns_and_tunnel(self) -> None:
        transport = FakeCloudflareTransport()
        custodian = RecordingSecretCustodian(fail_store=True)
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
            secret_custodian=custodian,
        )

        with self.assertRaisesRegex(
            CloudflareApiError,
            "generated secret custody failed",
        ) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(
            [(request.method, request.path) for request in transport.requests[-2:]],
            [
                ("DELETE", "/zones/zone-001/dns_records/dns-001"),
                ("DELETE", "/accounts/account-001/cfd_tunnel/tunnel-001"),
            ],
        )
        self.assertEqual(custodian.revoked_references, [_custody_grant().reference])
        self.assertNotIn(TUNNEL_TOKEN, repr(custodian))
        self.assertNotIn(TUNNEL_TOKEN, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_transport_exception_is_bounded_redacted_and_unchained(self) -> None:
        transport = FakeCloudflareTransport(
            raise_stages={"tunnel-allocation"},
        )
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
            secret_custodian=RecordingSecretCustodian(),
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(
            str(raised.exception),
            "Cloudflare API transport failed",
        )
        self.assertNotIn(API_TOKEN, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_hostname_policy_fails_closed_before_api_mutation(self) -> None:
        transport = FakeCloudflareTransport()
        resolver = _authorized_resolver()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=resolver,
            secret_custodian=RecordingSecretCustodian(),
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.create(
                NamedPublicIngress(
                    ingress_id="gateway-001",
                    authority_ref=IngressAuthorityReference("openj92-ingress"),
                    target=PublicIngressTarget("gateway", "control"),
                    connector_node_id="cloudflared-gateway-001",
                    hostname="gateway-001.cpk.openj92.dev",
                    readiness_check_id="ready",
                ),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertIn("hostname", str(raised.exception))
        self.assertEqual(transport.requests, [])

    def test_allocation_name_fails_closed_before_api_mutation(self) -> None:
        transport = FakeCloudflareTransport()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
            secret_custodian=RecordingSecretCustodian(),
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk gateway 001",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertIn("allocation_name", str(raised.exception))
        self.assertEqual(transport.requests, [])

    def test_teardown_deletes_only_recorded_owned_resources(self) -> None:
        transport = FakeCloudflareTransport()
        resolver = _authorized_resolver()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=resolver,
            secret_custodian=RecordingSecretCustodian(),
        )

        interpreter.teardown(
            authority=_authority(),
            resources=CloudflareOwnedIngressResources(
                tunnel_id="tunnel-001",
                dns_record_id="dns-001",
                tunnel_name="cpk-gateway-001",
                hostname="cpk-gateway-001.openj92.dev",
            ),
            secret_resolution_grant=_resolution_grant(),
            secret_custody_grant=_custody_grant(),
        )

        self.assertEqual(
            [(request.method, request.path) for request in transport.requests],
            [
                ("DELETE", "/zones/zone-001/dns_records/dns-001"),
                ("DELETE", "/accounts/account-001/cfd_tunnel/tunnel-001"),
            ],
        )
        self.assertEqual(resolver.grants, [_resolution_grant()])

    def test_teardown_attempts_every_exact_stage_after_each_possible_failure(self) -> None:
        cases = (
            (True, set(), "custody"),
            (False, {"dns-delete"}, "dns"),
            (False, {"tunnel-delete"}, "tunnel"),
        )
        for fail_revoke, fault_stages, expected_stage in cases:
            with self.subTest(expected_stage=expected_stage):
                transport = FakeCloudflareTransport(fault_stages=fault_stages)
                custodian = RecordingSecretCustodian(fail_revoke=fail_revoke)
                interpreter = CloudflareNamedIngressInterpreter(
                    transport=transport,
                    authorized_secret_resolver=_authorized_resolver(),
                    secret_custodian=custodian,
                )

                with self.assertRaises(CloudflareApiError) as raised:
                    interpreter.teardown(
                        authority=_authority(),
                        resources=_owned_resources(),
                        secret_resolution_grant=_resolution_grant(),
                        secret_custody_grant=_custody_grant(),
                    )

                self.assertEqual(
                    str(raised.exception),
                    f"Cloudflare exact cleanup is uncertain: {expected_stage}",
                )
                self.assertEqual(
                    [request.stage for request in transport.requests],
                    ["dns-delete", "tunnel-delete"],
                )

    def test_teardown_reports_all_failed_stages_without_secret_material(self) -> None:
        transport = FakeCloudflareTransport(
            fault_stages={"dns-delete", "tunnel-delete"},
        )
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
            secret_custodian=RecordingSecretCustodian(fail_revoke=True),
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.teardown(
                authority=_authority(),
                resources=_owned_resources(),
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(
            str(raised.exception),
            "Cloudflare exact cleanup is uncertain: custody,dns,tunnel",
        )
        self.assertEqual(
            [request.stage for request in transport.requests],
            ["dns-delete", "tunnel-delete"],
        )
        self.assertNotIn(API_TOKEN, repr(raised.exception))
        self.assertNotIn(TUNNEL_TOKEN, repr(raised.exception))

    def test_api_errors_are_bounded_and_redacted(self) -> None:
        transport = FakeCloudflareTransport(status_code=403)
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
            secret_custodian=RecordingSecretCustodian(),
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        text = repr(raised.exception)
        self.assertIn("403", text)
        self.assertNotIn(API_TOKEN, text)
        self.assertNotIn(TUNNEL_TOKEN, text)

    def test_missing_or_mismatched_api_token_grant_fails_before_api_io(self) -> None:
        authority = _authority()
        wrong_reference = SecretReference("secret://workspace/other-token")
        cases = (
            None,
            _resolution_grant(reference=wrong_reference),
            _resolution_grant(intent=SecretUseIntent.OCI_PULL_CREDENTIAL),
        )
        for grant in cases:
            with self.subTest(grant=grant):
                transport = FakeCloudflareTransport()
                resolver = _authorized_resolver()
                interpreter = CloudflareNamedIngressInterpreter(
                    transport=transport,
                    authorized_secret_resolver=resolver,
                    secret_custodian=RecordingSecretCustodian(),
                )

                with self.assertRaises(SecretResolutionError) as raised:
                    interpreter.create(
                        _ingress(),
                        authority=authority,
                        allocation_name="cpk-gateway-001-c0303ba7369e",
                        origin_service_url="http://gateway:8000",
                        secret_resolution_grant=grant,
                        secret_custody_grant=_custody_grant(),
                    )

                self.assertIs(raised.exception.code, SecretResolutionCode.DENIED)
                self.assertEqual(resolver.grants, [])
                self.assertEqual(transport.requests, [])

    def test_provider_denial_fails_before_cloudflare_api_io(self) -> None:
        transport = FakeCloudflareTransport()
        resolver = _authorized_resolver(
            SecretDenied(_authority().api_token_ref),
        )
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=resolver,
            secret_custodian=RecordingSecretCustodian(),
        )

        with self.assertRaises(SecretResolutionError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertIs(raised.exception.code, SecretResolutionCode.DENIED)
        self.assertEqual(resolver.grants, [_resolution_grant()])
        self.assertEqual(transport.requests, [])
        self.assertNotIn(API_TOKEN, repr(raised.exception))

    def test_provider_exception_is_bounded_and_redacted_before_api_io(self) -> None:
        transport = FakeCloudflareTransport()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=FailingAuthorizedSecretResolver(),
            secret_custodian=RecordingSecretCustodian(),
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )

        self.assertEqual(str(raised.exception), "Cloudflare API token resolution failed")
        self.assertNotIn(API_TOKEN, repr(raised.exception))
        self.assertEqual(transport.requests, [])


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    stage: str
    headers: Mapping[str, str]
    json: Mapping[str, object] | None
    params: Mapping[str, str] | None


@dataclass(repr=False)
class RecordingSecretCustodian:
    fail_store: bool = False
    fail_revoke: bool = False

    def __post_init__(self) -> None:
        self.stored_references: list[SecretReference] = []
        self.revoked_references: list[SecretReference] = []
        self.received_expected_value = False

    def store(
        self,
        grant: SecretCustodyGrant,
        value: SecretValue,
    ) -> SecretCustodyReceipt:
        self.stored_references.append(grant.reference)
        self.received_expected_value = value.reveal() == TUNNEL_TOKEN
        if self.fail_store:
            raise RuntimeError(TUNNEL_TOKEN)
        return SecretCustodyReceipt(
            custody_id=grant.custody_id,
            provider_registration_id=grant.provider_registration_id,
            reference=grant.reference,
            version_id="version-tunnel-token",
            version_number=1,
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

    def __post_init__(self) -> None:
        self.grants: list[SecretResolutionGrant] = []

    def resolve(self, grant: SecretResolutionGrant) -> SecretResolution:
        self.grants.append(grant)
        return self.result


class FailingAuthorizedSecretResolver:
    def resolve(self, grant: SecretResolutionGrant) -> SecretResolution:
        raise RuntimeError(API_TOKEN)


class FakeCloudflareTransport:
    def __init__(
        self,
        *,
        existing_dns_record_id: str | None = None,
        status_code: int = 200,
        fault_stages: set[str] | None = None,
        raise_stages: set[str] | None = None,
    ) -> None:
        self.requests: list[RecordedRequest] = []
        self.existing_dns_record_id = existing_dns_record_id
        self.status_code = status_code
        self.fault_stages = set() if fault_stages is None else set(fault_stages)
        self.raise_stages = set() if raise_stages is None else set(raise_stages)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> CloudflareHttpResponse:
        path = url.removeprefix("https://api.cloudflare.com/client/v4")
        stage = _cloudflare_request_stage(method, path)
        self.requests.append(
            RecordedRequest(method, path, stage, dict(headers), json, params)
        )
        if stage in self.raise_stages:
            raise RuntimeError(API_TOKEN)
        if self.status_code != 200:
            return CloudflareHttpResponse(self.status_code, {"success": False})
        if stage in self.fault_stages:
            return CloudflareHttpResponse(503, {"success": False})
        if method == "POST" and path == "/accounts/account-001/cfd_tunnel":
            return CloudflareHttpResponse(
                200,
                {"success": True, "result": {"id": "tunnel-001"}},
            )
        if method == "GET" and path == "/zones/zone-001/dns_records":
            result: list[object] = []
            if self.existing_dns_record_id is not None:
                result.append({"id": self.existing_dns_record_id})
            return CloudflareHttpResponse(200, {"success": True, "result": result})
        if method in {"POST", "PATCH"} and path.startswith("/zones/zone-001/dns_records"):
            return CloudflareHttpResponse(
                200,
                {"success": True, "result": {"id": "dns-001"}},
            )
        if method == "GET" and path.endswith("/token"):
            return CloudflareHttpResponse(200, {"success": True, "result": TUNNEL_TOKEN})
        if method == "GET" and "/cfd_tunnel/" in path:
            return CloudflareHttpResponse(
                200,
                {"success": True, "result": {"id": "tunnel-001", "status": "healthy"}},
            )
        return CloudflareHttpResponse(200, {"success": True, "result": {}})


def _authority() -> CloudflareZoneAuthority:
    return CloudflareZoneAuthority(
        account_id="account-001",
        zone_id="zone-001",
        zone_name="openj92.dev",
        api_token_ref=SecretReference("secret://local/cf/api-token"),
        allowed_hostname_pattern="cpk-gateway-*.openj92.dev",
    )


def _owned_resources() -> CloudflareOwnedIngressResources:
    return CloudflareOwnedIngressResources(
        tunnel_id="tunnel-001",
        dns_record_id="dns-001",
        tunnel_name="cpk-gateway-001",
        hostname="cpk-gateway-001.openj92.dev",
    )


def _cloudflare_request_stage(method: str, path: str) -> str:
    if method == "POST" and path == "/accounts/account-001/cfd_tunnel":
        return "tunnel-allocation"
    if method == "PUT" and path.endswith("/configurations"):
        return "tunnel-configuration"
    if method == "GET" and path == "/zones/zone-001/dns_records":
        return "dns-lookup"
    if method == "POST" and path == "/zones/zone-001/dns_records":
        return "dns-create"
    if method == "PATCH" and "/dns_records/" in path:
        return "dns-update"
    if method == "GET" and path.endswith("/token"):
        return "tunnel-token"
    if method == "DELETE" and "/dns_records/" in path:
        return "dns-delete"
    if method == "DELETE" and "/cfd_tunnel/" in path:
        return "tunnel-delete"
    return "tunnel-observe"


def _ingress() -> NamedPublicIngress:
    return NamedPublicIngress(
        ingress_id="gateway-001",
        authority_ref=IngressAuthorityReference("openj92-ingress"),
        target=PublicIngressTarget("gateway", "control"),
        connector_node_id="cloudflared-gateway-001",
        hostname="cpk-gateway-001.openj92.dev",
        readiness_check_id="ready",
    )


def _authorized_resolver(
    result: SecretResolution | None = None,
) -> RecordingAuthorizedSecretResolver:
    return RecordingAuthorizedSecretResolver(
        SecretResolved(_authority().api_token_ref, SecretValue(API_TOKEN))
        if result is None
        else result
    )


def _resolution_grant(
    *,
    reference: SecretReference | None = None,
    intent: SecretUseIntent = SecretUseIntent.CLOUDFLARE_API_TOKEN,
) -> SecretResolutionGrant:
    return SecretResolutionGrant(
        authorization_id="suse_" + "e" * 64,
        workspace_id="workspace-a",
        reference_registration_id="sref_" + "f" * 64,
        provider_registration_id="sprov_" + "b" * 64,
        endpoint_reference=SecretProviderEndpointReference("workspace-secrets"),
        credential_reference=SecretReference("secret://bootstrap/provider-token"),
        reference=_authority().api_token_ref if reference is None else reference,
        intent=intent,
        actor_subject="worker-a",
        correlation_id="secret-resolution-" + "1" * 64,
        intent_fingerprint="2" * 64,
        run_id="run-a",
        activity_id="allocate-gateway",
        effect_id="event-001",
    )


def _custody_grant() -> SecretCustodyGrant:
    return SecretCustodyGrant(
        custody_id="scust_" + "a" * 64,
        workspace_id="workspace-a",
        provider_registration_id="sprov_" + "b" * 64,
        endpoint_reference=SecretProviderEndpointReference("workspace-secrets"),
        credential_reference=SecretReference(
            "secret://bootstrap/provider-token"
        ),
        reference=SecretReference(
            "secret://generated/ingress/cloudflared-tunnel-token/token-001"
        ),
        intent=SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
        actor_subject="worker-a",
        correlation_id="secret-custody-" + "c" * 64,
        custody_fingerprint="d" * 64,
        run_id="run-a",
        activity_id="allocate-gateway",
        effect_id="event-001",
    )


if __name__ == "__main__":
    unittest.main()
