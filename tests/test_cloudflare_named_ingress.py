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
    LocalDevelopmentSecretResolver,
    SecretProviderAuthority,
    SecretProviderId,
    SecretReference,
    SecretResolutionCode,
    SecretResolutionError,
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
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            secret_resolver=_resolver(),
        )

        allocation = interpreter.create(
            _ingress(),
            authority=_authority(),
            origin_service_url="http://gateway:8000",
        )

        self.assertEqual(allocation.tunnel_id, "tunnel-001")
        self.assertEqual(allocation.dns_record_id, "dns-001")
        self.assertEqual(allocation.hostname, "cpk-gateway-001.openj92.dev")
        self.assertEqual(allocation.endpoint_url, "https://cpk-gateway-001.openj92.dev")
        self.assertEqual(allocation.tunnel_token.reveal(), TUNNEL_TOKEN)
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
            {"name": "cpk-gateway-001", "config_src": "cloudflare"},
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

    def test_existing_dns_record_is_patched_instead_of_recreated(self) -> None:
        transport = FakeCloudflareTransport(existing_dns_record_id="dns-existing")
        client = CloudflareApiClient(
            _authority(),
            api_token=_resolver().resolve(SecretReference("secret://local/cf/api-token")).value,
            transport=transport,
        )

        record_id = client.upsert_dns_cname(
            hostname="cpk-gateway-001.openj92.dev",
            tunnel_id="tunnel-001",
        )

        self.assertEqual(record_id, "dns-existing")
        self.assertEqual(
            [(request.method, request.path) for request in transport.requests],
            [
                ("GET", "/zones/zone-001/dns_records"),
                ("PATCH", "/zones/zone-001/dns_records/dns-existing"),
            ],
        )

    def test_missing_secret_resolver_fails_before_api_mutation(self) -> None:
        transport = FakeCloudflareTransport()
        interpreter = CloudflareNamedIngressInterpreter(transport=transport)

        with self.assertRaises(SecretResolutionError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                origin_service_url="http://gateway:8000",
            )

        self.assertIs(raised.exception.code, SecretResolutionCode.MISSING)
        self.assertEqual(transport.requests, [])
        self.assertNotIn(API_TOKEN, repr(raised.exception))

    def test_hostname_policy_fails_closed_before_api_mutation(self) -> None:
        transport = FakeCloudflareTransport()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            secret_resolver=_resolver(),
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.create(
                NamedPublicIngress(
                    ingress_id="gateway-001",
                    authority_ref=IngressAuthorityReference("openj92-ingress"),
                    target=PublicIngressTarget("gateway", "control"),
                    hostname="gateway-001.cpk.openj92.dev",
                ),
                authority=_authority(),
                origin_service_url="http://gateway:8000",
            )

        self.assertIn("hostname", str(raised.exception))
        self.assertEqual(transport.requests, [])

    def test_teardown_deletes_only_recorded_owned_resources(self) -> None:
        transport = FakeCloudflareTransport()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            secret_resolver=_resolver(),
        )

        interpreter.teardown(
            authority=_authority(),
            resources=CloudflareOwnedIngressResources(
                tunnel_id="tunnel-001",
                dns_record_id="dns-001",
                tunnel_name="cpk-gateway-001",
                hostname="cpk-gateway-001.openj92.dev",
            ),
        )

        self.assertEqual(
            [(request.method, request.path) for request in transport.requests],
            [
                ("DELETE", "/zones/zone-001/dns_records/dns-001"),
                ("DELETE", "/accounts/account-001/cfd_tunnel/tunnel-001"),
            ],
        )

    def test_api_errors_are_bounded_and_redacted(self) -> None:
        transport = FakeCloudflareTransport(status_code=403)
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            secret_resolver=_resolver(),
        )

        with self.assertRaises(CloudflareApiError) as raised:
            interpreter.create(
                _ingress(),
                authority=_authority(),
                origin_service_url="http://gateway:8000",
            )

        text = repr(raised.exception)
        self.assertIn("403", text)
        self.assertNotIn(API_TOKEN, text)
        self.assertNotIn(TUNNEL_TOKEN, text)


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    json: Mapping[str, object] | None
    params: Mapping[str, str] | None


class FakeCloudflareTransport:
    def __init__(
        self,
        *,
        existing_dns_record_id: str | None = None,
        status_code: int = 200,
    ) -> None:
        self.requests: list[RecordedRequest] = []
        self.existing_dns_record_id = existing_dns_record_id
        self.status_code = status_code

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
        self.requests.append(RecordedRequest(method, path, dict(headers), json, params))
        if self.status_code != 200:
            return CloudflareHttpResponse(self.status_code, {"success": False})
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


def _ingress() -> NamedPublicIngress:
    return NamedPublicIngress(
        ingress_id="gateway-001",
        authority_ref=IngressAuthorityReference("openj92-ingress"),
        target=PublicIngressTarget("gateway", "control"),
        hostname="cpk-gateway-001.openj92.dev",
    )


def _resolver() -> LocalDevelopmentSecretResolver:
    return LocalDevelopmentSecretResolver(
        SecretProviderAuthority(SecretProviderId("local")),
        {"secret://local/cf/api-token": API_TOKEN},
    )


if __name__ == "__main__":
    unittest.main()
