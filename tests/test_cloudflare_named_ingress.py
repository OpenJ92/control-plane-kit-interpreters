from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from typing import Mapping
import unittest

import control_plane_kit_interpreters.cloudflare as cloudflare_public

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
RAW_PROVIDER_BODY = "raw-provider-response-body"
RAW_PROVIDER_EXCEPTION = "raw-provider-exception-payload"
RAW_PROVIDER_STATUS = "provider-status-text"
RAW_PROVIDER_URL = "https://api.cloudflare.com/client/v4/raw-provider-url"


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
                ("GET", "/zones/zone-001/dns_records"),
                ("POST", "/accounts/account-001/cfd_tunnel"),
                ("PUT", "/accounts/account-001/cfd_tunnel/tunnel-001/configurations"),
                ("GET", "/zones/zone-001/dns_records"),
                ("POST", "/zones/zone-001/dns_records"),
                ("GET", "/accounts/account-001/cfd_tunnel/tunnel-001/token"),
            ],
        )
        tunnel_create = transport.requests[1]
        self.assertEqual(
            tunnel_create.json,
            {
                "name": "cpk-gateway-001-c0303ba7369e",
                "config_src": "cloudflare",
            },
        )
        tunnel_config = transport.requests[2]
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
        dns_create = transport.requests[4]
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

        self.assertEqual(
            [
                request.params
                for request in transport.requests
                if request.stage
                in {"dns-pre-observation", "dns-pre-mutation-observation"}
            ],
            [
                {"name": "cpk-gateway-001.openj92.dev"},
                {"name": "cpk-gateway-001.openj92.dev"},
            ],
        )

    def test_provider_failure_contract_is_public_closed_and_compatible(self) -> None:
        names = (
            "CloudflareProviderOperationError",
            "CloudflareProviderFailureEvidence",
            "CloudflareProviderFailureStage",
            "CloudflareProviderFailureCategory",
            "CloudflareProviderMutationCertainty",
            "CloudflareProviderCleanupResult",
        )
        self.assertEqual(
            tuple(
                name
                for name in names
                if name not in cloudflare_public.__all__
                or getattr(cloudflare_public, name, None) is None
            ),
            (),
        )

        error_type = cloudflare_public.CloudflareProviderOperationError
        evidence_type = cloudflare_public.CloudflareProviderFailureEvidence
        self.assertTrue(issubclass(error_type, CloudflareApiError))
        self.assertTrue(is_dataclass(evidence_type))
        self.assertTrue(evidence_type.__dataclass_params__.frozen)
        self.assertEqual(
            tuple(field.name for field in fields(evidence_type)),
            (
                "stage",
                "category",
                "mutation_certainty",
                "tunnel_id",
                "dns_record_id",
                "cleanup_result",
            ),
        )
        required_values = {
            "CloudflareProviderFailureStage": {
                "dns-pre-observation",
                "tunnel-allocation",
                "tunnel-configuration",
                "dns-pre-mutation-observation",
                "dns-create",
                "dns-reconciliation",
                "tunnel-token",
                "secret-custody",
                "cleanup",
            },
            "CloudflareProviderFailureCategory": {
                "hostname-occupied",
                "dns-conflict",
                "malformed-response",
                "provider-status",
                "transport",
                "secret-custody",
                "cleanup",
            },
            "CloudflareProviderMutationCertainty": {
                "none",
                "tunnel-created",
                "dns-and-tunnel-created",
                "uncertain",
            },
            "CloudflareProviderCleanupResult": {
                "not-required",
                "complete",
                "withheld",
                "uncertain",
            },
        }
        for name, values in required_values.items():
            enum_type = getattr(cloudflare_public, name)
            self.assertTrue(issubclass(enum_type, Enum))
            self.assertEqual({member.value for member in enum_type}, values)

    def test_tunnel_allocation_without_receipt_is_uncertain_and_withheld(
        self,
    ) -> None:
        cases = (
            (
                "transport",
                FakeCloudflareTransport(raise_stages={"tunnel-allocation"}),
                "transport",
            ),
            (
                "provider-status",
                FakeCloudflareTransport(fault_stages={"tunnel-allocation"}),
                "provider-status",
            ),
            (
                "missing-id",
                FakeCloudflareTransport(missing_tunnel_id=True),
                "malformed-response",
            ),
        )
        for case, transport, category in cases:
            with self.subTest(case=case):
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
                    [request.stage for request in transport.requests],
                    ["dns-pre-observation", "tunnel-allocation"],
                )
                self.assertFalse(
                    any(
                        request.method == "DELETE"
                        for request in transport.requests
                    )
                )
                _assert_failure_evidence(
                    self,
                    raised.exception,
                    stage="tunnel-allocation",
                    category=category,
                    mutation_certainty="uncertain",
                    tunnel_id=None,
                    dns_record_id=None,
                    cleanup_result="withheld",
                )

    def test_unexpected_response_mapping_exceptions_preserve_identity(self) -> None:
        cases = (
            (
                "initial-observation",
                "dns-pre-observation",
                ["dns-pre-observation"],
            ),
            (
                "configuration-after-receipt",
                "tunnel-configuration",
                [
                    "dns-pre-observation",
                    "tunnel-allocation",
                    "tunnel-configuration",
                    "tunnel-delete",
                ],
            ),
        )
        for case, stage, expected_stages in cases:
            with self.subTest(case=case):
                sentinel = SentinelProviderException(
                    f"{RAW_PROVIDER_EXCEPTION}-{case}"
                )
                transport = FakeCloudflareTransport(
                    response_get_errors={stage: sentinel},
                )
                interpreter = CloudflareNamedIngressInterpreter(
                    transport=transport,
                    authorized_secret_resolver=_authorized_resolver(),
                    secret_custodian=RecordingSecretCustodian(),
                )

                try:
                    interpreter.create(
                        _ingress(),
                        authority=_authority(),
                        allocation_name="cpk-gateway-001-c0303ba7369e",
                        origin_service_url="http://gateway:8000",
                        secret_resolution_grant=_resolution_grant(),
                        secret_custody_grant=_custody_grant(),
                    )
                except Exception as error:
                    self.assertIs(error, sentinel)
                else:
                    self.fail("unexpected response exception was suppressed")
                self.assertEqual(
                    [request.stage for request in transport.requests],
                    expected_stages,
                )

    def test_unexpected_exception_cleanup_failure_keeps_cleanup_precedence(
        self,
    ) -> None:
        sentinel = SentinelProviderException(RAW_PROVIDER_EXCEPTION)
        transport = FakeCloudflareTransport(
            response_get_errors={"tunnel-configuration": sentinel},
            fault_stages={"tunnel-delete"},
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

        self.assertIsNot(raised.exception, sentinel)
        self.assertEqual(
            str(raised.exception),
            "Cloudflare exact cleanup is uncertain: tunnel",
        )
        self.assertNotIn(RAW_PROVIDER_EXCEPTION, repr(raised.exception))
        self.assertEqual(
            [request.stage for request in transport.requests],
            [
                "dns-pre-observation",
                "tunnel-allocation",
                "tunnel-configuration",
                "tunnel-delete",
            ],
        )

    def test_direct_dns_create_remains_name_checked_and_api_error_compatible(
        self,
    ) -> None:
        success_transport = FakeCloudflareTransport(dns_lookup_results=[[]])
        client = CloudflareApiClient(
            _authority(),
            api_token=SecretValue(API_TOKEN),
            transport=success_transport,
        )

        self.assertEqual(
            client.create_dns_cname(
                hostname=_ingress().hostname,
                tunnel_id="tunnel-001",
            ),
            "dns-001",
        )
        self.assertEqual(
            [
                (request.method, request.stage, request.params)
                for request in success_transport.requests
            ],
            [
                (
                    "GET",
                    "dns-pre-observation",
                    {"name": "cpk-gateway-001.openj92.dev"},
                ),
                ("POST", "dns-create", None),
            ],
        )

        cases = (
            (
                "other-record-type",
                FakeCloudflareTransport(
                    dns_lookup_results=[
                        [_dns_record("dns-existing", "A", "192.0.2.10")]
                    ],
                ),
            ),
            (
                "malformed-top-level",
                FakeCloudflareTransport(
                    malformed_result_stages={"dns-pre-observation"},
                ),
            ),
        )
        for case, transport in cases:
            with self.subTest(case=case):
                client = CloudflareApiClient(
                    _authority(),
                    api_token=SecretValue(API_TOKEN),
                    transport=transport,
                )
                with self.assertRaises(CloudflareApiError):
                    client.create_dns_cname(
                        hostname=_ingress().hostname,
                        tunnel_id="tunnel-001",
                    )
                self.assertEqual(
                    [request.stage for request in transport.requests],
                    ["dns-pre-observation"],
                )

    def test_exact_hostname_occupants_are_preobserved_before_tunnel_creation(
        self,
    ) -> None:
        cases = (
            (
                "cname",
                [_dns_record("dns-existing", "CNAME", "foreign.cfargotunnel.com")],
                "hostname-occupied",
                "dns-existing",
            ),
            (
                "address",
                [_dns_record("dns-existing", "A", "192.0.2.10")],
                "hostname-occupied",
                "dns-existing",
            ),
            (
                "malformed",
                [{"id": "dns-existing", "name": _ingress().hostname}],
                "malformed-response",
                None,
            ),
        )
        for case, records, category, dns_record_id in cases:
            with self.subTest(case=case):
                transport = FakeCloudflareTransport(
                    dns_lookup_results=[records],
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
                    [
                        (request.method, request.path, request.stage)
                        for request in transport.requests
                    ],
                    [
                        (
                            "GET",
                            "/zones/zone-001/dns_records",
                            "dns-pre-observation",
                        ),
                    ],
                )
                self.assertEqual(
                    transport.requests[0].params,
                    {"name": "cpk-gateway-001.openj92.dev"},
                )
                _assert_failure_evidence(
                    self,
                    raised.exception,
                    stage="dns-pre-observation",
                    category=category,
                    mutation_certainty="none",
                    tunnel_id=None,
                    dns_record_id=dns_record_id,
                    cleanup_result="not-required",
                )

    def test_dns_is_reobserved_immediately_before_mutation_and_races_are_bounded(
        self,
    ) -> None:
        cases = (
            (
                "foreign-target",
                [_dns_cname("dns-race", "foreign-tunnel")],
                ["tunnel-delete"],
                "hostname-occupied",
                "tunnel-created",
                "dns-race",
                "complete",
            ),
            (
                "new-tunnel-target",
                [_dns_cname("dns-race", "tunnel-001")],
                [],
                "dns-conflict",
                "uncertain",
                "dns-race",
                "withheld",
            ),
            (
                "duplicate-records",
                [
                    _dns_cname("dns-race-a", "foreign-tunnel"),
                    _dns_cname("dns-race-b", "tunnel-001"),
                ],
                [],
                "dns-conflict",
                "uncertain",
                None,
                "withheld",
            ),
            (
                "malformed-record",
                [{"id": "dns-race"}],
                [],
                "malformed-response",
                "uncertain",
                None,
                "withheld",
            ),
        )
        for (
            case,
            observed_rows,
            expected_cleanup,
            category,
            mutation_certainty,
            dns_record_id,
            cleanup_result,
        ) in cases:
            with self.subTest(case=case):
                transport = FakeCloudflareTransport(
                    dns_lookup_results=[[], observed_rows],
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
                    [request.stage for request in transport.requests],
                    [
                        "dns-pre-observation",
                        "tunnel-allocation",
                        "tunnel-configuration",
                        "dns-pre-mutation-observation",
                        *expected_cleanup,
                    ],
                )
                self.assertNotIn(
                    "dns-create",
                    [request.stage for request in transport.requests],
                )
                _assert_failure_evidence(
                    self,
                    raised.exception,
                    stage="dns-pre-mutation-observation",
                    category=category,
                    mutation_certainty=mutation_certainty,
                    tunnel_id="tunnel-001",
                    dns_record_id=dns_record_id,
                    cleanup_result=cleanup_result,
                )

    def test_ambiguous_dns_create_adopts_one_complete_exact_record(self) -> None:
        reconciled_record = _dns_cname("dns-race", "tunnel-001")
        reconciled_record.update(
            {
                "comment": RAW_PROVIDER_BODY,
                "meta": {"token": API_TOKEN, "endpoint": RAW_PROVIDER_URL},
            }
        )
        transport = FakeCloudflareTransport(
            dns_lookup_pages=[
                _dns_page([]),
                _dns_page([]),
                _dns_page(
                    [reconciled_record],
                    total_count=47,
                    total_pages=24,
                ),
            ],
            raise_stages={"dns-create"},
        )
        custodian = RecordingSecretCustodian()
        interpreter = CloudflareNamedIngressInterpreter(
            transport=transport,
            authorized_secret_resolver=_authorized_resolver(),
            secret_custodian=custodian,
        )

        allocation = None
        failure = None
        try:
            allocation = interpreter.create(
                _ingress(),
                authority=_authority(),
                allocation_name="cpk-gateway-001-c0303ba7369e",
                origin_service_url="http://gateway:8000",
                secret_resolution_grant=_resolution_grant(),
                secret_custody_grant=_custody_grant(),
            )
        except CloudflareApiError as error:
            failure = error

        self.assertIsNotNone(
            allocation,
            f"one exact reconciled record was not admitted: {failure!r}",
        )
        assert allocation is not None
        self.assertEqual(allocation.tunnel_id, "tunnel-001")
        self.assertEqual(allocation.dns_record_id, "dns-race")
        self.assertTrue(allocation.secret_custody_receipt.matches(_custody_grant()))
        self.assertEqual(custodian.stored_references, [_custody_grant().reference])
        self.assertEqual(
            [request.stage for request in transport.requests],
            [
                "dns-pre-observation",
                "tunnel-allocation",
                "tunnel-configuration",
                "dns-pre-mutation-observation",
                "dns-create",
                "dns-reconciliation",
                "tunnel-token",
            ],
        )
        self.assertEqual(
            [
                request
                for request in transport.requests
                if request.method == "POST"
                and request.path == "/zones/zone-001/dns_records"
            ],
            [transport.requests[4]],
        )
        self.assertEqual(
            [
                request.params
                for request in transport.requests
                if request.stage == "dns-reconciliation"
            ],
            [
                {
                    "name": "cpk-gateway-001.openj92.dev",
                    "page": "1",
                    "per_page": "2",
                }
            ],
        )
        for forbidden in (API_TOKEN, RAW_PROVIDER_BODY, RAW_PROVIDER_URL):
            self.assertNotIn(forbidden, repr(allocation))

        interpreter.teardown(
            authority=_authority(),
            resources=CloudflareOwnedIngressResources(
                tunnel_id=allocation.tunnel_id,
                tunnel_name=allocation.tunnel_name,
                dns_record_id=allocation.dns_record_id,
                hostname=allocation.hostname,
            ),
            secret_resolution_grant=_resolution_grant(),
            secret_custody_grant=_custody_grant(),
        )

        self.assertEqual(
            [
                request.path
                for request in transport.requests
                if request.method == "DELETE"
            ],
            [
                "/zones/zone-001/dns_records/dns-race",
                "/accounts/account-001/cfd_tunnel/tunnel-001/connections",
                "/accounts/account-001/cfd_tunnel/tunnel-001",
            ],
        )

    def test_ambiguous_dns_create_cleanup_uses_only_closed_truth(self) -> None:
        cases = (
            (
                "absent",
                [],
                ["tunnel-delete"],
                None,
                "complete",
                False,
            ),
            (
                "foreign-target",
                [_dns_cname("dns-race", "foreign-tunnel")],
                ["tunnel-delete"],
                "dns-race",
                "complete",
                False,
            ),
            (
                "foreign-content",
                [_dns_record("dns-race", "CNAME", "elsewhere.example")],
                ["tunnel-delete"],
                "dns-race",
                "complete",
                False,
            ),
            (
                "duplicate-records",
                [
                    _dns_cname("dns-race-a", "foreign-tunnel"),
                    _dns_cname("dns-race-b", "tunnel-001"),
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "duplicate-all-foreign-records",
                [
                    _dns_cname("dns-race-a", "foreign-tunnel-a"),
                    _dns_cname("dns-race-b", "foreign-tunnel-b"),
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "malformed-record",
                [
                    {
                        "id": "dns-race",
                        "token": API_TOKEN,
                        "endpoint": RAW_PROVIDER_URL,
                    }
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "missing-id-may-target-fresh-tunnel",
                [
                    {
                        **_dns_cname("dns-race", "tunnel-001"),
                        "id": None,
                    }
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "empty-id-may-target-fresh-tunnel",
                [
                    {
                        **_dns_cname("dns-race", "tunnel-001"),
                        "id": "",
                    }
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "non-string-id-may-target-fresh-tunnel",
                [
                    {
                        **_dns_cname("dns-race", "tunnel-001"),
                        "id": 7,
                    }
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "overlong-id-may-target-fresh-tunnel",
                [
                    {
                        **_dns_cname("dns-race", "tunnel-001"),
                        "id": "a" * 129,
                    }
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "invalid-id-may-target-fresh-tunnel",
                [
                    {
                        **_dns_cname("dns-race", "tunnel-001"),
                        "id": "dns/race",
                    }
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "wrong-name-may-target-fresh-tunnel",
                [
                    {
                        **_dns_cname("dns-race", "tunnel-001"),
                        "name": "other.openj92.dev",
                    }
                ],
                [],
                None,
                "withheld",
                False,
            ),
            (
                "wrong-type-may-target-fresh-tunnel",
                [
                    _dns_record(
                        "dns-race",
                        "A",
                        "tunnel-001.cfargotunnel.com",
                    )
                ],
                [],
                "dns-race",
                "withheld",
                False,
            ),
            (
                "wrong-proxy-may-target-fresh-tunnel",
                [
                    {
                        **_dns_cname("dns-race", "tunnel-001"),
                        "proxied": False,
                    }
                ],
                [],
                "dns-race",
                "withheld",
                False,
            ),
            (
                "missing-proxy-may-target-fresh-tunnel",
                [
                    {
                        key: value
                        for key, value in _dns_cname(
                            "dns-race",
                            "tunnel-001",
                        ).items()
                        if key != "proxied"
                    }
                ],
                [],
                "dns-race",
                "withheld",
                False,
            ),
            (
                "non-bool-proxy-may-target-fresh-tunnel",
                [
                    {
                        **_dns_cname("dns-race", "tunnel-001"),
                        "proxied": 1,
                    }
                ],
                [],
                "dns-race",
                "withheld",
                False,
            ),
            (
                "provider-status-absent",
                [],
                ["tunnel-delete"],
                None,
                "complete",
                True,
            ),
        )
        for (
            case,
            reconciled_rows,
            expected_cleanup,
            dns_record_id,
            cleanup_result,
            provider_status,
        ) in cases:
            with self.subTest(case=case):
                transport = FakeCloudflareTransport(
                    dns_lookup_pages=[
                        _dns_page([]),
                        _dns_page([]),
                        _dns_page(reconciled_rows),
                    ],
                    fault_stages={"dns-create"} if provider_status else None,
                    raise_stages=None if provider_status else {"dns-create"},
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
                    [request.stage for request in transport.requests],
                    [
                        "dns-pre-observation",
                        "tunnel-allocation",
                        "tunnel-configuration",
                        "dns-pre-mutation-observation",
                        "dns-create",
                        "dns-reconciliation",
                        *expected_cleanup,
                    ],
                )
                self.assertFalse(
                    any(request.stage == "dns-delete" for request in transport.requests)
                )
                _assert_failure_evidence(
                    self,
                    raised.exception,
                    stage="dns-create",
                    category="provider-status" if provider_status else "transport",
                    mutation_certainty="uncertain",
                    tunnel_id="tunnel-001",
                    dns_record_id=dns_record_id,
                    cleanup_result=cleanup_result,
                )

    def test_ambiguous_dns_create_requires_one_complete_first_page(self) -> None:
        exact_record = _dns_cname("dns-race", "tunnel-001")
        cases = (
            (
                "missing-result-info",
                _hostile_dns_envelope(
                    {"success": True, "result": [exact_record]}
                ),
                "dns-race",
            ),
            (
                "missing-page",
                _hostile_dns_envelope(
                    _dns_page_without_result_info_field([exact_record], "page")
                ),
                "dns-race",
            ),
            (
                "missing-page-size",
                _hostile_dns_envelope(
                    _dns_page_without_result_info_field(
                        [exact_record],
                        "per_page",
                    )
                ),
                "dns-race",
            ),
            (
                "missing-count",
                _hostile_dns_envelope(
                    _dns_page_without_result_info_field([exact_record], "count")
                ),
                "dns-race",
            ),
            (
                "not-first-page",
                _hostile_dns_envelope(_dns_page([exact_record], page=2)),
                "dns-race",
            ),
            (
                "wrong-page-size",
                _hostile_dns_envelope(_dns_page([exact_record], per_page=3)),
                "dns-race",
            ),
            (
                "non-integer-page-size",
                _hostile_dns_envelope(_dns_page([exact_record], per_page=2.0)),
                "dns-race",
            ),
            (
                "count-mismatch",
                _hostile_dns_envelope(_dns_page([exact_record], count=0)),
                "dns-race",
            ),
            (
                "bool-page-field",
                _hostile_dns_envelope(_dns_page([exact_record], page=True)),
                "dns-race",
            ),
            (
                "bool-count-field",
                _hostile_dns_envelope(_dns_page([exact_record], count=True)),
                "dns-race",
            ),
            (
                "malformed-count-field",
                _hostile_dns_envelope(_dns_page([exact_record], count="1")),
                "dns-race",
            ),
            (
                "malformed-result-info",
                _hostile_dns_envelope(
                    {
                        "success": True,
                        "result": [exact_record],
                        "result_info": [RAW_PROVIDER_BODY],
                    }
                ),
                "dns-race",
            ),
            (
                "more-than-two-records",
                _hostile_dns_envelope(
                    _dns_page(
                        [
                            exact_record,
                            _dns_cname("dns-race-b", "foreign-tunnel"),
                            _dns_cname("dns-race-c", "foreign-tunnel"),
                        ]
                    )
                ),
                None,
            ),
        )
        for case, reconciliation_page, expected_dns_record_id in cases:
            with self.subTest(case=case):
                transport = FakeCloudflareTransport(
                    dns_lookup_pages=[
                        _dns_page([]),
                        _dns_page([]),
                        reconciliation_page,
                    ],
                    raise_stages={"dns-create"},
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

                stages = [request.stage for request in transport.requests]
                self.assertEqual(stages.count("dns-create"), 1)
                self.assertEqual(stages.count("dns-reconciliation"), 1)
                self.assertFalse(any(stage.endswith("delete") for stage in stages))
                _assert_failure_evidence(
                    self,
                    raised.exception,
                    stage="dns-create",
                    category="transport",
                    mutation_certainty="uncertain",
                    tunnel_id="tunnel-001",
                    dns_record_id=expected_dns_record_id,
                    cleanup_result="withheld",
                )

    def test_unexpected_dns_create_response_reconciles_once_and_preserves_identity(
        self,
    ) -> None:
        cases = (
            (
                "absent",
                [],
                ["tunnel-delete"],
            ),
            (
                "new-tunnel-target",
                [_dns_cname("dns-race", "tunnel-001")],
                [],
            ),
        )
        for case, reconciled_rows, expected_cleanup in cases:
            with self.subTest(case=case):
                sentinel = SentinelProviderException(
                    f"{RAW_PROVIDER_EXCEPTION}-{case}"
                )
                transport = FakeCloudflareTransport(
                    dns_lookup_pages=[
                        _dns_page([]),
                        _dns_page([]),
                        _dns_page(reconciled_rows),
                    ],
                    response_get_errors={"dns-create": sentinel},
                )
                interpreter = CloudflareNamedIngressInterpreter(
                    transport=transport,
                    authorized_secret_resolver=_authorized_resolver(),
                    secret_custodian=RecordingSecretCustodian(),
                )

                try:
                    interpreter.create(
                        _ingress(),
                        authority=_authority(),
                        allocation_name="cpk-gateway-001-c0303ba7369e",
                        origin_service_url="http://gateway:8000",
                        secret_resolution_grant=_resolution_grant(),
                        secret_custody_grant=_custody_grant(),
                    )
                except Exception as error:
                    self.assertIs(error, sentinel)
                else:
                    self.fail("unexpected DNS-create exception was suppressed")

                stages = [request.stage for request in transport.requests]
                self.assertEqual(
                    stages,
                    [
                        "dns-pre-observation",
                        "tunnel-allocation",
                        "tunnel-configuration",
                        "dns-pre-mutation-observation",
                        "dns-create",
                        "dns-reconciliation",
                        *expected_cleanup,
                    ],
                )
                self.assertEqual(stages.count("dns-reconciliation"), 1)

    def test_unexpected_dns_create_cleanup_failure_keeps_precedence(self) -> None:
        sentinel = SentinelProviderException(RAW_PROVIDER_EXCEPTION)
        transport = FakeCloudflareTransport(
            dns_lookup_pages=[_dns_page([]), _dns_page([]), _dns_page([])],
            response_get_errors={"dns-create": sentinel},
            fault_stages={"tunnel-delete"},
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

        self.assertIsNot(raised.exception, sentinel)
        self.assertEqual(
            str(raised.exception),
            "Cloudflare exact cleanup is uncertain: tunnel",
        )
        self.assertNotIn(RAW_PROVIDER_EXCEPTION, repr(raised.exception))
        stages = [request.stage for request in transport.requests]
        self.assertEqual(
            stages,
            [
                "dns-pre-observation",
                "tunnel-allocation",
                "tunnel-configuration",
                "dns-pre-mutation-observation",
                "dns-create",
                "dns-reconciliation",
                "tunnel-delete",
            ],
        )
        self.assertEqual(stages.count("dns-reconciliation"), 1)

    def test_malformed_tunnel_token_is_typed_and_compensated(self) -> None:
        transport = FakeCloudflareTransport(
            malformed_result_stages={"tunnel-token"},
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
            [request.stage for request in transport.requests],
            [
                "dns-pre-observation",
                "tunnel-allocation",
                "tunnel-configuration",
                "dns-pre-mutation-observation",
                "dns-create",
                "tunnel-token",
                "dns-delete",
                "tunnel-delete",
            ],
        )
        _assert_failure_evidence(
            self,
            raised.exception,
            stage="tunnel-token",
            category="malformed-response",
            mutation_certainty="dns-and-tunnel-created",
            tunnel_id="tunnel-001",
            dns_record_id="dns-001",
            cleanup_result="complete",
        )

    def test_dns_reconciliation_failures_withhold_all_cleanup(self) -> None:
        cases = (
            (
                "transport",
                FakeCloudflareTransport(
                    dns_lookup_results=[[], []],
                    raise_stages={"dns-create", "dns-reconciliation"},
                ),
                "transport",
            ),
            (
                "provider-status",
                FakeCloudflareTransport(
                    dns_lookup_results=[[], []],
                    raise_stages={"dns-create"},
                    fault_stages={"dns-reconciliation"},
                ),
                "provider-status",
            ),
            (
                "malformed-top-level-result",
                FakeCloudflareTransport(
                    dns_lookup_results=[[], []],
                    raise_stages={"dns-create"},
                    malformed_result_stages={"dns-reconciliation"},
                ),
                "malformed-response",
            ),
        )
        for case, transport, category in cases:
            with self.subTest(case=case):
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
                    [request.stage for request in transport.requests],
                    [
                        "dns-pre-observation",
                        "tunnel-allocation",
                        "tunnel-configuration",
                        "dns-pre-mutation-observation",
                        "dns-create",
                        "dns-reconciliation",
                    ],
                )
                _assert_failure_evidence(
                    self,
                    raised.exception,
                    stage="dns-reconciliation",
                    category=category,
                    mutation_certainty="uncertain",
                    tunnel_id="tunnel-001",
                    dns_record_id=None,
                    cleanup_result="withheld",
                )

    def test_create_failures_expose_closed_typed_redacted_evidence(self) -> None:
        cases = (
            (
                "configure-transport",
                FakeCloudflareTransport(
                    raise_stages={"tunnel-configuration"},
                ),
                "tunnel-configuration",
                "transport",
                "uncertain",
                "tunnel-001",
                None,
                "complete",
            ),
            (
                "configure-status",
                FakeCloudflareTransport(
                    fault_stages={"tunnel-configuration"},
                ),
                "tunnel-configuration",
                "provider-status",
                "tunnel-created",
                "tunnel-001",
                None,
                "complete",
            ),
            (
                "dns-conflict",
                FakeCloudflareTransport(existing_dns_record_id="dns-existing"),
                "dns-pre-observation",
                "hostname-occupied",
                "none",
                None,
                "dns-existing",
                "not-required",
            ),
            (
                "configure-status-cleanup-failed",
                FakeCloudflareTransport(
                    fault_stages={"tunnel-configuration", "tunnel-delete"},
                ),
                "tunnel-configuration",
                "provider-status",
                "tunnel-created",
                "tunnel-001",
                None,
                "uncertain",
            ),
        )
        for (
            case,
            transport,
            stage,
            category,
            mutation_certainty,
            tunnel_id,
            dns_record_id,
            cleanup_result,
        ) in cases:
            with self.subTest(case=case):
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

                _assert_failure_evidence(
                    self,
                    raised.exception,
                    stage=stage,
                    category=category,
                    mutation_certainty=mutation_certainty,
                    tunnel_id=tunnel_id,
                    dns_record_id=dns_record_id,
                    cleanup_result=cleanup_result,
                )

    def test_create_fault_matrix_compensates_only_known_owned_stages(self) -> None:
        cases = (
            ("tunnel-allocation", []),
            ("tunnel-configuration", ["tunnel-delete"]),
            ("dns-pre-mutation-observation", ["tunnel-delete"]),
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
                (
                    "DELETE",
                    "/accounts/account-001/cfd_tunnel/tunnel-001/connections",
                ),
                ("DELETE", "/accounts/account-001/cfd_tunnel/tunnel-001"),
            ],
        )
        self.assertEqual(resolver.grants, [_resolution_grant()])

    def test_teardown_attempts_every_exact_stage_after_each_possible_failure(self) -> None:
        cases = (
            (True, set(), "custody"),
            (False, {"dns-delete"}, "dns"),
            (False, {"tunnel-connections-delete"}, "connections"),
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
                    [
                        "dns-delete",
                        "tunnel-connections-delete",
                        "tunnel-delete",
                    ],
                )

    def test_teardown_reports_all_failed_stages_without_secret_material(self) -> None:
        transport = FakeCloudflareTransport(
            fault_stages={
                "dns-delete",
                "tunnel-connections-delete",
                "tunnel-delete",
            },
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
            "Cloudflare exact cleanup is uncertain: custody,dns,connections,tunnel",
        )
        self.assertEqual(
            [request.stage for request in transport.requests],
            [
                "dns-delete",
                "tunnel-connections-delete",
                "tunnel-delete",
            ],
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


class SentinelProviderException(RuntimeError):
    pass


class RaisingResponseBody(dict[str, object]):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def get(self, key: str, default: object = None) -> object:
        raise self.error


class FakeCloudflareTransport:
    def __init__(
        self,
        *,
        existing_dns_record_id: str | None = None,
        status_code: int = 200,
        fault_stages: set[str] | None = None,
        raise_stages: set[str] | None = None,
        malformed_result_stages: set[str] | None = None,
        dns_lookup_results: list[list[object]] | None = None,
        dns_lookup_pages: list[Mapping[str, object]] | None = None,
        missing_tunnel_id: bool = False,
        response_get_errors: Mapping[str, BaseException] | None = None,
    ) -> None:
        if dns_lookup_results is not None and dns_lookup_pages is not None:
            raise ValueError("DNS lookup results and pages are mutually exclusive")
        self.requests: list[RecordedRequest] = []
        self.existing_dns_record_id = existing_dns_record_id
        self.status_code = status_code
        self.fault_stages = set() if fault_stages is None else set(fault_stages)
        self.raise_stages = set() if raise_stages is None else set(raise_stages)
        self.malformed_result_stages = (
            set()
            if malformed_result_stages is None
            else set(malformed_result_stages)
        )
        self.dns_lookup_results = (
            None
            if dns_lookup_results is None
            else [list(result) for result in dns_lookup_results]
        )
        self.dns_lookup_pages = (
            None
            if dns_lookup_pages is None
            else [dict(page) for page in dns_lookup_pages]
        )
        self.missing_tunnel_id = missing_tunnel_id
        self.response_get_errors = (
            {}
            if response_get_errors is None
            else dict(response_get_errors)
        )

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
        stage = _cloudflare_request_stage(method, path, self.requests)
        self.requests.append(
            RecordedRequest(method, path, stage, dict(headers), json, params)
        )
        if stage in self.raise_stages:
            raise RuntimeError(
                f"{RAW_PROVIDER_EXCEPTION} {RAW_PROVIDER_URL} {API_TOKEN}"
            )
        if stage in self.response_get_errors:
            return CloudflareHttpResponse(
                200,
                RaisingResponseBody(self.response_get_errors[stage]),
            )
        if self.status_code != 200:
            return CloudflareHttpResponse(self.status_code, {"success": False})
        if stage in self.fault_stages:
            return CloudflareHttpResponse(
                503,
                {
                    "success": False,
                    "errors": [RAW_PROVIDER_BODY, RAW_PROVIDER_STATUS],
                    "url": RAW_PROVIDER_URL,
                    "token": API_TOKEN,
                },
            )
        if stage in self.malformed_result_stages:
            return CloudflareHttpResponse(
                200,
                {"success": True, "result": {"malformed": True}},
            )
        if method == "POST" and path == "/accounts/account-001/cfd_tunnel":
            return CloudflareHttpResponse(
                200,
                {
                    "success": True,
                    "result": (
                        {"missing": "id"}
                        if self.missing_tunnel_id
                        else {"id": "tunnel-001"}
                    ),
                },
            )
        if method == "GET" and path == "/zones/zone-001/dns_records":
            if self.dns_lookup_pages is not None:
                body = (
                    self.dns_lookup_pages.pop(0)
                    if self.dns_lookup_pages
                    else _dns_page([])
                )
                return CloudflareHttpResponse(200, body)
            if self.dns_lookup_results is not None:
                result = (
                    self.dns_lookup_results.pop(0)
                    if self.dns_lookup_results
                    else []
                )
            elif self.existing_dns_record_id is not None:
                result = [
                    _dns_cname(self.existing_dns_record_id, "foreign-tunnel")
                ]
            else:
                result = []
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


def _cloudflare_request_stage(
    method: str,
    path: str,
    previous_requests: list[RecordedRequest],
) -> str:
    if method == "POST" and path == "/accounts/account-001/cfd_tunnel":
        return "tunnel-allocation"
    if method == "PUT" and path.endswith("/configurations"):
        return "tunnel-configuration"
    if method == "GET" and path == "/zones/zone-001/dns_records":
        if any(request.stage == "dns-create" for request in previous_requests):
            return "dns-reconciliation"
        if any(
            request.stage == "tunnel-allocation"
            for request in previous_requests
        ):
            return "dns-pre-mutation-observation"
        return "dns-pre-observation"
    if method == "POST" and path == "/zones/zone-001/dns_records":
        return "dns-create"
    if method == "PATCH" and "/dns_records/" in path:
        return "dns-update"
    if method == "GET" and path.endswith("/token"):
        return "tunnel-token"
    if method == "DELETE" and "/dns_records/" in path:
        return "dns-delete"
    if method == "DELETE" and path.endswith("/connections"):
        return "tunnel-connections-delete"
    if method == "DELETE" and "/cfd_tunnel/" in path:
        return "tunnel-delete"
    return "tunnel-observe"


def _dns_cname(record_id: str, tunnel_id: str) -> dict[str, object]:
    return _dns_record(
        record_id,
        "CNAME",
        f"{tunnel_id}.cfargotunnel.com",
    )


def _dns_record(
    record_id: str,
    record_type: str,
    content: str,
) -> dict[str, object]:
    return {
        "id": record_id,
        "type": record_type,
        "name": "cpk-gateway-001.openj92.dev",
        "content": content,
        "proxied": True,
    }


def _dns_page(
    records: list[object],
    *,
    page: object = 1,
    per_page: object = 2,
    count: object | None = None,
    total_count: object | None = None,
    total_pages: object = 1,
) -> dict[str, object]:
    return {
        "success": True,
        "result": list(records),
        "result_info": {
            "page": page,
            "per_page": per_page,
            "count": len(records) if count is None else count,
            "total_count": len(records) if total_count is None else total_count,
            "total_pages": total_pages,
        },
    }


def _hostile_dns_envelope(body: Mapping[str, object]) -> dict[str, object]:
    hostile = dict(body)
    hostile["token"] = API_TOKEN
    hostile["endpoint"] = RAW_PROVIDER_URL
    hostile["errors"] = [
        RAW_PROVIDER_BODY,
        RAW_PROVIDER_EXCEPTION,
        RAW_PROVIDER_STATUS,
    ]
    result_info = hostile.get("result_info")
    if isinstance(result_info, Mapping):
        result_info = dict(result_info)
        result_info["credential"] = TUNNEL_TOKEN
        hostile["result_info"] = result_info
    return hostile


def _dns_page_without_result_info_field(
    records: list[object],
    field_name: str,
) -> dict[str, object]:
    page = _dns_page(records)
    result_info = page["result_info"]
    assert isinstance(result_info, dict)
    result_info.pop(field_name)
    return page


def _assert_failure_evidence(
    case: unittest.TestCase,
    error: CloudflareApiError,
    *,
    stage: str,
    category: str,
    mutation_certainty: str,
    tunnel_id: str | None,
    dns_record_id: str | None,
    cleanup_result: str,
) -> None:
    error_type = getattr(
        cloudflare_public,
        "CloudflareProviderOperationError",
        None,
    )
    case.assertIsNotNone(error_type)
    case.assertIsInstance(error, error_type)
    evidence = getattr(error, "provider_failure", None)
    case.assertIsNotNone(evidence, "Cloudflare failure evidence is missing")
    case.assertTrue(is_dataclass(evidence))
    case.assertTrue(evidence.__dataclass_params__.frozen)
    case.assertEqual(
        tuple(field.name for field in fields(evidence)),
        (
            "stage",
            "category",
            "mutation_certainty",
            "tunnel_id",
            "dns_record_id",
            "cleanup_result",
        ),
    )
    for field_name in (
        "stage",
        "category",
        "mutation_certainty",
        "cleanup_result",
    ):
        case.assertIsInstance(getattr(evidence, field_name), Enum)
    case.assertEqual(evidence.stage.value, stage)
    case.assertEqual(evidence.category.value, category)
    case.assertEqual(evidence.mutation_certainty.value, mutation_certainty)
    case.assertEqual(evidence.tunnel_id, tunnel_id)
    case.assertEqual(evidence.dns_record_id, dns_record_id)
    case.assertEqual(evidence.cleanup_result.value, cleanup_result)

    public_text = f"{error!r} {error} {evidence!r}"
    for forbidden in (
        API_TOKEN,
        TUNNEL_TOKEN,
        RAW_PROVIDER_BODY,
        RAW_PROVIDER_EXCEPTION,
        RAW_PROVIDER_STATUS,
        RAW_PROVIDER_URL,
    ):
        case.assertNotIn(forbidden, public_text)
    case.assertIsNone(error.__cause__)


def _ingress() -> NamedPublicIngress:
    return NamedPublicIngress(
        ingress_id="gateway-001",
        authority_ref=IngressAuthorityReference("openj92-ingress"),
        target=PublicIngressTarget("gateway", "control"),
        connector_node_id="cloudflared-gateway-001",
        hostname="cpk-gateway-001.openj92.dev",
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
