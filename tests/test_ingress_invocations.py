"""Semantic ingress boundaries through the existing Cloudflare provider doubles."""
import asyncio
from dataclasses import replace
import inspect
import unittest

from control_plane_kit_core.secrets import SecretCustodyStatus
from control_plane_kit_interpreters.cloudflare import CloudflareApiError, CloudflareNamedIngressInterpreter
from test_health_invocations import RecordingPort, Denied, RecordingUncertain
from test_cloudflare_named_ingress import (
    API_TOKEN, TUNNEL_TOKEN, FakeCloudflareTransport, RecordingSecretCustodian,
    _authorized_resolver, _authority, _custody_grant, _dns_cname, _dns_page, _ingress,
    _owned_resources, _resolution_grant,
)


class IngressPort(RecordingPort):
    def __init__(self, events, **kwargs):
        super().__init__(events, **kwargs)
        self.results = []
        self.after_result = None

    def record_result(self, permit, outcome, payload):
        kind, _ = self.permits[permit]
        self.events.append(("result", kind, outcome))
        self.results.append((kind, outcome, payload))
        if self.after_result is not None:
            self.after_result(kind, outcome, payload)


class IngressInvocationTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.port = IngressPort(self.events)
        self.transport = FakeCloudflareTransport()
        self.custodian = RecordingSecretCustodian()
        self.resolver = _authorized_resolver()
        self.interpreter = CloudflareNamedIngressInterpreter(self.transport, self.resolver, self.custodian)
        original_resolve = self.resolver.resolve
        original_request = self.transport.request
        original_store, original_revoke = self.custodian.store, self.custodian.revoke
        def resolve(grant):
            self.events.append(("resolve", grant.authorization_id))
            return original_resolve(grant)
        def request(method, url, **kwargs):
            self.events.append(("http", method, url.removeprefix("https://api.cloudflare.com/client/v4")))
            return original_request(method, url, **kwargs)
        def store(grant, value):
            self.events.append(("store",))
            return original_store(grant, value)
        def revoke(grant):
            self.events.append(("revoke",))
            return original_revoke(grant)
        self.resolver.resolve, self.transport.request = resolve, request
        self.custodian.store, self.custodian.revoke = store, revoke

    def create(self):
        self.assertIn("invocations", inspect.signature(self.interpreter.create).parameters,
            "#226 ingress create does not yet consume semantic invocations")
        return self.interpreter.create(_ingress(), authority=_authority(),
            allocation_name="cpk-gateway-001-c0303ba7369e", origin_service_url="http://gateway:8000",
            secret_resolution_grant=_resolution_grant(), secret_custody_grant=_custody_grant(),
            invocations=self.port)

    def remove(self):
        self.assertIn("invocations", inspect.signature(self.interpreter.teardown).parameters,
            "#226 ingress teardown does not yet consume semantic invocations")
        return self.interpreter.teardown(authority=_authority(), resources=_owned_resources(),
            secret_resolution_grant=_resolution_grant(), secret_custody_grant=_custody_grant(),
            invocations=self.port)

    def assert_no_deletes(self):
        self.assertFalse(any(event[:2] == ("http", "DELETE") for event in self.events))
        self.assertEqual(self.custodian.revoked_references, [])

    def test_create_records_provider_ids_before_separate_custody_admission(self):
        allocation = self.create()
        identity = _resolution_grant().authorization_id
        self.assertEqual(self.events[:4], [("admit", "secret-resolution", identity),
            ("resolve", identity), ("record", "secret-resolution", identity, "returned"),
            ("admit", "ingress-provider-create", None)])
        self.assertEqual(self.events[-4:], [("result", "ingress-provider-create", "returned"),
            ("admit", "ingress-custody-write", None), ("store",),
            ("result", "ingress-custody-write", "returned")])
        self.assertEqual(self.port.results, [
            ("ingress-provider-create", "returned", {"version": 1, "tag": "provider-created",
                "tunnel_id": "tunnel-001", "dns_record_id": "dns-001"}),
            ("ingress-custody-write", "returned", {"version": 1, "tag": "custody-write-returned",
                "receipt": allocation.secret_custody_receipt.descriptor()})])
        self.assertEqual(len(self.transport.requests), 6)
        self.assertTrue(self.custodian.received_expected_value)
        for value in (API_TOKEN, TUNNEL_TOKEN):
            self.assertNotIn(value, repr((self.events, self.port.results, allocation)))

    def test_token_acknowledgement_failure_prevents_provider_or_custody(self):
        uncertain = RecordingUncertain("closed-control")
        def after(*_):
            raise uncertain
        self.port.after = after
        with self.assertRaises(RecordingUncertain) as caught:
            self.create()
        self.assertIs(caught.exception, uncertain)
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.custodian.stored_references, [])

    def test_provider_admission_denial_prevents_all_provider_calls(self):
        denied = Denied("closed-control")
        def before(kind, _):
            if kind == "ingress-provider-create":
                raise denied
        self.port.before = before
        with self.assertRaises(Denied) as caught:
            self.create()
        self.assertIs(caught.exception, denied)
        self.assertEqual(self.transport.requests, [])

    def test_provider_record_failure_does_not_store_or_compensate(self):
        uncertain = RecordingUncertain("closed-control")
        def after(*_):
            raise uncertain
        self.port.after_result = after
        with self.assertRaises(RecordingUncertain) as caught:
            self.create()
        self.assertIs(caught.exception, uncertain)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(self.custodian.stored_references, [])
        self.assert_no_deletes()
        self.assertEqual(len(self.port.results), 1)

    def test_custody_admission_denial_keeps_created_provider_resources(self):
        denied = Denied("closed-control")
        def before(kind, _):
            if kind == "ingress-custody-write":
                raise denied
        self.port.before = before
        with self.assertRaises(Denied) as caught:
            self.create()
        self.assertIs(caught.exception, denied)
        self.assertEqual(self.custodian.stored_references, [])
        self.assert_no_deletes()

    def test_custody_provider_failure_records_unknown_without_compensation(self):
        self.custodian.fail_store = True
        with self.assertRaises(CloudflareApiError) as caught:
            self.create()
        self.assertEqual(self.port.results[-1], ("ingress-custody-write", "unknown",
            {"version": 1, "tag": "custody-write-unknown", "reason": "provider-error"}))
        self.assertNotIn(TUNNEL_TOKEN, str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assert_no_deletes()

    def test_inactive_custody_receipt_is_unknown_without_compensation(self):
        original = self.custodian.store
        def store(grant, value):
            return replace(original(grant, value), status=SecretCustodyStatus.REVOKED)
        self.custodian.store = store
        with self.assertRaises(CloudflareApiError):
            self.create()
        self.assertEqual(self.port.results[-1][2],
            {"version": 1, "tag": "custody-write-unknown", "reason": "invalid-receipt"})
        self.assert_no_deletes()

    def test_custody_record_failure_does_not_revoke_or_delete(self):
        uncertain = RecordingUncertain("closed-control")
        def after(kind, *_):
            if kind == "ingress-custody-write":
                raise uncertain
        self.port.after_result = after
        with self.assertRaises(RecordingUncertain) as caught:
            self.create()
        self.assertIs(caught.exception, uncertain)
        self.assertEqual(len(self.custodian.stored_references), 1)
        self.assert_no_deletes()
        self.assertEqual(len(self.port.results), 2)

    def test_token_fetch_failure_preserves_owned_dns_provenance_and_existing_cleanup(self):
        self.transport.raise_stages.add("dns-create")
        self.transport.dns_lookup_pages = [_dns_page([]), _dns_page([]),
            _dns_page([_dns_cname("dns-001", "tunnel-001")])]
        self.transport.fault_stages.add("tunnel-token")
        with self.assertRaises(CloudflareApiError):
            self.create()
        kind, outcome, payload = self.port.results[-1]
        self.assertEqual((kind, outcome), ("ingress-provider-create", "failed"))
        self.assertEqual(payload, {"version": 1, "tag": "provider-create-stopped",
            "stage": "tunnel-token", "category": "provider-status",
            "mutation_certainty": "dns-and-tunnel-created", "cleanup_result": "complete",
            "tunnel_id": "tunnel-001", "dns_record_id": "dns-001", "dns_provenance": "owned"})
        self.assertEqual([r.stage for r in self.transport.requests][-2:], ["dns-delete", "tunnel-delete"])
        self.assertEqual(self.custodian.stored_references, [])

    def test_existing_dns_is_observed_only_and_never_deleted(self):
        self.transport.existing_dns_record_id = "foreign-dns"
        with self.assertRaises(CloudflareApiError):
            self.create()
        payload = self.port.results[-1][2]
        self.assertEqual(payload["dns_record_id"], "foreign-dns")
        self.assertEqual(payload["dns_provenance"], "observed-only")
        self.assertIsNone(payload["tunnel_id"])
        self.assert_no_deletes()

    def test_remove_acknowledges_custody_before_admitting_exact_provider_cleanup(self):
        self.assertIsNone(self.remove())
        self.assertEqual(self.events[3:6], [("admit", "ingress-custody-revoke", None),
            ("revoke",), ("result", "ingress-custody-revoke", "returned")])
        self.assertEqual(self.events[6], ("admit", "ingress-provider-remove", None))
        self.assertEqual([r.stage for r in self.transport.requests],
            ["dns-delete", "tunnel-connections-delete", "tunnel-delete"])
        self.assertEqual(self.port.results, [
            ("ingress-custody-revoke", "returned", {"version": 1, "tag": "custody-revoke-returned"}),
            ("ingress-provider-remove", "returned", {"version": 1, "tag": "provider-removal-returned"})])

    def test_revoke_failure_prevents_every_provider_delete(self):
        self.custodian.fail_revoke = True
        with self.assertRaises(CloudflareApiError) as caught:
            self.remove()
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.port.results[-1], ("ingress-custody-revoke", "unknown",
            {"version": 1, "tag": "custody-revoke-unknown", "reason": "provider-error"}))
        self.assertNotIn(TUNNEL_TOKEN, str(caught.exception))

    def test_non_none_revoke_result_prevents_provider_deletes(self):
        self.custodian.revoke = lambda _: object()
        with self.assertRaises(CloudflareApiError):
            self.remove()
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.port.results[-1][2],
            {"version": 1, "tag": "custody-revoke-unknown", "reason": "invalid-result"})

    def test_revoke_record_failure_stops_before_delete_admission(self):
        uncertain = RecordingUncertain("closed-control")
        def after(*_):
            raise uncertain
        self.port.after_result = after
        with self.assertRaises(RecordingUncertain) as caught:
            self.remove()
        self.assertIs(caught.exception, uncertain)
        self.assertEqual(self.transport.requests, [])

    def test_provider_remove_denial_stops_after_acknowledged_revoke(self):
        denied = Denied("closed-control")
        def before(kind, _):
            if kind == "ingress-provider-remove":
                raise denied
        self.port.before = before
        with self.assertRaises(Denied) as caught:
            self.remove()
        self.assertIs(caught.exception, denied)
        self.assertEqual(len(self.custodian.revoked_references), 1)
        self.assertEqual(self.transport.requests, [])

    def test_provider_remove_attempts_exact_stages_and_records_bounded_failure_list(self):
        self.transport.fault_stages.update(("dns-delete", "tunnel-delete"))
        with self.assertRaises(CloudflareApiError):
            self.remove()
        self.assertEqual([r.stage for r in self.transport.requests],
            ["dns-delete", "tunnel-connections-delete", "tunnel-delete"])
        self.assertEqual(self.port.results[-1], ("ingress-provider-remove", "unknown",
            {"version": 1, "tag": "provider-removal-unknown", "reason": "provider-error",
                "failed_stages": ["dns", "tunnel"]}))

    def test_provider_control_survives_transport_and_create_handlers_without_cleanup(self):
        denied = Denied("closed-control")
        original = self.transport.request
        def request(method, url, **kwargs):
            if method == "PUT":
                raise denied
            return original(method, url, **kwargs)
        self.transport.request = request
        with self.assertRaises(Denied) as caught:
            self.create()
        self.assertIs(caught.exception, denied)
        self.assert_no_deletes()
        self.assertEqual(self.port.results, [])

    def test_cleanup_control_stops_remaining_deletes_without_reclassification(self):
        denied = Denied("closed-control")
        calls = []
        def request(method, url, **kwargs):
            calls.append((method, url))
            raise denied
        self.transport.request = request
        with self.assertRaises(Denied) as caught:
            self.remove()
        self.assertIs(caught.exception, denied)
        self.assertEqual(len(calls), 1)
        self.assertIn("dns_records/dns-001", calls[0][1])
        self.assertEqual(len(self.port.results), 1)

    def test_custody_cancellation_is_primary_if_recording_fails_and_never_compensates(self):
        cancelled = asyncio.CancelledError()
        def store(*_):
            raise cancelled
        def after(kind, *_):
            if kind == "ingress-custody-write":
                raise RecordingUncertain("closed-control")
        self.custodian.store, self.port.after_result = store, after
        with self.assertRaises(asyncio.CancelledError) as caught:
            self.create()
        self.assertIs(caught.exception, cancelled)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(self.port.results[-1][2],
            {"version": 1, "tag": "custody-write-unknown", "reason": "interrupted"})
        self.assert_no_deletes()

    def test_required_or_missing_result_port_refuses_before_token_resolution(self):
        self.assertIn("require_invocations", inspect.signature(CloudflareNamedIngressInterpreter).parameters)
        for port in (None, RecordingPort(self.events)):
            with self.subTest(port=type(port).__name__):
                self.interpreter = replace(self.interpreter, require_invocations=True)
                self.port = port
                with self.assertRaisesRegex(RuntimeError, "invocation port"):
                    self.create()
        self.assertEqual(self.events, [])
        self.assertEqual(self.resolver.grants, [])

    def test_invalid_successful_dns_id_never_enters_result_record_or_custody(self):
        for shape, invalid_id in (("malformed", "raw token=private-value"),
                ("oversized", "x" * 129), ("sensitive", "provider-secret-value")):
            with self.subTest(shape=shape):
                self.setUp()
                original = self.transport.request
                def request(method, url, **kwargs):
                    response = original(method, url, **kwargs)
                    if method == "POST" and url.endswith("/dns_records"):
                        return replace(response, body={"success": True, "result": {"id": invalid_id}})
                    return response
                self.transport.request = request
                with self.assertRaises(CloudflareApiError) as caught:
                    self.create()
                self.assertEqual(self.port.results, [("ingress-provider-create", "unknown",
                    {"version": 1, "tag": "provider-create-unclassified"})])
                self.assertNotIn(invalid_id, repr((self.events, self.port.results, caught.exception)))
                self.assertEqual(self.custodian.stored_references, [])
                self.assert_no_deletes()
                self.assertNotIn("tunnel-token", [value.stage for value in self.transport.requests])

    def test_create_cleanup_control_has_no_prior_private_provider_exception_chain(self):
        denied = Denied("closed-control")
        self.transport.raise_stages.add("tunnel-configuration")
        original = self.transport.request
        deletes = []
        def request(method, url, **kwargs):
            if method == "DELETE":
                deletes.append(url)
                raise denied
            return original(method, url, **kwargs)
        self.transport.request = request
        with self.assertRaises(Denied) as caught:
            self.create()
        self.assertIs(caught.exception, denied)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(deletes, ["https://api.cloudflare.com/client/v4/accounts/account-001/cfd_tunnel/tunnel-001"])
        self.assertEqual(self.port.results, [])
        self.assertEqual(self.custodian.stored_references, [])
