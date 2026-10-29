"""Typed policy wire laws; provider persistence and admission stay at their owners."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from control_plane_kit_core.provider_policy import (
    ProviderPolicyCommandResultRequest, ProviderPolicyCoordinate,
    ProviderPolicyErrorCode, ProviderPolicyFailure, ProviderPolicyGrantCommand,
    ProviderPolicyIntentMode, ProviderPolicyListRequest, ProviderPolicyOutcome,
    ProviderPolicyReadRequest, ProviderPolicyRevokeCommand,
)
from control_plane_kit_core.secrets import SecretProviderEndpointReference, SecretReference
from control_plane_kit_interpreters.secret_provider import (
    ControlPlaneKitSecretsPolicyClient, SecretProviderClientConfiguration,
    SecretProviderClientPolicy,
)

COORDINATE = ProviderPolicyCoordinate("client-a", "workspace-a", "secret.metadata")
COMMAND = ProviderPolicyGrantCommand("provider-a", "provider-actual", COORDINATE,
    4, "caller-key-not-on-wire", "command-correlation")
TOKEN = "synthetic-policy-token"


def result(command=COMMAND, **changes):
    value = {**command.coordinate.descriptor(), "provider_id": command.provider_id,
        "correlation_id": command.provider_correlation, "operation": command.operation.value,
        "expected_revision": command.expected_revision,
        "outcome": "granted", "code": "provider-policy-granted",
        "grant_id": "grant-a", "resulting_revision": command.expected_revision + 1,
        "actor": "provider-admin", "occurred_at": "2030-01-01T00:00:00Z"}
    value.update(changes)
    return value


def grant(**changes):
    value = {**COORDINATE.descriptor(), "grant_id": "grant-a", "provider_id": "provider-actual",
        "origin": "command", "granted_by": "provider-admin", "grant_correlation_id": "command-correlation",
        "granted_at": "2030-01-01T00:00:00Z", "revoked_by": None,
        "revoke_correlation_id": None, "revoked_at": None}
    value.update(changes)
    return value


class SecretProviderPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.credential = Path(self.directory.name) / "credential"
        self.credential.write_text(TOKEN, encoding="utf-8")
        self.configuration = SecretProviderClientConfiguration(
            SecretProviderEndpointReference("endpoint-ref"), "https://provider.invalid",
            SecretReference("secret://provider/policy-credential"), self.credential)
        self.requests = []

    def client(self, payload=None, status=200, *, handler=None, **kwargs):
        def send(request):
            self.requests.append(request)
            if handler:
                return handler(request)
            return httpx.Response(status, json=payload)
        return ControlPlaneKitSecretsPolicyClient(self.configuration, "provider-a", "provider-actual",
            transport=httpx.MockTransport(send), **kwargs)

    def assert_failure(self, callback, code, *, ambiguous=False, calls=1):
        with self.assertRaises(ProviderPolicyFailure) as raised:
            callback()
        self.assertIs(raised.exception.code, code)
        self.assertEqual(raised.exception.effect_may_have_occurred, ambiguous)
        self.assertEqual(len(self.requests), calls)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        for private in (TOKEN, "provider.invalid", "private-response-sentinel"):
            self.assertNotIn(private, str(raised.exception))
            self.assertNotIn(private, repr(raised.exception))
        return raised.exception

    def test_grant_and_revoke_have_exact_closed_payload_and_provider_identity(self):
        revoke = ProviderPolicyRevokeCommand("provider-a", "provider-actual", COORDINATE,
            5, "revoke-caller-key", "revoke-correlation", "grant-a")
        cases = ((COMMAND, "grant", "/v1/provider-policy/grants", result()),
            (revoke, "revoke", "/v1/provider-policy/grants/grant-a/revoke",
             result(revoke, outcome="revoked", code="provider-policy-revoked")))
        for command, method, path, payload in cases:
            with self.subTest(method=method):
                self.requests.clear()
                client = self.client(payload)
                observed = getattr(client, method)(command)
                self.assertTrue(observed.matches(command))
                self.assertEqual(observed.grant_id, "grant-a")
                self.assertEqual(observed.provider_actor, "provider-admin")
                self.assertEqual(len(self.requests), 1)
                sent = self.requests[0]
                self.assertEqual((sent.method, sent.url.path), ("POST", path))
                self.assertEqual(json.loads(sent.content), {**COORDINATE.descriptor(),
                    "expected_revision": command.expected_revision,
                    "correlation_id": command.provider_correlation})
                self.assertEqual(sent.headers["authorization"], "Bearer " + TOKEN)
                self.assertNotIn(TOKEN, repr(client))

    def test_all_reads_have_distinct_bounded_audit_headers_and_no_body(self):
        def provider(request):
            # Accepted E requires this header before entering its read route.
            audit = request.headers.get("X-Correlation-ID")
            if not audit:
                return httpx.Response(422, json={"detail": [{"msg": "header required"}]})
            if "/commands/" in request.url.path:
                payload = result()
            elif request.url.path.endswith("/grant-a"):
                payload = {"revision": 5, "grant": grant()}
            else:
                payload = {"revision": 5, "grants": [grant()], "next_after": None}
            return httpx.Response(200, json=payload)
        client = self.client(handler=provider)
        self.assertEqual(client.read(ProviderPolicyReadRequest("provider-a", "grant-a")).revision, 5)
        self.assertEqual(len(client.list(ProviderPolicyListRequest("provider-a")).grants), 1)
        self.assertEqual(client.command_result(ProviderPolicyCommandResultRequest(
            "provider-a", "command-correlation")).correlation_id, "command-correlation")
        self.assertEqual(len(self.requests), 3)
        audits = []
        for request in self.requests:
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.content, b"")
            self.assertEqual(request.headers["authorization"], "Bearer " + TOKEN)
            audit = request.headers["X-Correlation-ID"]
            self.assertLessEqual(len(audit), 128)
            self.assertNotEqual(audit, "command-correlation")
            audits.append(audit)
        self.assertEqual(len(set(audits)), 3)

    def test_mutation_correlation_128_129_preflight_and_command_url_512_are_distinct(self):
        accepted = replace(COMMAND, provider_correlation="x" * 128)
        self.client(result(accepted)).grant(accepted)
        self.assertEqual(json.loads(self.requests[0].content)["correlation_id"], "x" * 128)
        self.requests.clear()
        self.credential.unlink()
        self.assert_failure(lambda: self.client().grant(replace(COMMAND,
            provider_correlation="x" * 129)), ProviderPolicyErrorCode.INVALID, calls=0)
        self.credential.write_text(TOKEN, encoding="utf-8")
        long_target = "c" * 512
        observed = self.client(result(correlation_id=long_target)).command_result(
            ProviderPolicyCommandResultRequest("provider-a", long_target))
        self.assertEqual(observed.correlation_id, long_target)
        self.assertEqual(self.requests[0].url.path, "/v1/provider-policy/commands/" + long_target)

    def test_wrong_request_or_binding_refuses_before_credentials_and_transport(self):
        self.credential.unlink()
        for request in (object(), replace(COMMAND, logical_provider_id="another"),
                replace(COMMAND, provider_id="another")):
            with self.subTest(request=type(request).__name__):
                self.assert_failure(lambda: self.client().grant(request), ProviderPolicyErrorCode.INVALID, calls=0)
        self.assert_failure(lambda: self.client().read(ProviderPolicyReadRequest(
            "another", "grant-a")), ProviderPolicyErrorCode.INVALID, calls=0)

    def test_exact_command_evidence_and_revoke_grant_identity_are_checked(self):
        changes = ({"provider_id": "other"}, {"correlation_id": "other"},
            {"subject": "other"}, {"workspace_id": "other"}, {"action": "secret.resolve"},
            {"intent": "postgres-password"}, {"expected_revision": 3, "resulting_revision": 4},
            {"resulting_revision": 9}, {"private": "private-response-sentinel"})
        for change in changes:
            with self.subTest(change=tuple(change)):
                self.requests.clear()
                self.assert_failure(lambda: self.client(result(**change)).grant(COMMAND),
                    ProviderPolicyErrorCode.MALFORMED_RESULT, ambiguous=True)
        revoke = ProviderPolicyRevokeCommand("provider-a", "provider-actual", COORDINATE,
            4, "caller-key", "command-correlation", "expected-grant")
        self.requests.clear()
        self.assert_failure(lambda: self.client(result(revoke, outcome="revoked",
            code="provider-policy-revoked", grant_id="substituted-grant")).revoke(revoke),
            ProviderPolicyErrorCode.MALFORMED_RESULT, ambiguous=True)

    def test_http_conflict_never_becomes_canonical_or_causes_readback(self):
        client = self.client({"detail": {"outcome": "conflict", "code": "policy-revision-conflict"}}, 409)
        self.assert_failure(lambda: client.grant(COMMAND), ProviderPolicyErrorCode.CONFLICT)
        self.assertEqual(self.requests[0].method, "POST")
        self.requests.clear()
        canonical = result(outcome="conflict", code="policy-revision-conflict",
            grant_id=None, resulting_revision=9)
        observed = self.client(canonical).command_result(
            ProviderPolicyCommandResultRequest("provider-a", "command-correlation"))
        self.assertIs(observed.outcome, ProviderPolicyOutcome.CONFLICT)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0].method, "GET")

    def test_bounded_http_failures_are_safe_and_never_retry(self):
        for status, outcome, code in ((400, "malformed", ProviderPolicyErrorCode.INVALID),
                (422, "malformed", ProviderPolicyErrorCode.INVALID),
                (401, "denied", ProviderPolicyErrorCode.DENIED),
                (403, "denied", ProviderPolicyErrorCode.DENIED),
                (404, "missing", ProviderPolicyErrorCode.MISSING),
                (503, "unavailable", ProviderPolicyErrorCode.UNAVAILABLE)):
            with self.subTest(status=status):
                self.requests.clear()
                client = self.client({"detail": {"outcome": outcome, "code": "private-response-sentinel"}}, status)
                self.assert_failure(lambda: client.grant(COMMAND), code, ambiguous=status >= 500)

    def test_lost_reply_redirect_and_malformed_response_preserve_mutation_uncertainty(self):
        def timeout(request):
            raise httpx.ReadTimeout(TOKEN + " private-response-sentinel", request=request)
        cases = ((timeout, ProviderPolicyErrorCode.TRANSPORT),
            (lambda request: httpx.Response(307, headers={"location": "https://redirect.invalid"}), ProviderPolicyErrorCode.TRANSPORT),
            (lambda request: httpx.Response(200, json={"secret": "private-response-sentinel"}), ProviderPolicyErrorCode.MALFORMED_RESULT),
            (lambda request: httpx.Response(200, content=b"x" * 1025,
                headers={"content-type": "application/json"}), ProviderPolicyErrorCode.MALFORMED_RESULT))
        for handler, code in cases:
            with self.subTest(code=code, handler=handler):
                self.requests.clear()
                client = self.client(handler=handler, policy=SecretProviderClientPolicy(maximum_response_bytes=1024))
                self.assert_failure(lambda: client.grant(COMMAND), code, ambiguous=True)
                self.requests.clear()
                self.assert_failure(lambda: client.command_result(ProviderPolicyCommandResultRequest(
                    "provider-a", "command-correlation")), code)

    def test_command_result_and_grant_reads_refuse_substitution_without_fallback(self):
        for payload in (result(correlation_id="other"), result(provider_id="other")):
            self.requests.clear()
            self.assert_failure(lambda: self.client(payload).command_result(
                ProviderPolicyCommandResultRequest("provider-a", "command-correlation")),
                ProviderPolicyErrorCode.MALFORMED_RESULT)
        for payload in (grant(grant_id="other"), grant(provider_id="other")):
            self.requests.clear()
            self.assert_failure(lambda: self.client({"revision": 5, "grant": payload}).read(
                ProviderPolicyReadRequest("provider-a", "grant-a")), ProviderPolicyErrorCode.MALFORMED_RESULT)

    def test_list_maps_filters_and_one_ordered_page_without_autopagination(self):
        request = ProviderPolicyListRequest("provider-a", subject="client + a", workspace_id="workspace-a",
            action="secret.resolve", intent_mode=ProviderPolicyIntentMode.EXACT, intent="postgres-password",
            limit=1, after_grant_id="grant-0")
        payload = {"revision": 8, "grants": [grant(subject=request.subject,
            action=request.action, intent=request.intent)], "next_after": "grant-a"}
        page = self.client(payload).list(request)
        self.assertEqual((page.revision, page.next_after), (8, "grant-a"))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(dict(self.requests[0].url.params), {"subject": request.subject,
            "workspace_id": request.workspace_id, "action": request.action, "intent": request.intent,
            "intent_mode": "exact", "limit": "1", "after_grant_id": "grant-0"})
        self.requests.clear()
        empty = self.client({"revision": 8, "grants": [], "next_after": None}).list(
            ProviderPolicyListRequest("provider-a", intent_mode=ProviderPolicyIntentMode.NONE))
        self.assertEqual(empty.grants, ())
        self.assertEqual(self.requests[0].url.params["intent_mode"], "none")
        self.assertNotIn("intent", self.requests[0].url.params)

    def test_list_refuses_foreign_revoked_unordered_filter_and_cursor_evidence(self):
        cases = (
            {"grants": [grant(provider_id="other")]},
            {"grants": [grant(subject="other")]},
            {"grants": [grant(intent="unexpected")]},
            {"grants": [grant(revoked_by="admin", revoke_correlation_id="revoked", revoked_at="now")]},
            {"grants": [grant(grant_id="grant-c"), grant(grant_id="grant-b")]},
            {"grants": [grant(), grant()]},
            {"grants": [grant()], "next_after": "wrong"},
            {"grants": [], "next_after": "grant-a"},
            {"grants": [grant(grant_id="grant-0")]},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.requests.clear()
                payload = {"revision": 5, "grants": [], "next_after": None, **changes}
                self.assert_failure(lambda: self.client(payload).list(ProviderPolicyListRequest(
                    "provider-a", subject="client-a", intent_mode=ProviderPolicyIntentMode.NONE,
                    after_grant_id="grant-0", limit=2)), ProviderPolicyErrorCode.MALFORMED_RESULT)

    def test_revoked_grant_is_readable_and_does_not_become_current_list_policy(self):
        revoked = grant(revoked_by="admin", revoke_correlation_id="revoke-a", revoked_at="now")
        observed = self.client({"revision": 6, "grant": revoked}).read(
            ProviderPolicyReadRequest("provider-a", "grant-a"))
        self.assertEqual(observed.grant.revoked_at, "now")
        self.assertEqual(len(self.requests), 1)
