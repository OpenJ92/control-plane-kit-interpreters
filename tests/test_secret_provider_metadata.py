"""I190: exact metadata observation without plaintext resolution or selection."""
import json
import unittest

import httpx

from control_plane_kit_core.secrets import SecretReference, SecretUseIntent
import control_plane_kit_interpreters.secret_provider as provider
from test_secret_provider_client import _client, _metadata, _response


REFERENCE = SecretReference("secret://provider-a/cloudflare/tunnel/token")
INTENT = SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN


def metadata(**changes):
    return {**_metadata(workspace_id="workspace-1",
        secret_id=provider.canonical_provider_secret_id(REFERENCE), status="active"),
        **changes}


class SecretProviderMetadataTests(unittest.TestCase):
    def client_read(self, client, **changes):
        method = getattr(client, "read_metadata", None)
        self.assertTrue(callable(method), "provider client needs metadata-only read")
        return method(**{ "workspace_id": "workspace-1", "reference": REFERENCE,
            "version_id": "version-1", **changes})

    def reader(self, client):
        reader_type = getattr(provider, "ControlPlaneKitSecretsMetadataReader", None)
        self.assertIsNotNone(reader_type, "concrete metadata reader is required")
        config = client.configuration
        registry = provider.SecretProviderBootstrapRegistry(
            endpoints={config.endpoint_reference: config.base_url},
            credential_files={config.credential_reference: config.credential_file})
        return reader_type(registry, policy=client.policy, transport=client.transport)

    def read(self, client, **changes):
        config = client.configuration
        return self.reader(client).read_version(**{
            "workspace_id": "workspace-1", "endpoint_reference": config.endpoint_reference,
            "credential_reference": config.credential_reference, "reference": REFERENCE,
            "version_id": "version-1", "intent": INTENT, **changes})

    def test_metadata_is_authenticated_exact_version_get_without_plaintext(self):
        requests = []
        def handler(request):
            requests.append(request)
            return _response({"outcome": "metadata", "metadata": metadata()})
        with _client(handler) as client:
            observed = self.client_read(client)
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.url.path,
            "/v1/workspaces/workspace-1/secrets/"
            + provider.canonical_provider_secret_id(REFERENCE) + "/metadata")
        self.assertEqual(dict(request.url.params), {"version_id": "version-1"})
        self.assertEqual(request.content, b"")
        self.assertEqual(request.headers["authorization"], "Bearer provider-token")
        self.assertEqual(observed.reference, REFERENCE)
        self.assertEqual(observed.version_id, "version-1")
        self.assertEqual(observed.labels["intent"], INTENT.value)

    def test_reader_returns_existing_observation_only_for_exact_active_use(self):
        with _client(lambda request: _response(
                {"outcome": "metadata", "metadata": metadata()})) as client:
            observed = self.read(client)
            self.assertNotIn("provider-token", repr(self.reader(client)))
        self.assertIs(type(observed), provider.SecretProviderVersionMetadata)
        self.assertEqual(observed.reference, REFERENCE)
        self.assertEqual(observed.version_id, "version-1")
        self.assertEqual(observed.status, "active")

    def test_reader_refuses_substituted_or_unavailable_metadata_without_resolve(self):
        cases = (
            {"workspace_id": "other"}, {"secret_id": "other"},
            {"version_id": "version-other"}, {"status": "revoked"},
            {"labels": {}}, {"labels": {"intent": "postgres.password"}},
        )
        for changed in cases:
            with self.subTest(changed=changed):
                calls = []
                def handler(request):
                    calls.append((request.method, request.url.path))
                    return _response({"outcome": "metadata", "metadata": metadata(**changed)})
                with _client(handler) as client:
                    with self.assertRaises(provider.SecretProviderClientError) as raised:
                        self.read(client)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][0], "GET")
                self.assertTrue(calls[0][1].endswith("/metadata"))
                self.assertNotIn(REFERENCE.reference_id, str(raised.exception))

    def test_reader_rejects_malformed_input_before_bootstrap_credential_or_send(self):
        for changed in ({"version_id": ""}, {"version_id": "bad\nversion"},
                {"version_id": None}, {"intent": INTENT.value},
                {"reference": REFERENCE.reference_id}, {"workspace_id": "bad/workspace"},
                {"endpoint_reference": "provider-main"}, {"credential_reference": "token"}):
            with self.subTest(changed=changed):
                calls = []
                with _client(lambda request: calls.append(request)) as client:
                    reader = self.reader(client)
                    # A missing credential would fail differently if malformed input reached IO.
                    client.configuration.credential_file.unlink()
                    with self.assertRaises(provider.SecretProviderClientError) as raised:
                        config = client.configuration
                        reader.read_version(**{
                            "workspace_id": "workspace-1", "endpoint_reference": config.endpoint_reference,
                            "credential_reference": config.credential_reference, "reference": REFERENCE,
                            "version_id": "version-1", "intent": INTENT, **changed})
                self.assertIs(raised.exception.code, provider.SecretProviderClientCode.MALFORMED_REQUEST)
                self.assertEqual(calls, [])

    def test_metadata_failures_stay_bounded_and_never_retry(self):
        cases = (
            (404, {"detail": {"outcome": "missing", "code": "secret-missing"}}),
            (403, {"detail": {"outcome": "denied", "code": "insufficient-scope"}}),
            (200, {"outcome": "metadata", "metadata": metadata(), "value_base64": "c2VjcmV0"}),
            (200, {"outcome": "resolved", "metadata": metadata(), "value_base64": "c2VjcmV0"}),
        )
        for status, payload in cases:
            with self.subTest(status=status, keys=tuple(payload)):
                calls = []
                def handler(request):
                    calls.append(request)
                    return _response(payload, status)
                with _client(handler) as client:
                    with self.assertRaises(provider.SecretProviderClientError) as raised:
                        self.read(client)
                self.assertEqual(len(calls), 1)
                self.assertNotIn("c2VjcmV0", str(raised.exception))
                self.assertNotIn("provider-token", str(raised.exception))

    def test_metadata_transport_timeout_is_bounded_without_retry(self):
        calls = []
        def handler(request):
            calls.append(request)
            raise httpx.ReadTimeout("sensitive endpoint and credential", request=request)
        with _client(handler) as client:
            with self.assertRaises(provider.SecretProviderClientError) as raised:
                self.read(client)
        self.assertEqual(len(calls), 1)
        self.assertIs(raised.exception.code, provider.SecretProviderClientCode.TIMED_OUT)
        self.assertNotIn("sensitive", str(raised.exception))

    def test_exact_resolution_refuses_substituted_version(self):
        calls = []
        def handler(request):
            calls.append(json.loads(request.content))
            return _response({"outcome": "resolved", "metadata": metadata(version_id="version-other"),
                "value_base64": "c2VjcmV0"})
        with _client(handler) as client:
            with self.assertRaises(provider.SecretProviderClientError) as raised:
                client.resolve(workspace_id="workspace-1", reference=REFERENCE, intent=INTENT,
                    caller_subject="worker-1", correlation_id="request-1", version_id="version-1")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["version_id"], "version-1")
        self.assertIs(raised.exception.code, provider.SecretProviderClientCode.MALFORMED_RESPONSE)
        self.assertNotIn("secret", str(raised.exception).replace("secret provider", ""))
