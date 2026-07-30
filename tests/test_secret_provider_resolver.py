from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from control_plane_kit_core.secrets import (
    SecretDenied,
    SecretMissing,
    SecretProviderEndpointReference,
    SecretReference,
    SecretResolutionGrant,
    SecretResolved,
    SecretUseIntent,
)
from control_plane_kit_interpreters.secret_provider import (
    ControlPlaneKitSecretsResolver,
    SecretProviderBootstrapError,
    SecretProviderBootstrapRegistry,
    SecretProviderClientCode,
    SecretProviderClientError,
    canonical_provider_secret_id,
)


class SecretProviderResolverTests(unittest.TestCase):
    def test_resolves_exact_grant_and_preserves_provider_correlation(self) -> None:
        reference = SecretReference("secret://provider-a/team/postgres/password")
        observed: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            observed["path"] = request.url.path
            observed["body"] = json.loads(request.content)
            return _resolved_response(reference, "secret-value-1191")

        with _resolver(handler) as resolver:
            grant = _grant(reference=reference)
            result = resolver.resolve(grant)

        self.assertIsInstance(result, SecretResolved)
        assert isinstance(result, SecretResolved)
        self.assertEqual(result.reference, reference)
        self.assertEqual(result.value.reveal(), "secret-value-1191")
        self.assertEqual(
            observed["path"],
            "/v1/workspaces/workspace-1/secrets/"
            f"{canonical_provider_secret_id(reference)}/resolve",
        )
        self.assertEqual(
            observed["body"],
            {
                "caller_subject": "worker-1",
                "correlation_id": "correlation-1",
                "intent": "postgres.password",
                "version_id": None,
            },
        )
        self.assertNotIn("secret-value-1191", repr(resolver))

    def test_maps_bounded_missing_and_denied_provider_outcomes(self) -> None:
        reference = SecretReference("secret://provider-a/postgres/password")
        cases = (
            (404, _error("missing", "secret-missing"), SecretMissing),
            (409, _error("revoked", "secret-revoked"), SecretDenied),
            (403, _error("denied", "insufficient-scope"), SecretDenied),
        )
        for status, payload, expected in cases:
            with self.subTest(expected=expected):
                with _resolver(
                    lambda _request, s=status, p=payload: httpx.Response(
                        s,
                        headers={"content-type": "application/json"},
                        json=p,
                    )
                ) as resolver:
                    result = resolver.resolve(_grant(reference=reference))
                self.assertIsInstance(result, expected)
                self.assertEqual(result.reference, reference)

    def test_bootstrap_and_transport_failures_remain_bounded(self) -> None:
        reference = SecretReference("secret://provider-a/postgres/password")
        sentinel_endpoint = "https://sensitive-provider.invalid"
        sentinel_credential = "sensitive-provider-token"
        with tempfile.TemporaryDirectory() as directory:
            credential_file = Path(directory) / "provider.token"
            credential_file.write_text(sentinel_credential, encoding="utf-8")
            resolver = ControlPlaneKitSecretsResolver(
                SecretProviderBootstrapRegistry(
                    endpoints={
                        SecretProviderEndpointReference("other-provider"): sentinel_endpoint
                    },
                    credential_files={
                        SecretReference("secret://bootstrap/other-token"): credential_file
                    },
                )
            )
            with self.assertRaises(SecretProviderBootstrapError) as bootstrap:
                resolver.resolve(_grant(reference=reference))
        self.assertNotIn(sentinel_endpoint, str(bootstrap.exception))
        self.assertNotIn(sentinel_credential, str(bootstrap.exception))

        with _resolver(
            lambda request: (_ for _ in ()).throw(
                httpx.ReadTimeout("leaky timeout", request=request)
            )
        ) as resolver:
            with self.assertRaises(SecretProviderClientError) as transport:
                resolver.resolve(_grant(reference=reference))
        self.assertIs(transport.exception.code, SecretProviderClientCode.TIMED_OUT)
        self.assertNotIn(reference.reference_id, str(transport.exception))

    def test_rejects_provider_response_for_substituted_reference(self) -> None:
        reference = SecretReference("secret://provider-a/postgres/password")
        substituted = SecretReference("secret://provider-a/postgres/other")
        with _resolver(
            lambda _request: _resolved_response(substituted, "secret-value-1191")
        ) as resolver:
            with self.assertRaises(SecretProviderClientError) as raised:
                resolver.resolve(_grant(reference=reference))
        self.assertIs(
            raised.exception.code,
            SecretProviderClientCode.MALFORMED_RESPONSE,
        )


class _ResolverFixture:
    def __init__(self, handler) -> None:
        self._directory = tempfile.TemporaryDirectory()
        credential_file = Path(self._directory.name) / "provider.token"
        credential_file.write_text("provider-token", encoding="utf-8")
        self.resolver = ControlPlaneKitSecretsResolver(
            SecretProviderBootstrapRegistry(
                endpoints={
                    SecretProviderEndpointReference("provider-main"):
                        "https://secrets.internal.example"
                },
                credential_files={
                    SecretReference("secret://bootstrap/provider-token"):
                        credential_file
                },
            ),
            transport=httpx.MockTransport(handler),
        )

    def __enter__(self):
        return self.resolver

    def __exit__(self, *_args) -> None:
        self._directory.cleanup()


def _resolver(handler) -> _ResolverFixture:
    return _ResolverFixture(handler)


def _grant(*, reference: SecretReference) -> SecretResolutionGrant:
    return SecretResolutionGrant(
        authorization_id="suse_" + "a" * 64,
        workspace_id="workspace-1",
        reference_registration_id="sref_" + "b" * 64,
        provider_registration_id="sprov_" + "c" * 64,
        endpoint_reference=SecretProviderEndpointReference("provider-main"),
        credential_reference=SecretReference("secret://bootstrap/provider-token"),
        reference=reference,
        intent=SecretUseIntent.POSTGRES_PASSWORD,
        actor_subject="worker-1",
        correlation_id="correlation-1",
        intent_fingerprint="d" * 64,
        run_id="run-1",
        activity_id="activity-1",
        effect_id="effect-1",
    )


def _resolved_response(
    reference: SecretReference,
    value: str,
) -> httpx.Response:
    secret_id = canonical_provider_secret_id(reference)
    return httpx.Response(
        200,
        headers={"content-type": "application/json"},
        json={
            "outcome": "resolved",
            "metadata": {
                "workspace_id": "workspace-1",
                "secret_id": secret_id,
                "version_id": "version-1",
                "version_number": 1,
                "status": "active",
                "algorithm": "aes-256-gcm",
                "key_fingerprint": "a" * 64,
                "key_version": "master-v1",
                "labels": {},
                "created_at": "2026-07-30T00:00:00Z",
                "revoked_at": None,
            },
            "value_base64": base64.b64encode(value.encode("utf-8")).decode("ascii"),
        },
    )


def _error(outcome: str, code: str) -> dict[str, object]:
    return {"detail": {"outcome": outcome, "code": code}}


if __name__ == "__main__":
    unittest.main()
