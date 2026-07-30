from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import httpx

from control_plane_kit_core.secrets import (
    SecretCustodyGrant,
    SecretProviderEndpointReference,
    SecretReference,
    SecretUseIntent,
    SecretValue,
)
from control_plane_kit_interpreters.secret_provider import (
    ControlPlaneKitSecretsClient,
    ControlPlaneKitSecretsCustodian,
    SecretProviderBootstrapError,
    SecretProviderBootstrapRegistry,
    SecretProviderClientCode,
    SecretProviderClientError,
    SecretProviderClientPolicy,
    SecretProviderOutcomeCertainty,
    canonical_provider_secret_id,
)


class SecretProviderClientTests(unittest.TestCase):
    def test_custodian_writes_and_revokes_exact_granted_reference(self) -> None:
        reference = SecretReference("secret://provider-a/generated/tunnel-001")
        secret_id = canonical_provider_secret_id(reference)
        paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            paths.append(request.url.path)
            if request.url.path.endswith("/revoke"):
                return _response(
                    {
                        "outcome": "revoked",
                        "metadata": [
                            _metadata(
                                workspace_id="workspace-1",
                                secret_id=secret_id,
                                status="revoked",
                                revoked_at="2026-07-30T00:00:01Z",
                            )
                        ],
                    }
                )
            return _response(
                {
                    "outcome": "stored",
                    "metadata": _metadata(
                        workspace_id="workspace-1",
                        secret_id=secret_id,
                        status="active",
                    ),
                }
            )

        with tempfile.TemporaryDirectory() as directory:
            endpoint = SecretProviderEndpointReference("provider-main")
            credential = SecretReference("secret://bootstrap/provider-token")
            credential_file = Path(directory) / "provider.token"
            credential_file.write_text("provider-token", encoding="utf-8")
            custodian = ControlPlaneKitSecretsCustodian(
                SecretProviderBootstrapRegistry(
                    endpoints={endpoint: "https://secrets.internal.example"},
                    credential_files={credential: credential_file},
                ),
                transport=httpx.MockTransport(handler),
            )
            grant = SecretCustodyGrant(
                custody_id="scust_" + "a" * 64,
                workspace_id="workspace-1",
                provider_registration_id="sprov_" + "b" * 64,
                endpoint_reference=endpoint,
                credential_reference=credential,
                reference=reference,
                intent=SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
                actor_subject="cloudflare-interpreter",
                correlation_id="secret-custody-" + "c" * 64,
                custody_fingerprint="d" * 64,
                run_id="run-1",
                activity_id="activity-1",
                effect_id="effect-1",
            )

            receipt = custodian.store(grant, SecretValue("tunnel-token-value"))
            custodian.revoke(grant)

        self.assertTrue(receipt.matches(grant))
        self.assertEqual(receipt.version_number, 1)
        self.assertEqual(
            paths,
            [
                f"/v1/workspaces/workspace-1/secrets/{secret_id}",
                f"/v1/workspaces/workspace-1/secrets/{secret_id}/revoke",
            ],
        )
        self.assertNotIn("tunnel-token-value", repr(custodian))

    def test_custodian_revocation_is_idempotent_when_reference_is_absent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            endpoint = SecretProviderEndpointReference("provider-main")
            credential = SecretReference("secret://bootstrap/provider-token")
            credential_file = Path(directory) / "provider.token"
            credential_file.write_text("provider-token", encoding="utf-8")
            custodian = ControlPlaneKitSecretsCustodian(
                SecretProviderBootstrapRegistry(
                    endpoints={endpoint: "https://secrets.internal.example"},
                    credential_files={credential: credential_file},
                ),
                transport=httpx.MockTransport(
                    lambda _request: _response(
                        _error("missing", "secret-missing"),
                        404,
                    )
                ),
            )
            grant = SecretCustodyGrant(
                custody_id="scust_" + "a" * 64,
                workspace_id="workspace-1",
                provider_registration_id="sprov_" + "b" * 64,
                endpoint_reference=endpoint,
                credential_reference=credential,
                reference=SecretReference(
                    "secret://provider-a/generated/tunnel-absent"
                ),
                intent=SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
                actor_subject="cloudflare-interpreter",
                correlation_id="secret-custody-" + "c" * 64,
                custody_fingerprint="d" * 64,
            )

            custodian.revoke(grant)

    def test_canonical_secret_id_preserves_complete_reference_without_collision(
        self,
    ) -> None:
        nested = SecretReference("secret://provider-a/team/service/token")
        flattened = SecretReference("secret://provider-a/team-service-token")
        other_provider = SecretReference("secret://provider-b/team/service/token")

        values = {
            canonical_provider_secret_id(nested),
            canonical_provider_secret_id(flattened),
            canonical_provider_secret_id(other_provider),
        }

        self.assertEqual(len(values), 3)
        self.assertTrue(all(value.startswith("cpk1_") for value in values))
        self.assertTrue(all("/" not in value for value in values))
        self.assertEqual(
            canonical_provider_secret_id(nested),
            canonical_provider_secret_id(nested),
        )

    def test_bootstrap_registry_selects_exact_references_and_redacts_values(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            endpoint = SecretProviderEndpointReference("provider-main")
            credential = SecretReference("secret://bootstrap/provider-token")
            credential_file = Path(directory) / "provider.token"
            registry = SecretProviderBootstrapRegistry(
                endpoints={endpoint: "https://secrets.internal.example"},
                credential_files={credential: credential_file},
            )

            configuration = registry.configuration_for(
                endpoint_reference=endpoint,
                credential_reference=credential,
            )

            self.assertEqual(
                configuration.base_url,
                "https://secrets.internal.example",
            )
            self.assertEqual(configuration.credential_file, credential_file)
            self.assertNotIn(configuration.base_url, repr(configuration))
            self.assertNotIn(str(credential_file), repr(configuration))
            self.assertNotIn(configuration.base_url, repr(registry))
            with self.assertRaises(SecretProviderBootstrapError):
                registry.configuration_for(
                    endpoint_reference=SecretProviderEndpointReference("missing"),
                    credential_reference=credential,
                )

    def test_write_resolve_and_revoke_use_mounted_credential_and_exact_shapes(
        self,
    ) -> None:
        requests: list[dict[str, object]] = []
        reference = SecretReference("secret://provider-a/cloudflare/tunnel/token")
        secret_id = canonical_provider_secret_id(reference)

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            requests.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers["authorization"],
                    "body": body,
                }
            )
            if request.url.path.endswith("/resolve"):
                return _response(
                    {
                        "outcome": "resolved",
                        "metadata": _metadata(
                            workspace_id="workspace-1",
                            secret_id=secret_id,
                            status="active",
                        ),
                        "value_base64": "dHVubmVsLXRva2VuLXZhbHVl",
                    }
                )
            if request.url.path.endswith("/revoke"):
                return _response(
                    {
                        "outcome": "revoked",
                        "metadata": [
                            _metadata(
                                workspace_id="workspace-1",
                                secret_id=secret_id,
                                status="revoked",
                                revoked_at="2026-07-30T00:00:01Z",
                            )
                        ],
                    }
                )
            return _response(
                {
                    "outcome": "stored",
                    "metadata": _metadata(
                        workspace_id="workspace-1",
                        secret_id=secret_id,
                        status="active",
                    ),
                }
            )

        with _client(handler) as client:
            written = client.write(
                workspace_id="workspace-1",
                reference=reference,
                value=SecretValue("tunnel-token-value"),
                intent=SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
                caller_subject="cloudflare-interpreter",
                correlation_id="ingress-effect-1",
            )
            resolved = client.resolve(
                workspace_id="workspace-1",
                reference=reference,
                intent=SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
                caller_subject="docker-interpreter",
                correlation_id="connector-start-1",
            )
            revoked = client.revoke(
                workspace_id="workspace-1",
                reference=reference,
                caller_subject="cloudflare-interpreter",
                correlation_id="ingress-compensation-1",
            )

        self.assertEqual(written.reference, reference)
        self.assertEqual(resolved.value.reveal(), "tunnel-token-value")
        self.assertEqual(revoked.reference, reference)
        self.assertNotIn("tunnel-token-value", repr(resolved))
        self.assertEqual(
            [request["authorization"] for request in requests],
            ["Bearer provider-token"] * 3,
        )
        self.assertEqual(
            requests[0]["path"],
            f"/v1/workspaces/workspace-1/secrets/{secret_id}",
        )
        self.assertEqual(
            requests[1]["body"]["correlation_id"],
            "connector-start-1",
        )
        self.assertEqual(
            requests[2]["body"]["correlation_id"],
            "ingress-compensation-1",
        )

    def test_bounded_failures_distinguish_provider_outcomes(self) -> None:
        reference = SecretReference("secret://provider-a/value")
        cases = (
            (401, _error("denied", "unauthenticated"), SecretProviderClientCode.DENIED),
            (403, _error("denied", "insufficient-scope"), SecretProviderClientCode.DENIED),
            (404, _error("missing", "secret-missing"), SecretProviderClientCode.MISSING),
            (409, _error("revoked", "secret-revoked"), SecretProviderClientCode.REVOKED),
            (
                503,
                _error("unavailable", "integrity-failure"),
                SecretProviderClientCode.INTEGRITY_FAILURE,
            ),
            (
                503,
                _error("unavailable", "audit-unavailable"),
                SecretProviderClientCode.UNAVAILABLE,
            ),
        )
        for status, payload, expected in cases:
            with self.subTest(expected=expected):
                with _client(
                    lambda _request, s=status, p=payload: _response(p, s)
                ) as client:
                    with self.assertRaises(SecretProviderClientError) as raised:
                        client.resolve(
                            workspace_id="workspace-1",
                            reference=reference,
                            intent=SecretUseIntent.POSTGRES_PASSWORD,
                            caller_subject="docker-interpreter",
                            correlation_id="resolve-1",
                        )
                self.assertIs(raised.exception.code, expected)
                self.assertIs(
                    raised.exception.certainty,
                    SecretProviderOutcomeCertainty.DEFINITE,
                )

    def test_redirect_timeout_oversize_and_malformed_responses_fail_closed(
        self,
    ) -> None:
        outbound = httpx.Request("POST", "https://provider.invalid")
        cases = (
            (
                lambda _request: httpx.Response(
                    307,
                    headers={
                        "location": "https://redirect.invalid",
                        "content-type": "application/json",
                    },
                    json={},
                ),
                SecretProviderClientCode.REDIRECTED,
            ),
            (
                lambda _request: (_ for _ in ()).throw(
                    httpx.ReadTimeout("timed out", request=outbound)
                ),
                SecretProviderClientCode.TIMED_OUT,
            ),
            (
                lambda _request: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=b"x" * 257,
                ),
                SecretProviderClientCode.RESPONSE_TOO_LARGE,
            ),
            (
                lambda _request: httpx.Response(
                    200,
                    headers={"content-type": "text/plain"},
                    content=b"{}",
                ),
                SecretProviderClientCode.MALFORMED_RESPONSE,
            ),
            (
                lambda _request: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=b"not-json",
                ),
                SecretProviderClientCode.MALFORMED_RESPONSE,
            ),
        )
        for handler, expected in cases:
            with self.subTest(expected=expected):
                with _client(
                    handler,
                    policy=SecretProviderClientPolicy(
                        maximum_response_bytes=256
                    ),
                ) as client:
                    with self.assertRaises(SecretProviderClientError) as raised:
                        client.resolve(
                            workspace_id="workspace-1",
                            reference=SecretReference("secret://provider-a/value"),
                            intent=SecretUseIntent.POSTGRES_PASSWORD,
                            caller_subject="docker-interpreter",
                            correlation_id="resolve-1",
                        )
                self.assertIs(raised.exception.code, expected)

    def test_mutation_transport_failure_is_explicitly_uncertain(self) -> None:
        outbound = httpx.Request("POST", "https://provider.invalid")
        sentinel = "provider-token"
        with _client(
            lambda _request: (_ for _ in ()).throw(
                httpx.ReadTimeout("timed out", request=outbound)
            ),
            token=sentinel,
        ) as client:
            with self.assertRaises(SecretProviderClientError) as raised:
                client.write(
                    workspace_id="workspace-1",
                    reference=SecretReference("secret://provider-a/value"),
                    value=SecretValue("secret-value"),
                    intent=SecretUseIntent.APPLICATION_CONTROL_TOKEN,
                    caller_subject="interpreter",
                    correlation_id="write-1",
                )

        self.assertIs(
            raised.exception.certainty,
            SecretProviderOutcomeCertainty.UNCERTAIN,
        )
        self.assertNotIn(sentinel, str(raised.exception))
        self.assertNotIn("secret-value", repr(raised.exception))
        self.assertNotIn("provider.internal", repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_successful_mutation_with_malformed_response_is_uncertain(self) -> None:
        with _client(
            lambda _request: _response(
                {"outcome": "stored", "metadata": {"unexpected": True}}
            )
        ) as client:
            with self.assertRaises(SecretProviderClientError) as raised:
                client.write(
                    workspace_id="workspace-1",
                    reference=SecretReference("secret://provider-a/value"),
                    value=SecretValue("secret-value"),
                    intent=SecretUseIntent.APPLICATION_CONTROL_TOKEN,
                    caller_subject="interpreter",
                    correlation_id="write-1",
                )

        self.assertIs(
            raised.exception.code,
            SecretProviderClientCode.MALFORMED_RESPONSE,
        )
        self.assertIs(
            raised.exception.certainty,
            SecretProviderOutcomeCertainty.UNCERTAIN,
        )

    def test_total_deadline_applies_to_empty_response(self) -> None:
        ticks = iter((0.0, 11.0))
        with _client(
            lambda _request: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b"",
            ),
            clock=lambda: next(ticks),
        ) as client:
            with self.assertRaises(SecretProviderClientError) as raised:
                client.resolve(
                    workspace_id="workspace-1",
                    reference=SecretReference("secret://provider-a/value"),
                    intent=SecretUseIntent.POSTGRES_PASSWORD,
                    caller_subject="interpreter",
                    correlation_id="resolve-1",
                )

        self.assertIs(
            raised.exception.code,
            SecretProviderClientCode.TIMED_OUT,
        )

    def test_credential_file_is_reread_and_never_exposed_by_failure(self) -> None:
        authorizations: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            authorizations.append(request.headers["authorization"])
            return _response(_error("missing", "secret-missing"), 404)

        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "provider.token"
            client = _configured_client(
                handler,
                token_file=token_file,
            )
            for token in ("first-token", "rotated-token"):
                token_file.write_text(f"{token}\n", encoding="ascii")
                with self.assertRaises(SecretProviderClientError) as raised:
                    client.resolve(
                        workspace_id="workspace-1",
                        reference=SecretReference("secret://provider-a/missing"),
                        intent=SecretUseIntent.POSTGRES_PASSWORD,
                        caller_subject="interpreter",
                        correlation_id=f"resolve-{token}",
                    )
                self.assertNotIn(token, str(raised.exception))
                self.assertNotIn(str(token_file), repr(client))

        self.assertEqual(
            authorizations,
            ["Bearer first-token", "Bearer rotated-token"],
        )


class _ClientContext:
    def __init__(self, client: ControlPlaneKitSecretsClient, directory) -> None:
        self.client = client
        self.directory = directory

    def __enter__(self) -> ControlPlaneKitSecretsClient:
        return self.client

    def __exit__(self, *args: object) -> None:
        self.directory.cleanup()


def _client(
    handler,
    *,
    token: str = "provider-token",
    policy: SecretProviderClientPolicy | None = None,
    clock=None,
) -> _ClientContext:
    directory = tempfile.TemporaryDirectory()
    token_file = Path(directory.name) / "provider.token"
    token_file.write_text(f"{token}\n", encoding="ascii")
    return _ClientContext(
        _configured_client(
            handler,
            token_file=token_file,
            policy=policy,
            clock=clock,
        ),
        directory,
    )


def _configured_client(
    handler,
    *,
    token_file: Path,
    policy: SecretProviderClientPolicy | None = None,
    clock=None,
) -> ControlPlaneKitSecretsClient:
    endpoint = SecretProviderEndpointReference("provider-main")
    credential = SecretReference("secret://bootstrap/provider-token")
    registry = SecretProviderBootstrapRegistry(
        endpoints={endpoint: "https://provider.internal"},
        credential_files={credential: token_file},
    )
    return ControlPlaneKitSecretsClient(
        registry.configuration_for(
            endpoint_reference=endpoint,
            credential_reference=credential,
        ),
        policy=policy or SecretProviderClientPolicy(),
        transport=httpx.MockTransport(handler),
        **({"clock": clock} if clock is not None else {}),
    )


def _metadata(
    *,
    workspace_id: str,
    secret_id: str,
    status: str,
    revoked_at: str | None = None,
) -> dict[str, object]:
    return {
        "workspace_id": workspace_id,
        "secret_id": secret_id,
        "version_id": "version-1",
        "version_number": 1,
        "status": status,
        "algorithm": "AES-256-GCM",
        "key_fingerprint": "a" * 64,
        "key_version": "test",
        "labels": {"intent": "cloudflare.tunnel-token"},
        "created_at": "2026-07-30T00:00:00Z",
        "revoked_at": revoked_at,
    }


def _response(payload: object, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": "application/json"},
        json=payload,
    )


def _error(outcome: str, code: str) -> dict[str, object]:
    return {"detail": {"outcome": outcome, "code": code}}


if __name__ == "__main__":
    unittest.main()
