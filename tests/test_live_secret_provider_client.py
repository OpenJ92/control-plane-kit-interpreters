from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import httpx

from control_plane_kit_core.secrets import (
    SecretProviderEndpointReference,
    SecretReference,
    SecretResolutionGrant,
    SecretResolved,
    SecretUseIntent,
    SecretValue,
)
from control_plane_kit_interpreters.secret_provider import (
    ControlPlaneKitSecretsClient,
    ControlPlaneKitSecretsResolver,
    SecretProviderBootstrapRegistry,
    SecretProviderClientCode,
    SecretProviderClientError,
    canonical_provider_secret_id,
)
from control_plane_kit_secrets.audit import SqliteAuditStore
from control_plane_kit_secrets.crypto import encode_master_key_for_file


class LiveSecretProviderClientTests(unittest.TestCase):
    def test_write_resolve_revoke_and_audit_correlation_through_real_provider(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            database = base / "secrets.sqlite3"
            key_file = base / "master.key"
            key_file.write_text(
                encode_master_key_for_file(os.urandom(32)),
                encoding="utf-8",
            )
            key_file.chmod(0o600)
            token = "live-provider-client-token"
            token_file = base / "provider.token"
            token_file.write_text(f"{token}\n", encoding="ascii")
            token_file.chmod(0o600)
            credentials_file = base / "provider-credentials.json"
            credentials_file.write_text(
                json.dumps(
                    [
                        {
                            "subject": "interpreter-client",
                            "token": token,
                            "grants": [
                                {
                                    "action": "secret.write",
                                    "workspace_id": "workspace-1",
                                },
                                {
                                    "action": "secret.resolve",
                                    "workspace_id": "workspace-1",
                                    "intents": ["cloudflare.tunnel-token"],
                                },
                                {
                                    "action": "secret.revoke",
                                    "workspace_id": "workspace-1",
                                },
                            ],
                        }
                    ],
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            credentials_file.chmod(0o600)
            port = _free_port()
            environment = {
                **os.environ,
                "CPK_SECRETS_DATABASE_PATH": str(database),
                "CPK_SECRETS_MASTER_KEY_FILE": str(key_file),
                "CPK_SECRETS_PROVIDER_ID": "provider-live",
                "CPK_SECRETS_CREDENTIALS_FILE": str(credentials_file),
            }
            process = _start_provider(port=port, environment=environment)
            stdout = ""
            stderr = ""
            try:
                _wait_ready(port)
                endpoint = SecretProviderEndpointReference("provider-live")
                credential = SecretReference("secret://bootstrap/provider-token")
                registry = SecretProviderBootstrapRegistry(
                    endpoints={endpoint: f"http://127.0.0.1:{port}"},
                    credential_files={credential: token_file},
                )
                client = ControlPlaneKitSecretsClient(
                    registry.configuration_for(
                        endpoint_reference=endpoint,
                        credential_reference=credential,
                    )
                )
                reference = SecretReference(
                    "secret://provider-live/cloudflare/generated/tunnel/token"
                )
                value = SecretValue("generated-tunnel-token-value")
                resolver = ControlPlaneKitSecretsResolver(registry)

                written = client.write(
                    workspace_id="workspace-1",
                    reference=reference,
                    value=value,
                    intent=SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
                    caller_subject="cloudflare-interpreter",
                    correlation_id="ingress-create-1",
                )
                grant_resolved = resolver.resolve(
                    SecretResolutionGrant(
                        authorization_id="suse_" + "a" * 64,
                        workspace_id="workspace-1",
                        reference_registration_id="sref_" + "b" * 64,
                        provider_registration_id="sprov_" + "c" * 64,
                        endpoint_reference=endpoint,
                        credential_reference=credential,
                        reference=reference,
                        intent=SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
                        actor_subject="docker-interpreter",
                        correlation_id="grant-resolver-1",
                        intent_fingerprint="d" * 64,
                        run_id="run-1",
                        activity_id="activity-1",
                        effect_id="effect-1",
                    )
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
                    correlation_id="ingress-compensate-1",
                )
                with self.assertRaises(SecretProviderClientError) as raised:
                    client.resolve(
                        workspace_id="workspace-1",
                        reference=reference,
                        intent=SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN,
                        caller_subject="docker-interpreter",
                        correlation_id="connector-retry-1",
                    )

                self.assertEqual(written.reference, reference)
                self.assertIsInstance(grant_resolved, SecretResolved)
                assert isinstance(grant_resolved, SecretResolved)
                self.assertEqual(
                    grant_resolved.value.reveal(),
                    "generated-tunnel-token-value",
                )
                self.assertEqual(
                    resolved.value.reveal(),
                    "generated-tunnel-token-value",
                )
                self.assertEqual(revoked.reference, reference)
                self.assertIs(
                    raised.exception.code,
                    SecretProviderClientCode.REVOKED,
                )
                self.assertEqual(
                    written.version_id,
                    resolved.metadata.version_id,
                )
                self.assertTrue(
                    canonical_provider_secret_id(reference).startswith("cpk1_")
                )
            finally:
                stdout, stderr = _stop_provider(process)

            rows = SqliteAuditStore(database).rows_for_tests()
            correlations = {
                (row["outcome"], row["correlation_id"])
                for row in rows
            }
            self.assertIn(("stored", "ingress-create-1"), correlations)
            self.assertIn(("resolved", "grant-resolver-1"), correlations)
            self.assertIn(("resolved", "connector-start-1"), correlations)
            self.assertIn(("revoked", "ingress-compensate-1"), correlations)
            self.assertIn(("revoked", "connector-retry-1"), correlations)
            leak_surface = "\n".join((stdout, stderr, repr(rows)))
            self.assertNotIn("generated-tunnel-token-value", leak_surface)
            self.assertNotIn(token, leak_surface)
            self.assertNotIn(token, repr(client))
            self.assertNotIn(str(token_file), repr(client))


def _start_provider(*, port: int, environment: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "control_plane_kit_secrets.server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )


def _stop_provider(process: subprocess.Popen[str]) -> tuple[str, str]:
    process.terminate()
    try:
        return process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.communicate(timeout=10)


def _wait_ready(port: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            response = httpx.get(
                f"http://127.0.0.1:{port}/health/ready",
                timeout=1,
            )
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.1)
    raise AssertionError("provider did not become ready")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


if __name__ == "__main__":
    unittest.main()
