from __future__ import annotations

import json
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import jwt

from control_plane_kit_core.gateway_delegation import (
    DelegatedGatewayProbeGrant,
    GatewayProbeCommandKind,
    GatewayProbeRequest,
)
from control_plane_kit_core.probe_intents import (
    EndpointContext,
    LiteralEndpointMaterial,
    RuntimeEndpointObservation,
)
from control_plane_kit_core.runtime_effects import GatewayTargetId
from control_plane_kit_core.secrets import (
    LocalDevelopmentSecretResolver,
    SecretProviderAuthority,
    SecretProviderId,
    SecretReference,
)
from control_plane_kit_core.types import Protocol

from control_plane_kit_interpreters.probes import (
    Ed25519GatewayProbeSigner,
    GatewayProbeClientCode,
    GatewayProbeClientError,
    ProbeAddressPolicy,
    ProbeSecurityError,
    SignedGatewayProbeClient,
)


class GatewayProbeClientTests(unittest.TestCase):
    def setUp(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        self.private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        self.public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.reference = SecretReference("secret://test/gateway/signing-key")
        self.resolver = LocalDevelopmentSecretResolver(
            SecretProviderAuthority(
                SecretProviderId("test"),
                (("gateway",),),
            ),
            {self.reference.reference_id: self.private_pem},
        )
        self.signer = Ed25519GatewayProbeSigner(self.reference, self.resolver)
        self.request = GatewayProbeRequest(
            GatewayProbeCommandKind.HTTP_STATUS,
            GatewayTargetId("hello.internal"),
            "/health/ready",
        )
        issued_at = int(time.time()) - 1
        self.grant = DelegatedGatewayProbeGrant(
            issuer="urn:cpk:test",
            key_id="gateway-key-a",
            audience="gateway:workspace-a:gateway-a",
            workspace_id="workspace-a",
            operation_id="probe-a",
            request_id="request-a",
            gateway_node_id="gateway-a",
            probe_kind=self.request.kind,
            target_id=self.request.target_id,
            request_digest=self.request.canonical_digest(),
            issued_at=issued_at,
            expires_at=issued_at + 60,
            jti="jti-a",
        )
        self.endpoint = RuntimeEndpointObservation(
            subject_id="gateway-a",
            socket_name="control",
            graph_id="graph-a",
            protocol=Protocol.HTTP,
            context=EndpointContext.RUNTIME_PRIVATE,
            address=LiteralEndpointMaterial("http://gateway-a:8000"),
        )
        self.policy = ProbeAddressPolicy(
            runtime_private_authorities=frozenset({"http://gateway-a:8000"})
        )

    def test_signs_exact_grant_and_posts_canonical_request(self) -> None:
        observed: dict[str, object] = {}

        def handler(inbound: httpx.Request) -> httpx.Response:
            observed["method"] = inbound.method
            observed["url"] = str(inbound.url)
            observed["body"] = json.loads(inbound.content)
            authorization = inbound.headers["authorization"]
            observed["scheme"] = authorization.split(" ", maxsplit=1)[0]
            token = authorization.split(" ", maxsplit=1)[1]
            observed["claims"] = jwt.decode(
                token,
                self.public_pem,
                algorithms=["EdDSA"],
                audience=self.grant.audience,
                issuer=self.grant.issuer,
            )
            observed["headers"] = jwt.get_unverified_header(token)
            return httpx.Response(
                200,
                json={
                    "outcome": "passed",
                    "target_id": "hello.internal",
                    "probe": "http-status",
                    "status": 200,
                    "body_size": 4,
                },
            )

        result = self.client(handler).dispatch(
            self.grant,
            self.request,
            self.endpoint,
        )

        self.assertIs(result.code, GatewayProbeClientCode.SUCCEEDED)
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["url"], "http://gateway-a:8000/cpk/probes")
        self.assertEqual(observed["body"], self.request.descriptor())
        self.assertEqual(observed["scheme"], "CPK-Gateway")
        self.assertEqual(observed["claims"]["gateway_probe"], self.grant.descriptor())
        self.assertEqual(observed["headers"]["kid"], self.grant.key_id)
        self.assertEqual(observed["headers"]["typ"], "CPK-GATEWAY-PROBE+JWT")
        self.assertEqual(
            result.evidence,
            {
                "body_size": 4,
                "http_status": 200,
                "outcome": "passed",
                "probe": "http-status",
                "target_id": "hello.internal",
            },
        )

    def test_rejects_untrusted_endpoint_and_request_substitution_before_io(self) -> None:
        calls = 0

        def handler(inbound: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(200, json={})

        client = self.client(handler)
        untrusted = RuntimeEndpointObservation(
            "gateway-a",
            "control",
            "graph-a",
            Protocol.HTTP,
            EndpointContext.RUNTIME_PRIVATE,
            LiteralEndpointMaterial("http://evil:8000"),
        )
        with self.assertRaises(ProbeSecurityError):
            client.dispatch(self.grant, self.request, untrusted)
        changed = GatewayProbeRequest(
            GatewayProbeCommandKind.HTTP_STATUS,
            GatewayTargetId("hello.internal"),
            "/different",
        )
        with self.assertRaises(GatewayProbeClientError):
            client.dispatch(self.grant, changed, self.endpoint)

        self.assertEqual(calls, 0)

    def test_redirect_timeout_oversize_and_malformed_results_are_closed(self) -> None:
        cases = (
            (
                lambda request: httpx.Response(
                    302,
                    headers={"location": "http://evil.test"},
                ),
                GatewayProbeClientCode.MALFORMED_RESPONSE,
            ),
            (
                lambda request: (_ for _ in ()).throw(
                    httpx.ReadTimeout("timed out", request=request)
                ),
                GatewayProbeClientCode.TIMED_OUT,
            ),
            (
                lambda request: httpx.Response(200, content=b"x" * 200),
                GatewayProbeClientCode.OVERSIZED_RESPONSE,
            ),
            (
                lambda request: httpx.Response(200, content=b"not-json"),
                GatewayProbeClientCode.MALFORMED_RESPONSE,
            ),
            (
                lambda request: httpx.Response(
                    200,
                    json={
                        "outcome": "passed",
                        "target_id": "wrong.internal",
                        "probe": "http-status",
                    },
                ),
                GatewayProbeClientCode.MALFORMED_RESPONSE,
            ),
        )

        for handler, expected in cases:
            with self.subTest(expected=expected):
                client = SignedGatewayProbeClient(
                    self.signer,
                    self.policy,
                    transport=httpx.MockTransport(handler),
                    maximum_response_bytes=128,
                )
                result = client.dispatch(self.grant, self.request, self.endpoint)
                self.assertIs(result.code, expected)
                self.assertNotIn("evil.test", repr(result))

    def test_rejected_response_and_secret_failures_are_bounded_and_redacted(self) -> None:
        rejected = self.client(
            lambda request: httpx.Response(403, json={"detail": self.private_pem})
        ).dispatch(self.grant, self.request, self.endpoint)

        self.assertIs(rejected.code, GatewayProbeClientCode.REJECTED)
        self.assertEqual(rejected.evidence, {"http_status": 403})
        self.assertNotIn(self.private_pem, repr(rejected))
        self.assertNotIn(self.private_pem, repr(self.signer))
        self.assertNotIn(self.private_pem, repr(self.client(lambda request: None)))

        missing = Ed25519GatewayProbeSigner(
            SecretReference("secret://test/gateway/missing"),
            self.resolver,
        )
        with self.assertRaises(GatewayProbeClientError) as raised:
            SignedGatewayProbeClient(
                missing,
                self.policy,
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, json={})
                ),
            ).dispatch(self.grant, self.request, self.endpoint)
        self.assertNotIn("missing", str(raised.exception))
        self.assertNotIn(self.private_pem, str(raised.exception))

    def client(self, handler) -> SignedGatewayProbeClient:
        return SignedGatewayProbeClient(
            self.signer,
            self.policy,
            transport=httpx.MockTransport(handler),
        )


if __name__ == "__main__":
    unittest.main()
