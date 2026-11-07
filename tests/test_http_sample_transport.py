"""Supplied signed inputs prove one transport/codec exchange, never admission."""
import asyncio
from dataclasses import replace
import importlib
import importlib.util
import json
import unittest

import httpx
import jwt
import control_plane_kit_core as core
from control_plane_kit_core.http_verification_samples import (
    HttpVerificationSampleRequest, HttpVerificationSampleGrant, HttpVerificationSampleResult,
    HttpVerificationSampleResultCodec, http_verification_check_digest,
)
from control_plane_kit_core.receiver_management_routes import ReceiverManagementRouteBinding
from control_plane_kit_core.public_ingress import IngressAuthorityReference, NamedPublicIngress, PublicIngressTarget
from control_plane_kit_core.verification import HttpCheck, HttpVerificationEvidence, VerificationOutcome
from health_signing_fixtures import key

MODULE = "control_plane_kit_interpreters.probes.http_sample_transport"


class Resolver:
    def __init__(self, *, delay=0):
        self.calls = []
        self.delay = delay

    async def resolve(self, hostname):
        self.calls.append(hostname)
        await asyncio.sleep(self.delay)
        return ("8.8.8.8",)


def inputs(api):
    """Real Core values and signatures; no authorization or secret provider."""
    roles = core.NodeControlGraphReferenceRole
    target = core.NodeControlReceiverTarget(*(core.NodeControlGraphReference(role, text) for role, text in (
        (roles.WORKSPACE, "workspace-a"), (roles.RUNTIME, "runtime-a"),
        (roles.NODE, "workload-a"), (roles.PROVIDER_SOCKET, "control"))), "a" * 32)
    gateway = replace(target, node_id=core.NodeControlGraphReference(roles.NODE, "gateway-a"), receiver_id="b" * 32)
    declaration = core.WorkloadNodeControlSurfaceDeclaration(
        core.WorkloadNodeControlSurfaceDescriptor(target.provider_socket_name, (),
            health_reads=(core.NodeHealthReadKind.LIVENESS,)),
        profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2)
    check = HttpCheck(check_id="ready", provider_socket="application", path="/ready")
    request = HttpVerificationSampleRequest(target=target,
        authority_context=core.NodeControlAuthorityContext("revision-a", "projection-a"),
        declaration_identity=declaration.identity().value, gateway_target=gateway,
        route_id="workload-management", run_id="run-a", activity_id="check-a", outer_attempt=1,
        effect_id="event-a", request_fingerprint="1" * 64, check_id=check.check_id,
        check_digest=http_verification_check_digest(check), sample_ordinal=1, request_id="sample-1")
    grants, tokens = [], []
    for role, purpose, audience, typ, claim in (
            ("transit", core.DelegationKeyPurpose.GATEWAY_HTTP_VERIFICATION_SAMPLE_TRANSIT,
                "gateway:workspace-a:gateway-a", "CPK-GATEWAY-HTTP-VERIFICATION-SAMPLE-TRANSIT+JWT", "gateway_http_verification_sample_transit"),
            ("workload", core.DelegationKeyPurpose.WORKLOAD_HTTP_VERIFICATION_SAMPLE,
                core.receiver_node_control_audience(target), "CPK-WORKLOAD-HTTP-VERIFICATION-SAMPLE+JWT", "workload_http_verification_sample")):
        private, public = key(role + "-key")
        grant = HttpVerificationSampleGrant(request=request, purpose=purpose, issuer=role + "-issuer",
            key_id=public.key_id, audience=audience, issued_at=90, not_before=90, expires_at=101, jti=role + "-sample-1")
        claims = dict(iss=grant.issuer, aud=grant.audience, iat=grant.issued_at, nbf=grant.not_before,
            exp=grant.expires_at, jti=grant.jti, **{claim: grant.descriptor()})
        tokens.append(jwt.encode(claims, private, algorithm="EdDSA", headers={"typ":typ, "kid":grant.key_id}).encode("ascii"))
        grants.append(grant)
    destination = api.SelectedHttpSampleGateway(
        NamedPublicIngress("management", IngressAuthorityReference("synthetic-authority"),
            PublicIngressTarget("gateway-a", "transit"), "connector-a", "gateway.example.invalid"),
        gateway, ReceiverManagementRouteBinding(request.route_id, target, declaration, "http://workload-a:8087"), "transit")
    credentials = api.SignedHttpSampleCredentials(tokens[0], tokens[1], grants[0], grants[1])
    return request, check, destination, credentials


def success(request, check):
    return HttpVerificationSampleResultCodec(request, check).encode_canonical_bytes(
        HttpVerificationSampleResult(request, VerificationOutcome.PASSED, HttpVerificationEvidence(200, 0)))


class HttpSampleTransportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec(MODULE), "signed sample sender/codec adapter is missing")
        self.api = importlib.import_module(MODULE)
        self.request, self.check, self.destination, self.credentials = inputs(self.api)
        self.resolver = Resolver()
        self.calls = []

    def client(self, status=200, body=None, *, delay=0, **options):
        async def handle(request):
            self.calls.append(request)
            await asyncio.sleep(delay)
            return httpx.Response(status, content=success(self.request, self.check) if body is None else body,
                headers={"Content-Type":"application/json"})
        return self.api.SignedGatewayHttpSampleClient(clock=lambda:100,
            public_resolver=self.resolver, transport=httpx.MockTransport(handle), **options)

    async def dispatch(self, client, **changes):
        return await client.dispatch(**(dict(request=self.request, check=self.check,
            destination=self.destination, credentials=self.credentials) | changes))

    async def test_one_signed_sender_request_decodes_against_original_check(self):
        result = await self.dispatch(self.client())
        self.assertEqual(result.code.value, "received")
        self.assertIs(result.result.outcome, VerificationOutcome.PASSED)
        self.assertEqual(result.result.request, self.request)
        self.assertEqual(len(self.calls), 1)
        outbound, = self.calls
        self.assertEqual((outbound.method, str(outbound.url)), ("POST", "https://8.8.8.8/cpk/verification/http"))
        self.assertEqual(outbound.headers["Host"], "gateway.example.invalid")
        self.assertEqual(outbound.headers["Authorization"], "Bearer " + self.credentials.transit.decode())
        self.assertEqual(json.loads(outbound.content), dict(profile="cpk-gateway-http-verification-sample-request.v1",
            target_id=self.request.route_id, request=self.request.descriptor(),
            workload_credential=self.credentials.workload.decode()))
        self.assertNotIn("workload-a:8087", str(outbound.url))

    async def test_mismatched_200_earns_no_sample_evidence(self):
        other = replace(self.request, request_id="other-sample")
        result = await self.dispatch(self.client(body=success(other, self.check)))
        self.assertEqual(result.code.value, "result-rejected")
        self.assertIsNone(result.result)
        self.assertEqual(len(self.calls), 1)

    async def test_unsupported_route_or_redirect_has_no_retry_or_private_fallback(self):
        for status in (404, 302):
            self.calls.clear()
            result = await self.dispatch(self.client(status=status, body=b"private-error-canary"))
            self.assertEqual(result.code.value, "relay-rejected")
            self.assertIsNone(result.result)
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0].url.path, "/cpk/verification/http")
            self.assertNotIn("private-error-canary", repr(result))

    async def test_wrong_selector_role_or_original_check_refuses_before_network(self):
        for changes in (dict(destination=replace(self.destination,
                route=replace(self.destination.route, target_id="other-route"))),
                dict(credentials=replace(self.credentials, transit=self.credentials.workload)),
                dict(check=replace(self.check, path="/other"))):
            result = await self.dispatch(self.client(), **changes)
            self.assertNotEqual(result.code.value, "received")
            self.assertIsNone(result.result)
            self.assertEqual(self.resolver.calls, [])
            self.assertEqual(self.calls, [])

    async def test_deadline_clipped_to_credential_window_is_not_application_timeout(self):
        self.resolver = Resolver(delay=0.05)
        client = self.client()
        client = replace(client, clock=lambda:100.99)
        result = await self.dispatch(client)
        self.assertEqual(result.code.value, "timed-out")
        self.assertIsNone(result.result)
        self.assertEqual(self.calls, [])
