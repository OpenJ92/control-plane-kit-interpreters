"""Native runtime branch and signed sampler, without Operations state emulation."""
import asyncio
from dataclasses import replace
from types import SimpleNamespace
import json
import unittest
from unittest.mock import patch

import httpx
import jwt
import control_plane_kit_core as core
from control_plane_kit_core.http_verification_samples import (
    HttpVerificationSampleResult, http_verification_check_digest,
    HttpVerificationSampleRequestCodec,
)
from control_plane_kit_core.operations.execution import EffectResultKind
from control_plane_kit_core.planning import NodeTarget, WaitForHealthy
from control_plane_kit_core.secrets import SecretResolved, SecretValue, http_verification_sample_signing_intent_for
from control_plane_kit_core.verification import (
    VerificationOutcome, HttpVerificationEvidence, VerificationPolicy, VerificationContract,
)
from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter
from control_plane_kit_interpreters.invocations import InvocationPortError
from control_plane_kit_interpreters.probes import http_sample_transport as transport_api
from control_plane_kit_interpreters.probes.http_sample_check import (
    HttpSampleCheckExecutor, HttpSampleCheckInput, HttpSampleSigningKey,
)
from health_signing_fixtures import fixture, private_pem
from test_health_invocations import RecordingPort
from test_http_sample_transport import inputs
from test_docker_runtime_interpreter import _product_with_health_check, _material, _request


class NativeHttpSampleTests(unittest.TestCase):
    def setUp(self):
        self.events, self.posts, self.resolved = [], [], []
        self.support = object()  # Identity supplied by composition, never authority.
        product = _product_with_health_check(policy=VerificationPolicy(
            timeout_seconds=1, interval_seconds=0, maximum_attempts=2))
        check, = product.runtime_contract.verification.checks
        self.runtime = _request(WaitForHealthy(NodeTarget("api")), products=(_material(product),))
        original, _, destination, _ = inputs(transport_api)
        target = replace(original.target, node_id=replace(original.target.node_id, value="api"),
                         runtime_id=replace(original.target.runtime_id, value="docker"))
        gateway = replace(original.gateway_target, runtime_id=target.runtime_id)
        template = replace(original, target=target, gateway_target=gateway,
            authority_context=core.NodeControlAuthorityContext("graph-desired", "projection-a"),
            activity_id="activity-a", effect_id="event-started", check_digest=http_verification_check_digest(check))
        destination = replace(destination, gateway_target=gateway, route=replace(destination.route, target=target))
        values = fixture()
        purposes = (core.DelegationKeyPurpose.GATEWAY_HTTP_VERIFICATION_SAMPLE_TRANSIT,
                    core.DelegationKeyPurpose.WORKLOAD_HTTP_VERIFICATION_SAMPLE)
        grants = tuple(replace(grant, intent=http_verification_sample_signing_intent_for(purpose),
            activity_id=template.activity_id, effect_id=template.effect_id)
            for grant, purpose in zip(values.resolutions, purposes))
        self.keys = tuple(HttpSampleSigningKey("sample-controller", public, grant)
                          for public, grant in zip(values.publics, grants))
        self.prepared = HttpSampleCheckInput(template, check, destination, *self.keys)
        self.secrets = dict(zip((grant.authorization_id for grant in grants),
                               (private_pem(private) for private in values.privates)))
        self.publics = values.publics
        owner = self
        class Resolver:
            def resolve(self, grant):
                owner.resolved.append(grant.authorization_id)
                return SecretResolved(grant.reference, SecretValue(owner.secrets[grant.authorization_id]))
        class PublicResolver:
            async def resolve(self, _hostname):
                return ("8.8.8.8",)
        self.outcomes = [VerificationOutcome.FAILED, VerificationOutcome.PASSED]
        async def gateway(request):
            body = json.loads(await request.aread())
            g = request.headers["authorization"][7:]
            w = body["workload_credential"]
            verified = []
            for token, public, claim in zip((g, w), self.publics,
                    ("gateway_http_verification_sample_transit", "workload_http_verification_sample")):
                payload = jwt.decode(token, public.public_key_pem, algorithms=["EdDSA"],
                    options={"verify_exp": False, "verify_iat": False, "verify_nbf": False, "verify_aud": False})
                verified.append(payload[claim]["request"] == body["request"])
            self.posts.append((body["request"]["sample_ordinal"], body["request"]["request_id"], all(verified)))
            r = HttpVerificationSampleRequestCodec().decode(body["request"])
            outcome = self.outcomes.pop(0)
            result = HttpVerificationSampleResult(r, outcome, HttpVerificationEvidence(200 if outcome is VerificationOutcome.PASSED else 503, 0))
            return httpx.Response(200, content=result.canonical_bytes(installed_check=check),
                                  headers={"content-type": "application/json"})
        self.client = transport_api.SignedGatewayHttpSampleClient(clock=lambda: 100,
            public_resolver=PublicResolver(), transport=httpx.MockTransport(gateway))
        self.executor = HttpSampleCheckExecutor(Resolver(), self.client, lambda: 100, self.support)
        self.child = RecordingPort(self.events)
        self.child.prepare_http_sample = lambda: self.prepared
        self.parent = RecordingPort(self.events)
        self.parent.http_sample_support = self.support
        self.parent.for_check = lambda _check: self.child
        self.interpreter = DockerRuntimeInterpreter(client=SimpleNamespace(),
            http_sample_executor=self.executor, require_invocations=True)

    def execute(self):
        with patch.object(DockerRuntimeInterpreter, "_runtime_private_endpoint_observations") as private, \
                patch.object(DockerRuntimeInterpreter, "_execute_runtime_private_http_health_check") as helper:
            result = self.interpreter.execute(self.runtime, invocations=self.parent)
            private.assert_not_called()
            helper.assert_not_called()
            return result

    def test_actual_sender_retries_only_original_application_result_with_one_pair_resolution(self):
        result = self.execute()
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(self.resolved, [key.resolution_grant.authorization_id for key in self.keys])
        self.assertEqual([(ordinal, valid) for ordinal, _, valid in self.posts], [(1, True), (2, True)])
        self.assertNotEqual(self.posts[0][1], self.posts[1][1])
        observation, = result.observations
        self.assertIs(observation.outcome, VerificationOutcome.PASSED)
        self.assertEqual(observation.attempts, 2)
        self.assertEqual(observation.identity.node_id, "api")
        self.assertEqual(self.events[-1], ("record", "ordinary-verification-check", None, "returned"))
        self.assertEqual(sum(item[:2] == ("admit", "ordinary-verification-check") for item in self.events), 1)

    def test_both_private_fingerprints_checked_before_either_token_emission(self):
        self.secrets[self.keys[1].resolution_grant.authorization_id] = self.secrets[self.keys[0].resolution_grant.authorization_id]
        with patch("control_plane_kit_interpreters.probes.http_sample_check.jwt.encode") as encode:
            result = self.execute()
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(result.observations, ())
        self.assertEqual(len(self.resolved), 2)
        self.assertEqual(self.posts, [])
        encode.assert_not_called()

    def test_missing_or_swapped_sample_capability_has_no_private_fallback_or_resolution(self):
        for sampler in (None, replace(self.executor, http_sample_support=object())):
            self.interpreter = replace(self.interpreter, http_sample_executor=sampler)
            with self.assertRaises(InvocationPortError):
                self.execute()
        self.assertEqual(self.resolved, [])
        self.assertEqual(self.posts, [])

    def test_transport_refusal_is_uncertain_without_application_observation(self):
        self.executor = replace(self.executor, client=replace(self.client,
            transport=httpx.MockTransport(lambda _: httpx.Response(502, content=b"peer-secret"))))
        self.interpreter = replace(self.interpreter, http_sample_executor=self.executor)
        result = self.execute()
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(result.observations, ())
        self.assertEqual(self.events[-1], ("record", "ordinary-verification-check", None, "unknown"))
        self.assertNotIn("peer-secret", str(result.descriptor()))

    def test_synchronous_runtime_arm_works_under_an_active_operator_event_loop(self):
        self.outcomes = [VerificationOutcome.PASSED]
        async def operator():
            return self.execute()
        self.assertIs(asyncio.run(operator()).kind, EffectResultKind.SUCCEEDED)

    def test_original_attempt_timeout_and_interval_both_contribute_to_overall_budget(self):
        check = replace(self.prepared.check, policy=VerificationPolicy(
            timeout_seconds=0.1, interval_seconds=0.2, maximum_attempts=2))
        product = self.runtime.products[0].product
        material = replace(self.runtime.products[0], product=replace(product,
            runtime_contract=replace(product.runtime_contract, verification=VerificationContract((check,)))))
        self.runtime = replace(self.runtime, products=(material,))
        self.prepared = replace(self.prepared, check=check, request_template=replace(
            self.prepared.request_template, check_digest=http_verification_check_digest(check)))
        # The controlled peer encodes using the original check object captured
        # above; its wire policy must agree with the currently selected check.
        async def gateway(request):
            body = json.loads(await request.aread())
            r = HttpVerificationSampleRequestCodec().decode(body["request"])
            self.posts.append((r.sample_ordinal, r.request_id, True))
            outcome = self.outcomes.pop(0)
            result = HttpVerificationSampleResult(r, outcome,
                HttpVerificationEvidence(200 if outcome is VerificationOutcome.PASSED else 503, 0))
            return httpx.Response(200, content=result.canonical_bytes(installed_check=check),
                                  headers={"content-type": "application/json"})
        self.executor = replace(self.executor, client=replace(self.client, transport=httpx.MockTransport(gateway)))
        self.interpreter = replace(self.interpreter, http_sample_executor=self.executor)
        self.assertIs(self.execute().kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(len(self.posts), 2)
