"""One reached original HTTP check over authenticated gateway samples.

Operations owns preparation/admission/history. The composition translates its
reference-only result into these Core-valued inputs. No Operations import,
provider discovery, private workload fallback or durable truth lives here.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
import math
import time
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt

from control_plane_kit_core.delegation_keys import DelegationPublicKey, DelegationKeyAlgorithm, DelegationKeyPurpose
from control_plane_kit_core.http_verification_samples import (
    HttpVerificationSampleRequest, HttpVerificationSampleGrant, HttpVerificationSampleResultCodec,
)
from control_plane_kit_core.runtime_effects import RuntimeEffectRequest
from control_plane_kit_core.runtime_effect_observation import (
    runtime_effect_intent_for_request, runtime_effect_intent_fingerprint,
)
from control_plane_kit_core.receiver_identity import receiver_node_control_audience, NodeControlAuthorityContext
from control_plane_kit_core.public_ingress import NamedPublicIngressCodec, PublicIngressExposure
from control_plane_kit_core.products import ProductReference
from control_plane_kit_core.secrets import (
    SecretResolutionGrant, require_authorized_secret, http_verification_sample_signing_intent_for,
)
from control_plane_kit_core.verification import (
    HttpCheck, VerificationCompleted, VerificationIdentity, VerificationCapability, VerificationOutcome,
)
from control_plane_kit_interpreters.invocations import control_errors, invoke
from .http_sample_transport import (
    SignedGatewayHttpSampleClient, SignedHttpSampleCredentials, SelectedHttpSampleGateway, _destination,
)


class HttpSampleUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("authenticated HTTP sample is unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class HttpSampleSigningKey:
    issuer: str
    public_key: DelegationPublicKey
    resolution_grant: SecretResolutionGrant


@dataclass(frozen=True, slots=True, repr=False)
class HttpSampleCheckInput:
    request_template: HttpVerificationSampleRequest
    check: HttpCheck
    destination: SelectedHttpSampleGateway
    transit_key: HttpSampleSigningKey
    workload_key: HttpSampleSigningKey


@dataclass(frozen=True, slots=True, repr=False)
class HttpSampleRouteInput:
    """Actual owner's acquired public selection, before any signing-use rows."""
    destination: SelectedHttpSampleGateway
    checks: tuple[HttpCheck, ...]
    authority_context: NodeControlAuthorityContext
    workload_product: ProductReference


def _require(condition):
    if condition is not True:
        raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class HttpSampleCheckExecutor:
    authorized_secret_resolver: object
    client: SignedGatewayHttpSampleClient
    clock: object
    # Exact opaque identity is installed by the Operations/Servers composition.
    # It is never inferred from method names or imported from Operations here.
    http_sample_support: object

    def __post_init__(self):
        _require(type(self.client) is SignedGatewayHttpSampleClient and callable(self.clock)
                 and self.http_sample_support is not None
                 and callable(getattr(self.authorized_secret_resolver, "resolve", None)))

    def acquire(self, runtime_request, parent):
        """Read once inside the existing acquisition invocation, then validate."""
        controls = control_errors(parent, required=True)
        try:
            value = parent.acquire_http_sample_route()
            _require(type(runtime_request) is RuntimeEffectRequest and type(value) is HttpSampleRouteInput
                and len(runtime_request.products) == 1
                and type(value.destination) is SelectedHttpSampleGateway
                and type(value.checks) is tuple and len(value.checks) > 0
                and all(type(check) is HttpCheck for check in value.checks)
                and type(value.authority_context) is NodeControlAuthorityContext
                and type(value.workload_product) is ProductReference)
            runtime_effect_intent_for_request(runtime_request)
            material = runtime_request.products[0]
            target, gateway = value.destination.route.target, value.destination.gateway_target
            ingress = NamedPublicIngressCodec().decode(value.destination.ingress.descriptor())
            _require(value.workload_product == material.reference
                and value.checks == tuple(material.product.runtime_contract.verification.checks)
                and value.authority_context.authored_graph_id == runtime_request.source.desired_graph_id
                and (target.workspace_id.value, target.runtime_id.value, target.node_id.value)
                    == (runtime_request.source.workspace_id, material.runtime_id, runtime_request.operation.target.node_id)
                and gateway.workspace_id == target.workspace_id and gateway.runtime_id == target.runtime_id
                and ingress == value.destination.ingress and ingress.exposure is PublicIngressExposure.HTTPS
                and ingress.target.node_id == gateway.node_id.value
                and ingress.target.provider_socket == value.destination.transit_provider_socket_name)
            return value
        except controls:
            raise
        except Exception:
            failure = HttpSampleUnavailable()
        raise failure

    def execute(self, runtime_request, check, child, *, acquired):
        controls = control_errors(child, required=True)
        try:
            _require(type(runtime_request) is RuntimeEffectRequest and type(check) is HttpCheck)
            policy = check.policy
            deadline = time.monotonic() + (policy.maximum_attempts * policy.timeout_seconds
                + (policy.maximum_attempts - 1) * policy.interval_seconds)
            prepared = child.prepare_http_sample()
            self._context(prepared, runtime_request, check)
            _require(type(acquired) is HttpSampleRouteInput
                and prepared.destination == acquired.destination and check in acquired.checks
                and prepared.request_template.authority_context == acquired.authority_context)
            keys = (prepared.transit_key, prepared.workload_key)
            privates = []
            for selected in keys:
                private = invoke(child, "secret-resolution",
                    lambda: self._resolve(selected), authorization_id=selected.resolution_grant.authorization_id)
                privates.append(private)
                _require(time.monotonic() < deadline)
            # Both actual private fingerprints have been verified before either
            # token can be produced. Resolutions are not repeated per ordinal.
            def run():
                # The runtime arm is synchronous, including when hosted by the
                # async operator API. A single owned worker owns this client's
                # event loop and exits after the finite original-check budget.
                with ThreadPoolExecutor(max_workers=1, thread_name_prefix="cpk-http-sample") as worker:
                    return worker.submit(lambda: asyncio.run(self._samples(
                        prepared, tuple(privates), deadline))).result()
            return invoke(child, "ordinary-verification-check", run)
        except controls:
            raise
        except Exception:
            failure = HttpSampleUnavailable()
        raise failure

    def _context(self, value, runtime, check):
        _require(type(value) is HttpSampleCheckInput and value.check == check
                 and type(value.request_template) is HttpVerificationSampleRequest)
        request = value.request_template
        HttpVerificationSampleResultCodec(request, check)
        _require((request.target.workspace_id.value, request.run_id, request.activity_id,
                  request.effect_id, request.authority_context.authored_graph_id)
                 == (runtime.source.workspace_id, runtime.source.run_id.value, runtime.activity_id.value,
                     runtime.effect_id, runtime.source.desired_graph_id)
                 and request.target.node_id.value == runtime.operation.target.node_id)
        _require(len(runtime.products) == 1
                 and request.target.runtime_id.value == runtime.products[0].runtime_id
                 and request.request_fingerprint == runtime_effect_intent_fingerprint(
                     runtime_effect_intent_for_request(runtime)))
        purposes = (DelegationKeyPurpose.GATEWAY_HTTP_VERIFICATION_SAMPLE_TRANSIT,
                    DelegationKeyPurpose.WORKLOAD_HTTP_VERIFICATION_SAMPLE)
        for key, purpose in zip((value.transit_key, value.workload_key), purposes):
            _require(type(key) is HttpSampleSigningKey and type(key.public_key) is DelegationPublicKey
                and replace(key.public_key) == key.public_key
                and key.public_key.algorithm is DelegationKeyAlgorithm.ED25519
                and type(key.resolution_grant) is SecretResolutionGrant)
            grant = key.resolution_grant
            _require(replace(grant) == grant and grant.intent is http_verification_sample_signing_intent_for(purpose)
                and (grant.workspace_id, grant.run_id, grant.activity_id, grant.effect_id)
                    == (runtime.source.workspace_id, request.run_id, request.activity_id, request.effect_id))
        left, right = value.transit_key, value.workload_key
        _require(left.public_key.fingerprint_sha256 != right.public_key.fingerprint_sha256
            and left.resolution_grant.reference != right.resolution_grant.reference
            and left.resolution_grant.authorization_id != right.resolution_grant.authorization_id
            and left.resolution_grant.correlation_id != right.resolution_grant.correlation_id)
        # Validate the selected public route before touching either secret. This
        # uses only unsigned Core grants; no compact token is emitted here.
        grants = self._grants(value, request, min(1, check.policy.timeout_seconds))
        _destination(value.destination, request, SignedHttpSampleCredentials(b"", b"", *grants))

    def _resolve(self, selected):
        material = require_authorized_secret(self.authorized_secret_resolver, selected.resolution_grant)
        private = serialization.load_pem_private_key(material.reveal().encode("ascii"), password=None)
        _require(isinstance(private, Ed25519PrivateKey))
        derived = DelegationPublicKey(selected.public_key.key_id, DelegationKeyAlgorithm.ED25519,
            private.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"))
        _require(derived.fingerprint_sha256 == selected.public_key.fingerprint_sha256)
        return private

    def _grants(self, value, request, remaining):
        now = self.clock()
        _require(type(now) in (int, float) and math.isfinite(now) and 0 <= now <= 2**53 - 2)
        issued, expires = math.floor(now), math.floor(now + min(5, remaining))
        # JWT epochs are integral. Never round the authority window beyond the
        # available original probe budget; refuse if no future epoch fits.
        _require(expires > now)
        return tuple(HttpVerificationSampleGrant(request=request, purpose=purpose,
            issuer=key.issuer, key_id=key.public_key.key_id, audience=audience,
            issued_at=issued, not_before=issued, expires_at=expires, jti=uuid4().hex)
            for key, purpose, audience in (
                (value.transit_key, DelegationKeyPurpose.GATEWAY_HTTP_VERIFICATION_SAMPLE_TRANSIT,
                 f"gateway:{request.gateway_target.workspace_id.value}:{request.gateway_target.node_id.value}"),
                (value.workload_key, DelegationKeyPurpose.WORKLOAD_HTTP_VERIFICATION_SAMPLE,
                 receiver_node_control_audience(request.target))))

    async def _samples(self, value, privates, deadline):
        check = value.check
        loop_deadline = asyncio.get_running_loop().time() + max(0, deadline - time.monotonic())
        async with asyncio.timeout_at(loop_deadline):
            for ordinal in range(1, check.policy.maximum_attempts + 1):
                if ordinal > 1:
                    await asyncio.sleep(check.policy.interval_seconds)
                remaining = deadline - time.monotonic()
                _require(remaining > 0)
                request = replace(value.request_template, sample_ordinal=ordinal, request_id=uuid4().hex)
                grants = self._grants(value, request, min(remaining, check.policy.timeout_seconds))
                tokens = tuple(jwt.encode(dict(iss=grant.issuer, aud=grant.audience,
                    iat=grant.issued_at, nbf=grant.not_before, exp=grant.expires_at, jti=grant.jti,
                    **{claim: grant.descriptor()}), private, algorithm="EdDSA",
                    headers={"typ": typ, "kid": grant.key_id}).encode("ascii")
                    for grant, private, typ, claim in zip(grants, privates,
                        ("CPK-GATEWAY-HTTP-VERIFICATION-SAMPLE-TRANSIT+JWT", "CPK-WORKLOAD-HTTP-VERIFICATION-SAMPLE+JWT"),
                        ("gateway_http_verification_sample_transit", "workload_http_verification_sample")))
                received = await self.client.dispatch(request=request, check=check, destination=value.destination,
                    credentials=SignedHttpSampleCredentials(*tokens, *grants))
                _require(received.code.value == "received" and received.result is not None)
                result = received.result
                if result.outcome is VerificationOutcome.PASSED or ordinal == check.policy.maximum_attempts:
                    return VerificationCompleted(VerificationIdentity(request.target.node_id.value,
                        request.authority_context.authored_graph_id, check.check_id), VerificationCapability.HTTP,
                        result.outcome, ordinal, result.evidence)
