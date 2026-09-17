"""Immediate-use health credentials from a caller's admitted, committed inputs.

The caller must reload current authority and leave its transaction before calling
this effect. These values check congruence, not authorization, approval or replay.
This module neither sends target requests nor records durable observations.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields, replace

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from control_plane_kit_core.delegation_keys import DelegationKeyAlgorithm, DelegationPublicKey
from control_plane_kit_core.node_control import (
    NodeControlGraphReference, workload_node_control_audience,
)
from control_plane_kit_core.node_control_surface_reads import (
    WorkloadNodeControlSurfaceDeclaration, WorkloadNodeControlSurfaceDeclarationCodec,
)
from control_plane_kit_core.node_health_reads import (
    DelegatedWorkloadNodeHealthReadGrant, DelegatedWorkloadNodeHealthReadGrantCodec,
    NodeHealthReadRequest, NodeHealthReadRequestCodec, verify_workload_node_health_read_grant,
)
from control_plane_kit_core.node_health_transit import (
    DelegatedGatewayNodeHealthReadTransitGrant, DelegatedGatewayNodeHealthReadTransitGrantCodec,
    verify_gateway_node_health_read_transit_grant,
)
from control_plane_kit_core.secrets import (
    AuthorizedSecretResolver, SecretProviderEndpointReference, SecretReference,
    SecretResolutionGrant, SecretUseIntent, require_authorized_secret,
)


class HealthCredentialSigningError(RuntimeError):
    """Fixed refusal that carries no input, provider payload or partial result."""


@dataclass(frozen=True, slots=True, repr=False)
class HealthSigningContext:
    """Independent caller context; construction alone proves no current authority."""
    request: NodeHealthReadRequest
    attempt_id: str
    gateway_node_id: NodeControlGraphReference
    declaration: WorkloadNodeControlSurfaceDeclaration
    transit_issuer: str
    workload_issuer: str

    def __repr__(self) -> str:
        return "HealthSigningContext(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class HealthSigningKey:
    public_key: DelegationPublicKey
    resolution_grant: SecretResolutionGrant

    def __repr__(self) -> str:
        return "HealthSigningKey(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SignedHealthCredentialPair:
    """Ephemeral complete output; never place credentials in history or descriptors."""
    request: NodeHealthReadRequest
    transit_credential: bytes
    workload_credential: bytes

    def __repr__(self) -> str:
        return "SignedHealthCredentialPair(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class Ed25519HealthCredentialPairSigner:
    authorized_secret_resolver: AuthorizedSecretResolver
    clock: Callable[[], int]

    def sign(self, context: HealthSigningContext, *,
             transit_grant: DelegatedGatewayNodeHealthReadTransitGrant,
             workload_grant: DelegatedWorkloadNodeHealthReadGrant,
             transit_key: HealthSigningKey, workload_key: HealthSigningKey,
             ) -> SignedHealthCredentialPair:
        """Validate both families, then resolve/sign once without renewing either.

        Provider/crypto failures can follow a successful first read. Nothing is
        retried or returned partially. Python memory erasure is not guaranteed.
        """
        try:
            context = _context(context)
            transit_grant = _canonical(transit_grant, DelegatedGatewayNodeHealthReadTransitGrant,
                DelegatedGatewayNodeHealthReadTransitGrantCodec())
            workload_grant = _canonical(workload_grant, DelegatedWorkloadNodeHealthReadGrant,
                DelegatedWorkloadNodeHealthReadGrantCodec())
            transit_key, workload_key = _key(transit_key), _key(workload_key)
            _pair(context, transit_grant, workload_grant, transit_key, workload_key)
            now = _now(self.clock)
            expected = dict(expected_target=context.request.target,
                expected_runtime_id=context.request.runtime_id,
                expected_declaration=context.declaration, expected_kind=context.request.kind, now=now)
            if not verify_gateway_node_health_read_transit_grant(transit_grant, context.request,
                    expected_issuer=context.transit_issuer, expected_key_id=transit_key.public_key.key_id,
                    expected_attempt_id=context.attempt_id, expected_gateway_node_id=context.gateway_node_id,
                    **expected).is_accepted:
                raise ValueError
            if not verify_workload_node_health_read_grant(workload_grant, context.request,
                    expected_issuer=context.workload_issuer, expected_key_id=workload_key.public_key.key_id,
                    expected_audience=workload_node_control_audience(context.request.target),
                    **expected).is_accepted:
                raise ValueError

            transit_private = _resolve(self.authorized_secret_resolver, transit_key)
            _window(self.clock, transit_grant, workload_grant)
            workload_private = _resolve(self.authorized_secret_resolver, workload_key)
            _window(self.clock, transit_grant, workload_grant)
            transit = _encode(transit_grant, transit_private,
                "CPK-GATEWAY-NODE-HEALTH-READ-TRANSIT+JWT", "gateway_node_health_read_transit")
            _window(self.clock, transit_grant, workload_grant)
            workload = _encode(workload_grant, workload_private,
                "CPK-WORKLOAD-NODE-HEALTH-READ+JWT", "workload_node_health_read")
            _window(self.clock, transit_grant, workload_grant)
            return SignedHealthCredentialPair(context.request, transit, workload)
        except Exception:
            # This public effect boundary also redacts unexpected provider/crypto
            # payloads. Raise after the handler so __context__ is absent as well.
            failure = HealthCredentialSigningError("health credential signing failed")
        raise failure

    def __repr__(self) -> str:
        return "Ed25519HealthCredentialPairSigner(<redacted>)"


def _canonical(value, expected_type, codec):
    if type(value) is not expected_type:
        raise ValueError
    copied = codec.decode(value.descriptor())
    if copied != value:
        raise ValueError
    return copied


def _context(value: HealthSigningContext) -> HealthSigningContext:
    if type(value) is not HealthSigningContext:
        raise ValueError
    if any(type(text) is not str for text in (value.attempt_id, value.transit_issuer, value.workload_issuer)):
        raise ValueError
    gateway = value.gateway_node_id
    if type(gateway) is not NodeControlGraphReference or replace(gateway) != gateway:
        raise ValueError
    return replace(value, gateway_node_id=replace(gateway),
        request=_canonical(value.request, NodeHealthReadRequest, NodeHealthReadRequestCodec()),
        declaration=_canonical(value.declaration, WorkloadNodeControlSurfaceDeclaration,
            WorkloadNodeControlSurfaceDeclarationCodec()))


def _key(value: HealthSigningKey) -> HealthSigningKey:
    if type(value) is not HealthSigningKey:
        raise ValueError
    public, resolution = value.public_key, value.resolution_grant
    if (type(public) is not DelegationPublicKey or public.algorithm is not DelegationKeyAlgorithm.ED25519
            or any(type(text) is not str for text in (public.key_id, public.public_key_pem, public.fingerprint_sha256))
            or replace(public) != public or type(resolution) is not SecretResolutionGrant):
        raise ValueError
    if not isinstance(serialization.load_pem_public_key(public.public_key_pem.encode("ascii")), Ed25519PublicKey):
        raise ValueError
    reference_types = {"endpoint_reference": SecretProviderEndpointReference,
        "credential_reference": SecretReference, "reference": SecretReference}
    copied_references = {}
    for name, reference_type in reference_types.items():
        reference = getattr(resolution, name)
        if type(reference) is not reference_type or type(reference.reference_id) is not str:
            raise ValueError
        copied_references[name] = reference_type(reference.reference_id)
        if copied_references[name] != reference:
            raise ValueError
    for item in fields(resolution):
        if item.name not in (*reference_types, "intent"):
            field_value = getattr(resolution, item.name)
            if field_value is not None and type(field_value) is not str:
                raise ValueError
    copied = replace(resolution, **copied_references)
    if copied != resolution:
        raise ValueError
    return HealthSigningKey(replace(public), copied)


def _pair(context, transit, workload, transit_key, workload_key):
    left, right = transit_key.resolution_grant, workload_key.resolution_grant
    if (left.intent is not SecretUseIntent.GATEWAY_NODE_HEALTH_READ_TRANSIT_SIGNING_KEY
            or right.intent is not SecretUseIntent.WORKLOAD_NODE_HEALTH_READ_SIGNING_KEY
            or left.reference == right.reference
            or left.authorization_id == right.authorization_id or left.correlation_id == right.correlation_id
            or transit_key.public_key.fingerprint_sha256 == workload_key.public_key.fingerprint_sha256
            or (transit.issued_at, transit.not_before, transit.expires_at)
                != (workload.issued_at, workload.not_before, workload.expires_at)):
        raise ValueError
    for name in ("actor_subject", "session_id", "run_id", "activity_id"):
        if getattr(left, name) is None or getattr(left, name) != getattr(right, name):
            raise ValueError
    for resolution in (left, right):
        if (resolution.workspace_id != context.request.target.workspace_id.value
                or resolution.operation_id != context.attempt_id
                or resolution.effect_id is not None or resolution.probe_id is not None):
            raise ValueError


def _now(clock: Callable[[], int]) -> int:
    now = clock()
    if type(now) is not int or not 0 <= now <= 2**53 - 1:
        raise ValueError
    return now


def _window(clock, transit, workload):
    now = _now(clock)
    if not all(grant.not_before <= now < grant.expires_at for grant in (transit, workload)):
        raise ValueError


def _resolve(resolver, selected):
    material = require_authorized_secret(resolver, selected.resolution_grant)
    private = serialization.load_pem_private_key(material.reveal().encode("ascii"), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError
    derived = DelegationPublicKey(selected.public_key.key_id, DelegationKeyAlgorithm.ED25519,
        private.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"))
    if derived.fingerprint_sha256 != selected.public_key.fingerprint_sha256:
        raise ValueError
    return private


def _encode(grant, private, token_type, claim):
    return jwt.encode({"iss": grant.issuer, "aud": grant.audience, "iat": grant.issued_at,
        "nbf": grant.not_before, "exp": grant.expires_at, "jti": grant.jti, claim: grant.descriptor()},
        private, algorithm="EdDSA", headers={"kid": grant.key_id, "typ": token_type}).encode("ascii")
