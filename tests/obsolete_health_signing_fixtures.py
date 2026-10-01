"""Frozen valid V1 negative specimen for canonical receiver-health admission.

Keep this independent of the evolving provider and receiver fixtures. Core's
historical value constructors describe the rejected input; they do not provide
an alternate signer or gateway. Key material exists only in the test container.
"""
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import control_plane_kit_core as core
from control_plane_kit_core.secrets import (
    SecretProviderEndpointReference, SecretReference, SecretResolutionGrant,
    SecretResolved, SecretUseIntent, SecretValue,
)


def obsolete_world():
    roles = core.NodeControlGraphReferenceRole
    target = core.NodeControlTarget(*(
        core.NodeControlGraphReference(role, value) for role, value in (
            (roles.WORKSPACE, "workspace-a"), (roles.GRAPH_REVISION, "revision-a"),
            (roles.NODE, "workload-a"), (roles.PROVIDER_SOCKET, "control"))))
    runtime = core.NodeControlGraphReference(roles.RUNTIME, "runtime-a")
    gateway = core.NodeControlGraphReference(roles.NODE, "gateway-a")
    declaration = core.WorkloadNodeControlSurfaceDeclaration(
        core.WorkloadNodeControlSurfaceDescriptor(target.provider_socket_name, (),
            health_reads=(core.NodeHealthReadKind.LIVENESS,)),
        profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2)
    request = core.NodeHealthReadRequest(target, runtime, core.NodeHealthReadKind.LIVENESS,
        declaration.identity(), "observation-a")
    privates = tuple(Ed25519PrivateKey.generate() for _ in range(2))
    publics = tuple(core.DelegationPublicKey(name, core.DelegationKeyAlgorithm.ED25519,
        private.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"))
        for name, private in zip(("transit-key", "workload-key"), privates, strict=True))
    common = dict(canonicalization=core.NodeControlCanonicalization.JCS_RFC8785_V1,
        target=target, runtime_id=runtime, kind=request.kind,
        declaration_identity=declaration.identity(), request_id=request.request_id,
        request_digest=request.canonical_digest(), issued_at=100, not_before=101, expires_at=200)
    transit = core.DelegatedGatewayNodeHealthReadTransitGrant(
        profile=core.DelegatedGatewayNodeHealthReadTransitGrantProfile.V1,
        purpose=core.DelegationKeyPurpose.GATEWAY_NODE_HEALTH_READ_TRANSIT,
        issuer="transit-issuer", key_id=publics[0].key_id, gateway_node_id=gateway,
        attempt_id="attempt-a", jti="transit-jti", **common)
    workload = core.DelegatedWorkloadNodeHealthReadGrant(
        profile=core.DelegatedWorkloadNodeHealthReadGrantProfile.V1,
        purpose=core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ,
        issuer="workload-issuer", key_id=publics[1].key_id,
        audience=core.workload_node_control_audience(target), jti="workload-jti", **common)
    resolutions = tuple(SecretResolutionGrant(
        authorization_id="suse_" + marker * 64, workspace_id="workspace-a",
        reference_registration_id="sref_" + marker * 64,
        provider_registration_id="sprov_" + "c" * 64,
        endpoint_reference=SecretProviderEndpointReference("provider-a"),
        credential_reference=SecretReference("secret://bootstrap/provider-token"),
        reference=SecretReference("secret://provider-a/keys/" + family), intent=intent,
        actor_subject="actor-a", correlation_id="correlation-" + marker,
        intent_fingerprint=marker * 64, operation_id="attempt-a", session_id="session-a",
        run_id="run-a", activity_id="health-a")
        for marker, family, intent in zip("ab", ("transit", "workload"), (
            SecretUseIntent.GATEWAY_NODE_HEALTH_READ_TRANSIT_SIGNING_KEY,
            SecretUseIntent.WORKLOAD_NODE_HEALTH_READ_SIGNING_KEY), strict=True))
    return SimpleNamespace(request=request, gateway=gateway, declaration=declaration,
        transit=transit, workload=workload, publics=publics, privates=privates,
        resolutions=resolutions)


class ObsoleteRecordingResolver:
    def __init__(self, value):
        self.calls = []
        self.results = {grant.reference: SecretResolved(grant.reference, SecretValue(
            private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode("ascii")))
            for grant, private in zip(value.resolutions, value.privates, strict=True)}

    def resolve(self, grant):
        self.calls.append(grant)
        return self.results[grant.reference]
