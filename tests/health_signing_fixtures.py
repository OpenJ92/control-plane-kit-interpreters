"""Synthetic health inputs and real provider composition; no authority emulator."""
from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import control_plane_kit_core as core
from control_plane_kit_core.secrets import (
    SecretProviderEndpointReference, SecretReference, SecretResolutionGrant,
    SecretResolved, SecretUseIntent, SecretValue,
)
from control_plane_kit_interpreters.secret_provider import (
    ControlPlaneKitSecretsResolver, SecretProviderBootstrapRegistry, canonical_provider_secret_id,
)
from control_plane_kit_secrets.api import create_app
from control_plane_kit_secrets.auth import ProviderCredential, ProviderGrant
from control_plane_kit_secrets.control import (
    SecretsControlConfiguration, encode_secrets_control_configuration,
    secrets_control_declaration,
)
from control_plane_kit_secrets.crypto import encode_master_key_for_file, load_master_key_file
from control_plane_kit_secrets.custody import admit_provider_custody
from control_plane_kit_server_sdk.verifier_keys import (
    WorkloadNodeControlSurfaceReadVerifierKeySet, WorkloadNodeHealthReadVerifierKeySet,
)


def key(key_id):
    private = Ed25519PrivateKey.generate()
    public = core.DelegationPublicKey(key_id, core.DelegationKeyAlgorithm.ED25519,
        private.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"))
    return private, public


def private_pem(private):
    return private.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii")


def provider_control():
    roles = core.NodeControlGraphReferenceRole
    target = core.NodeControlTarget(*(
        core.NodeControlGraphReference(role, value) for role, value in (
            (roles.WORKSPACE, "workspace-a"), (roles.GRAPH_REVISION, "revision-a"),
            (roles.NODE, "provider-a"), (roles.PROVIDER_SOCKET, "control"))))
    return SecretsControlConfiguration(target=target,
        runtime_id=core.NodeControlGraphReference(roles.RUNTIME, "runtime-a"),
        declaration=secrets_control_declaration(), surface_issuer="surface-issuer",
        surface_keys=WorkloadNodeControlSurfaceReadVerifierKeySet(
            core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ, (key("surface")[1],)),
        health_issuer="health-issuer", health_keys=WorkloadNodeHealthReadVerifierKeySet(
            core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ, (key("health")[1],)))


def write_provider_control(path):
    path.write_bytes(encode_secrets_control_configuration(provider_control()))
    path.chmod(0o600)


def world():
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
    transit_private, transit_public = key("transit-key")
    workload_private, workload_public = key("workload-key")
    common = dict(canonicalization=core.NodeControlCanonicalization.JCS_RFC8785_V1,
        target=target, runtime_id=runtime, kind=request.kind,
        declaration_identity=declaration.identity(), request_id=request.request_id,
        request_digest=request.canonical_digest(), issued_at=100, not_before=101, expires_at=200)
    transit = core.DelegatedGatewayNodeHealthReadTransitGrant(
        profile=core.DelegatedGatewayNodeHealthReadTransitGrantProfile.V1,
        purpose=core.DelegationKeyPurpose.GATEWAY_NODE_HEALTH_READ_TRANSIT,
        issuer="transit-issuer", key_id=transit_public.key_id, gateway_node_id=gateway,
        attempt_id="attempt-a", jti="transit-jti", **common)
    workload = core.DelegatedWorkloadNodeHealthReadGrant(
        profile=core.DelegatedWorkloadNodeHealthReadGrantProfile.V1,
        purpose=core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ,
        issuer="workload-issuer", key_id=workload_public.key_id,
        audience=core.workload_node_control_audience(target), jti="workload-jti", **common)
    references = (SecretReference("secret://provider-a/keys/transit"),
                  SecretReference("secret://provider-a/keys/workload"))
    intents = (SecretUseIntent.GATEWAY_NODE_HEALTH_READ_TRANSIT_SIGNING_KEY,
               SecretUseIntent.WORKLOAD_NODE_HEALTH_READ_SIGNING_KEY)
    # Explicit post-authority projections: no copied Operations registration or
    # fingerprint algorithm, and construction does not prove current authority.
    resolutions = tuple(SecretResolutionGrant(
        authorization_id="suse_" + marker * 64, workspace_id="workspace-a",
        reference_registration_id="sref_" + marker * 64,
        provider_registration_id="sprov_" + "c" * 64,
        endpoint_reference=SecretProviderEndpointReference("provider-a"),
        credential_reference=SecretReference("secret://bootstrap/provider-token"),
        reference=reference, intent=intent, actor_subject="actor-a",
        correlation_id="correlation-" + marker, intent_fingerprint=marker * 64,
        operation_id="attempt-a", session_id="session-a", run_id="run-a",
        activity_id="health-a")
        for marker, reference, intent in zip("ab", references, intents, strict=True))
    return SimpleNamespace(target=target, runtime=runtime, gateway=gateway,
        declaration=declaration, request=request, transit=transit, workload=workload,
        publics=(transit_public, workload_public), privates=(transit_private, workload_private),
        resolutions=resolutions)


class RecordingResolver:
    def __init__(self, value):
        self.calls = []
        self.results = {grant.reference: SecretResolved(grant.reference, SecretValue(private_pem(private)))
            for grant, private in zip(value.resolutions, value.privates, strict=True)}

    def resolve(self, grant):
        self.calls.append(grant)
        result = self.results[grant.reference]
        if isinstance(result, Exception):
            raise result
        return result


class Provider:
    """Local real provider API behind an in-process HTTP transport."""
    def __init__(self, testcase, base, value):
        base = Path(base)
        master = base / "master.key"
        master.write_text(encode_master_key_for_file(os.urandom(32)), encoding="ascii")
        master.chmod(0o600)
        store, audit = admit_provider_custody(base / "secrets.sqlite3",
            master_key=load_master_key_file(master, version="test"), provider_id="provider-a")
        intents = tuple(grant.intent.value for grant in value.resolutions)
        credentials = (ProviderCredential("fixture", "fixture-token", (
            ProviderGrant("secret.generate-delegation-key", "workspace-a", intents),
            ProviderGrant("secret.resolve", "workspace-a", intents))),)
        self.client = TestClient(create_app(control=provider_control(),
            initialize_provider=lambda: (store, audit, credentials), provider_id="provider-a"))
        testcase.addCleanup(self.client.close)
        self.calls = []

        def handle(request):
            self.calls.append(json.loads(request.content))
            response = self.client.request(request.method, request.url.raw_path.decode("ascii"),
                headers=dict(request.headers), content=request.content)
            return httpx.Response(response.status_code, headers=response.headers, content=response.content)

        transport = httpx.MockTransport(handle)
        credential_file = base / "provider.token"
        credential_file.write_text("fixture-token", encoding="ascii")
        credential_file.chmod(0o600)
        grant = value.resolutions[0]
        registry = SecretProviderBootstrapRegistry(
            {grant.endpoint_reference: "http://provider.invalid"},
            {grant.credential_reference: credential_file})
        generated = []
        # Provision through the real provider owner to isolate signing tests.
        # #158 separately verifies the generation client against these actual
        # health responses using deliberate original-correlation replay.
        for index, (resolution, grant) in enumerate(zip(value.resolutions,
                (value.transit, value.workload), strict=True)):
            secret_id = canonical_provider_secret_id(resolution.reference)
            response = self.client.post(f"/v1/workspaces/workspace-a/delegation-keys/{secret_id}/generate",
                headers={"Authorization": "Bearer fixture-token"}, json={
                    "secret_reference": resolution.reference.reference_id,
                    "purpose": grant.purpose.value, "issuer": grant.issuer,
                    "caller_subject": "actor-a", "correlation_id": "generate-" + str(index)})
            testcase.assertEqual(response.status_code, 200, "synthetic provider key generation failed")
            payload = response.json()
            testcase.assertEqual(payload["purpose"], grant.purpose.value)
            testcase.assertEqual(payload["metadata"]["labels"]["intent"], resolution.intent.value)
            generated.append(core.DelegationPublicKey(payload["key_id"],
                core.DelegationKeyAlgorithm(payload["algorithm"]), payload["public_key_pem"]))
        value.publics = tuple(generated)
        value.transit = replace(value.transit, key_id=value.publics[0].key_id)
        value.workload = replace(value.workload, key_id=value.publics[1].key_id)
        self.resolver = ControlPlaneKitSecretsResolver(registry, transport=transport)
