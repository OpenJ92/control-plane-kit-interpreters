"""#147 real signer/relay/SDK composition with synthetic selected inputs only."""
from dataclasses import replace

import httpx
from fastapi import FastAPI
import control_plane_kit_core as core
from control_plane_kit_core.public_ingress import (
    IngressAuthorityReference, NamedPublicIngress, PublicIngressTarget,
)
from control_plane_kit_interpreters.probes.health_signing import (
    Ed25519HealthCredentialPairSigner, HealthSigningContext, HealthSigningKey,
)
from control_plane_kit_server_sdk.fastapi import install_cpk_control_routes
from control_plane_kit_server_sdk.health import WorkloadNodeHealthReadDispatcher
from control_plane_kit_server_sdk.verification import (
    Ed25519WorkloadNodeHealthReadVerifier, Ed25519WorkloadNodeControlSurfaceReadVerifier,
)
from control_plane_kit_server_sdk.verifier_keys import (
    WorkloadNodeHealthReadVerifierKeySet, AtomicWorkloadNodeHealthReadVerifierKeySet,
    WorkloadNodeControlSurfaceReadVerifierKeySet, AtomicWorkloadNodeControlSurfaceReadVerifierKeySet,
)
from control_plane_kit_servers_cpk_local_gateway.health_relay import GatewayHealthRelay
from control_plane_kit_servers_cpk_local_gateway.health_relay_configuration import (
    GatewayHealthTargetBinding, GatewayHealthRelayConfiguration,
)
from control_plane_kit_servers_cpk_local_gateway.health_transit_verification import (
    gateway_health_transit_verifier_from_artifact,
)
from control_plane_kit_servers_cpk_local_gateway.server import create_app
from health_signing_fixtures import world, RecordingResolver, key
from receiver_configuration_fixtures import gateway_artifact


class Resolver:
    def __init__(self, addresses=("8.8.8.8",)):
        self.addresses = addresses
        self.calls = []

    async def resolve(self, hostname):
        self.calls.append(hostname)
        return self.addresses


class Transport(httpx.AsyncBaseTransport):
    def __init__(self, inner):
        self.inner = inner
        self.requests = []
        self.closed = False

    async def handle_async_request(self, request):
        self.requests.append(request)
        return await self.inner.handle_async_request(request)

    async def aclose(self):
        self.closed = True
        await self.inner.aclose()


class World:
    def __init__(self, kind=core.NodeHealthReadKind.LIVENESS):
        self.value = value = world()
        value.declaration = replace(value.declaration, surface=replace(value.declaration.surface,
            health_reads=(core.NodeHealthReadKind.LIVENESS, core.NodeHealthReadKind.READINESS)))
        value.request = replace(value.request, kind=kind, declaration_identity=value.declaration.identity())
        changed = dict(kind=kind, declaration_identity=value.declaration.identity(),
            request_digest=value.request.canonical_digest())
        value.transit = replace(value.transit, **changed)
        value.workload = replace(value.workload, **changed)
        self.now = 150
        self.context = HealthSigningContext(value.request, "attempt-a", value.gateway,
            value.declaration, "transit-issuer", "workload-issuer")
        signer = Ed25519HealthCredentialPairSigner(RecordingResolver(value), lambda:self.now)
        self.pair = signer.sign(self.context, transit_grant=value.transit, workload_grant=value.workload,
            transit_key=HealthSigningKey(value.publics[0], value.resolutions[0]),
            workload_key=HealthSigningKey(value.publics[1], value.resolutions[1]))
        self.ingress = NamedPublicIngress("management", IngressAuthorityReference("synthetic-authority"),
            PublicIngressTarget(value.gateway.value, "control"), "connector-a", "gateway.example.invalid")
        self.resolver = Resolver()
        self.callbacks = []
        self.outcome = core.NodeHealthReadOutcome.HEALTHY
        self.workload_transport = Transport(httpx.ASGITransport(app=self.workload_app()))
        configuration = GatewayHealthRelayConfiguration(value.target.workspace_id, value.gateway,
            value.runtime, (GatewayHealthTargetBinding("workload-management", value.target,
                value.runtime, value.declaration, "http://workload-a:8087"),))
        relay = GatewayHealthRelay(configuration, gateway_health_transit_verifier_from_artifact(
            gateway_artifact(value)), clock=lambda:self.now, transport=self.workload_transport)
        self.gateway_transport = Transport(httpx.ASGITransport(app=create_app(health_relay=relay)))

    def workload_app(self):
        value = self.value
        audience = core.workload_node_control_audience(value.target)
        health = Ed25519WorkloadNodeHealthReadVerifier(AtomicWorkloadNodeHealthReadVerifierKeySet(
            WorkloadNodeHealthReadVerifierKeySet(core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ,
                (value.publics[1],))), expected_issuer="workload-issuer", expected_audience=audience,
            clock=lambda:self.now)
        surface = Ed25519WorkloadNodeControlSurfaceReadVerifier(AtomicWorkloadNodeControlSurfaceReadVerifierKeySet(
            WorkloadNodeControlSurfaceReadVerifierKeySet(core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ,
                (key("surface-key")[1],))), expected_issuer="surface-issuer", expected_audience=audience,
            clock=lambda:self.now)
        def callback(kind):
            self.callbacks.append(kind)
            return self.outcome
        app = FastAPI()
        install_cpk_control_routes(app, target=value.target, declaration=value.declaration,
            surface_read_verifier=surface, health_dispatcher=WorkloadNodeHealthReadDispatcher(
                target=value.target, runtime_id=value.runtime, declaration=value.declaration, verifier=health,
                liveness=lambda:callback(core.NodeHealthReadKind.LIVENESS),
                readiness=lambda:callback(core.NodeHealthReadKind.READINESS)))
        return app

    def destination(self, module):
        return module.SelectedManagementGateway(self.ingress, self.value.gateway, "control",
            self.value.runtime, "workload-management")

    def client(self, module, **changes):
        return module.SignedGatewayHealthClient(**{"clock":lambda:self.now,
            "public_resolver":self.resolver, "transport":self.gateway_transport, **changes})

    async def dispatch(self, module, *, client=None, **changes):
        values = dict(context=self.context, pair=self.pair, destination=self.destination(module),
            transit_grant=self.value.transit, workload_grant=self.value.workload)
        values.update(changes)
        return await (client or self.client(module)).dispatch(**values)
