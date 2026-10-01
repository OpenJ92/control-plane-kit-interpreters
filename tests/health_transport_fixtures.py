"""#147 real signer/relay/SDK composition with synthetic selected inputs only."""
from dataclasses import replace
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
import control_plane_kit_core as core
from control_plane_kit_core.public_ingress import (
    IngressAuthorityReference, NamedPublicIngress, PublicIngressTarget,
)
from control_plane_kit_interpreters.probes.health_signing import (
    Ed25519HealthCredentialPairSigner, HealthSigningContext, HealthSigningKey,
)
from control_plane_kit_server_sdk.fastapi import install_cpk_wrapper
from control_plane_kit_servers_cpk_local_gateway.health_relay import GatewayHealthRelay
from control_plane_kit_servers_cpk_local_gateway.health_relay_configuration import (
    GatewayHealthTargetBinding, GatewayHealthRelayConfiguration,
)
from control_plane_kit_servers_cpk_local_gateway.health_transit_verification import (
    gateway_health_transit_verifier_from_artifact,
)
from control_plane_kit_servers_cpk_local_gateway.server import create_app
from health_signing_fixtures import world, RecordingResolver
from receiver_configuration_fixtures import gateway_artifact, receiver_configuration


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
        self.context = HealthSigningContext(value.request, "attempt-a", value.gateway_target,
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
        self.workload_application = self.workload_app()
        self.workload_transport = Transport(httpx.ASGITransport(app=self.workload_application))
        configuration = GatewayHealthRelayConfiguration(value.gateway_target,
            (GatewayHealthTargetBinding("workload-management", value.target,
                value.declaration, "http://workload-a:8087"),))
        relay = GatewayHealthRelay(configuration, gateway_health_transit_verifier_from_artifact(
            gateway_artifact(value)), clock=lambda:self.now, transport=self.workload_transport)
        self.gateway_app = create_app(health_relay=relay)
        self.gateway_transport = Transport(httpx.ASGITransport(app=self.gateway_app))

    @asynccontextmanager
    async def workload_lifespan(self):
        # ASGITransport does not start application lifespan. The separate real
        # workload must be serving for its SDK readiness callback to execute.
        # Same-app bootstrap keeps its existing caller-owned gateway lifespan.
        if self.workload_application is self.gateway_app:
            yield
        else:
            async with self.workload_application.router.lifespan_context(self.workload_application):
                yield

    def workload_app(self):
        value = self.value
        configuration = receiver_configuration(value.target, value.declaration, value.publics[1])
        def callback(kind):
            self.callbacks.append(kind)
            return self.outcome
        app = FastAPI()
        install_cpk_wrapper(app, configuration=configuration, clock=lambda:self.now,
            liveness=(lambda:callback(core.NodeHealthReadKind.LIVENESS))
                if core.NodeHealthReadKind.LIVENESS in value.declaration.surface.health_reads else None,
            readiness=(lambda:callback(core.NodeHealthReadKind.READINESS))
                if core.NodeHealthReadKind.READINESS in value.declaration.surface.health_reads else None)
        return app

    def destination(self, module):
        return module.SelectedManagementGateway(self.ingress, self.value.gateway, "control",
            self.value.runtime, "workload-management", core.GatewayTransitProtocol.RECEIVER_HEALTH_READ_V2)

    def client(self, module, **changes):
        return module.SignedGatewayHealthClient(**{"clock":lambda:self.now,
            "public_resolver":self.resolver, "transport":self.gateway_transport, **changes})

    async def dispatch(self, module, *, client=None, **changes):
        values = dict(context=self.context, pair=self.pair, destination=self.destination(module),
            transit_grant=self.value.transit, workload_grant=self.value.workload)
        values.update(changes)
        async with self.workload_lifespan():
            return await (client or self.client(module)).dispatch(**values)
