from __future__ import annotations

from importlib import import_module as _import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from control_plane_kit_interpreters.probes.clients import (
        DefaultDatagramExchangeClient,
        DefaultSocketConnector,
        HttpApplicationHealthProbeAdapter,
        StaticRuntimeEndpointProvider,
        TcpTransportProbeAdapter,
        TransportProbeRouter,
        UdpTransportProbeAdapter,
        UnsupportedTransportProbe,
    )
    from control_plane_kit_interpreters.probes.gateway import (
        Ed25519GatewayProbeSigner,
        GatewayProbeClientCode,
        GatewayProbeClientError,
        GatewayProbeClientResult,
        SignedGatewayProbeClient,
    )
    from control_plane_kit_interpreters.probes.public_dns import (
        DnsOverHttpsPublicAddressResolver,
        PublicDnsResolutionCode,
        PublicDnsResolutionError,
        PublicDnsResolverPolicy,
    )
    from control_plane_kit_interpreters.probes.security import (
        AuthorizedProbeTarget,
        ProbeAddressPolicy,
        ProbeSecurityCode,
        ProbeSecurityError,
        authorize_probe_endpoint,
    )


_EXPORT_MODULES = {
    "AuthorizedProbeTarget": "security",
    "DefaultDatagramExchangeClient": "clients",
    "DefaultSocketConnector": "clients",
    "DnsOverHttpsPublicAddressResolver": "public_dns",
    "Ed25519GatewayProbeSigner": "gateway",
    "GatewayProbeClientCode": "gateway",
    "GatewayProbeClientError": "gateway",
    "GatewayProbeClientResult": "gateway",
    "HttpApplicationHealthProbeAdapter": "clients",
    "ProbeAddressPolicy": "security",
    "ProbeSecurityCode": "security",
    "ProbeSecurityError": "security",
    "PublicDnsResolutionCode": "public_dns",
    "PublicDnsResolutionError": "public_dns",
    "PublicDnsResolverPolicy": "public_dns",
    "StaticRuntimeEndpointProvider": "clients",
    "SignedGatewayProbeClient": "gateway",
    "TcpTransportProbeAdapter": "clients",
    "TransportProbeRouter": "clients",
    "UdpTransportProbeAdapter": "clients",
    "UnsupportedTransportProbe": "clients",
    "authorize_probe_endpoint": "security",
}


def __getattr__(name: str) -> object:
    module = _EXPORT_MODULES.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(_import_module(f"{__name__}.{module}"), name)


__all__ = [
    "AuthorizedProbeTarget",
    "DefaultDatagramExchangeClient",
    "DefaultSocketConnector",
    "DnsOverHttpsPublicAddressResolver",
    "Ed25519GatewayProbeSigner",
    "GatewayProbeClientCode",
    "GatewayProbeClientError",
    "GatewayProbeClientResult",
    "HttpApplicationHealthProbeAdapter",
    "ProbeAddressPolicy",
    "ProbeSecurityCode",
    "ProbeSecurityError",
    "PublicDnsResolutionCode",
    "PublicDnsResolutionError",
    "PublicDnsResolverPolicy",
    "StaticRuntimeEndpointProvider",
    "SignedGatewayProbeClient",
    "TcpTransportProbeAdapter",
    "TransportProbeRouter",
    "UdpTransportProbeAdapter",
    "UnsupportedTransportProbe",
    "authorize_probe_endpoint",
]
