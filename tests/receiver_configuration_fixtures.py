"""Public synthetic receiver bytes shared by recording and mounted witnesses."""
from dataclasses import replace
import json

import control_plane_kit_core as core
from control_plane_kit_core.wrapper_configuration import NodeControlVerificationConfiguration
from control_plane_kit_core.configuration import ConfigurationArtifact, ConfigurationMediaType
from control_plane_kit_servers_cpk_local_gateway.health_transit_configuration import (
    ARTIFACT_ID, CONFIGURATION_PATH, PROFILE,
)
from health_signing_fixtures import key


def gateway_artifact(value):
    public = value.publics[0]
    return ConfigurationArtifact(ARTIFACT_ID, CONFIGURATION_PATH, ConfigurationMediaType.JSON,
        json.dumps({"profile": PROFILE, "gateway_target": value.gateway_target.descriptor(),
            "issuer": "transit-issuer", "purpose": core.DelegationKeyPurpose.GATEWAY_NODE_HEALTH_READ_TRANSIT.value,
            "public_keys": [{"key_id": public.key_id, "algorithm": public.algorithm.value,
                             "public_key_pem": public.public_key_pem}]}, sort_keys=True, separators=(",", ":")))


def receiver_configuration(target, declaration, health_public):
    """Actual common value; installed targets come from fixture topology intent."""
    return core.ReceiverNodeControlConfiguration(target, declaration, (
        NodeControlVerificationConfiguration(core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ,
            "surface-issuer", (key("surface-key")[1],)),
        NodeControlVerificationConfiguration(core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ,
            "workload-issuer", (health_public,))))


def receiver_artifact(configuration, artifact_id="workload-control", path="/etc/workload/control.json"):
    return ConfigurationArtifact(artifact_id, path, ConfigurationMediaType.JSON,
        core.ReceiverNodeControlConfigurationCodec().encode_bytes(configuration).decode())


def receiver_artifacts(value):
    # Selected common public bytes for recording/mounted delivery. These two
    # witnesses still do not execute a CPK process or establish current authority.
    socket = replace(value.target.provider_socket_name, value="http-api")
    target = replace(value.target, provider_socket_name=socket)
    declaration = replace(value.declaration,
        surface=replace(value.declaration.surface, provider_socket_name=socket))

    configuration = receiver_configuration(target, declaration, value.publics[1])
    return (gateway_artifact(value), receiver_artifact(configuration,
        "cpk-control", "/etc/cpk/cpk-server/control.json"))
