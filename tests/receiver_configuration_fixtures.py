"""Public synthetic receiver bytes shared by recording and mounted witnesses."""
from dataclasses import replace
import json

import control_plane_kit_core as core
from control_plane_kit_core.configuration import ConfigurationArtifact, ConfigurationMediaType
from control_plane_kit_servers_cpk_local_gateway.health_transit_configuration import (
    ARTIFACT_ID, CONFIGURATION_PATH, PROFILE,
)
from health_signing_fixtures import key


def gateway_artifact(value):
    public = value.publics[0]
    return ConfigurationArtifact(ARTIFACT_ID, CONFIGURATION_PATH, ConfigurationMediaType.JSON,
        json.dumps({"profile": PROFILE, "workspace_id": value.target.workspace_id.value,
            "gateway_node_id": value.gateway.value, "runtime_id": value.runtime.value,
            "issuer": "transit-issuer", "purpose": core.DelegationKeyPurpose.GATEWAY_NODE_HEALTH_READ_TRANSIT.value,
            "public_keys": [{"key_id": public.key_id, "algorithm": public.algorithm.value,
                             "public_key_pem": public.public_key_pem}]}, sort_keys=True, separators=(",", ":")))


def receiver_artifacts(value):
    # Static input aligned with Servers4d781 control_configuration.py:
    # exact http-api V2 liveness declaration, separate family keys.
    # Neither witness executes the CPK configuration decoder or receiver process.
    socket = replace(value.target.provider_socket_name, value="http-api")
    target = replace(value.target, provider_socket_name=socket)
    declaration = replace(value.declaration,
        surface=replace(value.declaration.surface, provider_socket_name=socket))

    def family(issuer, public):
        return {"issuer": issuer, "public_keys": [{"key_id": public.key_id,
            "algorithm": public.algorithm.value, "public_key_pem": public.public_key_pem}]}

    content = json.dumps({"profile": "cpk-control-configuration.v1", "target": target.descriptor(),
        "runtime_id": value.runtime.value, "declaration": declaration.descriptor(),
        "surface_read": family("surface-issuer", key("surface-key")[1]),
        "health_read": family("workload-issuer", value.publics[1])}, sort_keys=True)
    return (gateway_artifact(value), ConfigurationArtifact("cpk-control",
        "/etc/cpk/cpk-server/control.json", ConfigurationMediaType.JSON, content))
