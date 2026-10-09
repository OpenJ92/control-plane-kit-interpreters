"""Exact configuration allocation interpretation; no lifecycle policy or cleanup."""
from dataclasses import dataclass, field
from hashlib import sha256
import json

from control_plane_kit_core.configuration_instances import ConfigurationInstanceRefCodec
from control_plane_kit_core.configuration_invocation import (
    ConfigurationInvocationCompletion, configuration_invocation_correlation_for_request,
    configuration_invocation_selection_fingerprint,
)
from control_plane_kit_core.runtime_effect_observation import runtime_effect_result_fingerprint
from control_plane_kit_core.runtime_effects import (
    EffectResultKind, RuntimeEffectFailure, RuntimeEffectRequest, RuntimeEffectResult,
)
from control_plane_kit_interpreters.docker.sdk import DockerSdkConfigurationMount


_PREFIX = "org.openj92.cpk."


class ConfigurationMaterialConflict(ValueError):
    def __init__(self):
        super().__init__("selected configuration material does not match owned provider evidence")


class ConfigurationObservationUnknown(RuntimeError):
    def __init__(self):
        super().__init__("configuration provider observation is unknown")


def configuration_volume_name(reference):
    scope = (reference.workspace_id, reference.runtime_id, reference.node_id, reference.allocation_id)
    digest = sha256(json.dumps(scope, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    return "cpk-cfg-" + digest[:55]


def configuration_volume_labels(reference):
    digest = sha256(ConfigurationInstanceRefCodec().encode_canonical_bytes(reference)).hexdigest()
    return {_PREFIX + name: value for name, value in {
        "kind": "configuration-volume", "volume.kind": "configuration",
        "workspace": reference.workspace_id, "runtime": reference.runtime_id,
        "node": reference.node_id, "allocation": reference.allocation_id,
        "configuration.profile": "configuration-instance.v1", "configuration.reference": digest,
        "artifact": reference.artifact_id, "artifact.digest": reference.content_digest,
    }.items()}


def require_configuration_owner(inspection, reference):
    expected = configuration_volume_labels(reference)
    if inspection is None or any(inspection.labels.get(key) != value for key, value in expected.items()):
        raise ConfigurationMaterialConflict()


def require_configuration_file(observed, artifact):
    if (observed is None or not observed.regular_file
            or observed.content_digest != artifact.content_digest
            or observed.mode != int(artifact.file_mode.value, 8)):
        raise ConfigurationMaterialConflict()


@dataclass
class ConfigurationAttempt:
    """Bounded facts about this invocation, never an allocation registry."""
    request: RuntimeEffectRequest
    phase: str = "preflight"
    attempted_indices: list[int] = field(default_factory=list)
    staged_indices: list[int] = field(default_factory=list)
    old_container_id: str | None = None
    container_id: str | None = None
    old_removed: bool = False
    unknown_created_resource: bool = False
    action: str = "not-started"

    def __post_init__(self):
        self.correlation = configuration_invocation_correlation_for_request(self.request)
        self.selection_fingerprint = configuration_invocation_selection_fingerprint(self.correlation.selection)

    def evidence(self):
        return {
            "action": self.action,
            "configuration_attempt": {
                "profile": "docker.configuration-attempt.v1", "phase": self.phase,
                "selection_fingerprint": self.selection_fingerprint,
                "attempted_indices": list(self.attempted_indices),
                "staged_indices": list(self.staged_indices),
                "old_container_id": self.old_container_id, "container_id": self.container_id,
                "old_removed": self.old_removed,
                "unknown_created_resource": self.unknown_created_resource,
                "configuration_volumes_removed": 0,
            },
        }

    def result(self, kind, *, failure=None, observations=(), extra=None):
        evidence = self.evidence()
        if extra is not None:
            evidence.update(extra)
        if kind in (EffectResultKind.SUCCEEDED, EffectResultKind.FAILED):
            evidence["configuration_invocation_completion"] = ConfigurationInvocationCompletion(
                self.correlation.request_fingerprint, self.selection_fingerprint,
            ).descriptor()
        result = RuntimeEffectResult(self.request.effect_id, kind, evidence, failure, observations)
        runtime_effect_result_fingerprint(result)
        return result

    def uncertain(self):
        # Provider exception strings, config bodies and secret material never enter evidence.
        return self.result(EffectResultKind.UNCERTAIN, failure=RuntimeEffectFailure(
            "docker.configuration-effect-uncertain", "Docker configuration effect is uncertain"))


def stage_configuration(client, request, attempt):
    artifacts = {item.artifact_id: item for item in request.products[0].product.runtime_contract.configuration_artifacts}
    mounts = []
    attempt.phase = "configuration-staging"
    for index, reference in enumerate(request.configuration_instances.instances):
        artifact = artifacts[reference.artifact_id]
        name = configuration_volume_name(reference)
        inspection = client.inspect_volume(name)
        if inspection is None:
            attempt.attempted_indices.append(index)
            client.create_volume(name=name, labels=configuration_volume_labels(reference))
            require_configuration_owner(client.inspect_volume(name), reference)
        else:
            require_configuration_owner(inspection, reference)
            attempt.attempted_indices.append(index)
        observed = client.inspect_configuration_file(name)
        if observed is None:
            client.materialize_configuration_artifact(name, artifact)
            observed = client.inspect_configuration_file(name)
        require_configuration_file(observed, artifact)
        require_configuration_owner(client.inspect_volume(name), reference)
        attempt.staged_indices.append(index)
        mounts.append(DockerSdkConfigurationMount(artifact, name))
    return tuple(mounts)


def installed_configuration_matches(client, identity, mounts):
    if identity is None:
        raise ConfigurationObservationUnknown()
    for mount in mounts:
        observed = client.inspect_configuration_mount(identity, mount)
        if observed is None or observed.container_id != identity:
            raise ConfigurationObservationUnknown()
        if (observed.volume_name != mount.volume_name or observed.target_path != mount.artifact.target_path
                or observed.subpath != "content" or observed.read_only is not True):
            raise ConfigurationMaterialConflict()
        require_configuration_file(observed.file, mount.artifact)
    return True
