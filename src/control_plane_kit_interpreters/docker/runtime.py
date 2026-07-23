from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Mapping

from control_plane_kit_core.planning import (
    ActivityOperation,
    ReconcileNode,
    RemoveNodeResource,
    StartNode,
    StartRuntime,
    StopNode,
    StopRuntime,
)
from control_plane_kit_core.runtime_effects import (
    RuntimeEffectFailure,
    RuntimeEffectKind,
    RuntimeEffectRequest,
    RuntimeEffectResult,
    RuntimeProductMaterial,
)
from control_plane_kit_core.types import RuntimeKind

from control_plane_kit_interpreters.docker.sdk import (
    DockerSdkClient,
    DockerSdkConfigurationMount,
    DockerSdkPortBinding,
    runtime_endpoint_observations,
    verify_published_ports,
)


_LABEL_PREFIX = "org.openj92.cpk"
_SEGMENT = re.compile(r"[^a-zA-Z0-9_.-]+")


@dataclass(frozen=True)
class DockerRuntimeInterpreter:
    """Interpret pure runtime-effect requests with the Python Docker SDK."""

    client: DockerSdkClient

    def execute(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        if not isinstance(request, RuntimeEffectRequest):
            raise TypeError("DockerRuntimeInterpreter requires RuntimeEffectRequest")
        if request.kind is not RuntimeEffectKind.REALIZE_ACTIVITY:
            return _unsupported(request, "docker.unsupported-effect-kind")
        if request.runtime_kind is not RuntimeKind.DOCKER:
            return _unsupported(request, "docker.unsupported-runtime-kind")

        try:
            match request.operation:
                case StartRuntime():
                    return self._start_runtime(request)
                case StopRuntime():
                    return self._stop_runtime(request)
                case StartNode() | ReconcileNode():
                    return self._start_node(request)
                case StopNode():
                    return self._stop_node(request)
                case RemoveNodeResource():
                    return self._remove_node(request)
                case _:
                    return _unsupported(
                        request,
                        "docker.unsupported-activity-operation",
                    )
        except _DockerInterpreterPreconditionError as error:
            return _failed(request, error.code, str(error))
        except Exception as error:
            return RuntimeEffectResult.uncertain(
                request.effect_id,
                RuntimeEffectFailure(
                    "docker.effect-uncertain",
                    _bounded_error_message(error),
                ),
            )

    def _start_runtime(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        runtime_id = _runtime_target(request.operation)
        network_name = _network_name(request, runtime_id)
        labels = _runtime_labels(request, runtime_id)
        inspection = self.client.inspect_network(network_name)
        if inspection is None:
            self.client.create_network(name=network_name, labels=labels)
            action = "created"
        else:
            _require_owned(inspection.labels, labels, "network")
            action = "reused"
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": action,
                "runtime_id": runtime_id,
                "network": network_name,
            },
        )

    def _stop_runtime(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        runtime_id = _runtime_target(request.operation)
        network_name = _network_name(request, runtime_id)
        labels = _runtime_labels(request, runtime_id)
        inspection = self.client.inspect_network(network_name)
        if inspection is not None:
            _require_owned(inspection.labels, labels, "network")
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": "logical-stop",
                "runtime_id": runtime_id,
                "network": network_name,
            },
        )

    def _start_node(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        material = _single_product(request)
        _reject_unresolved_secret_deliveries(material)
        runtime_id = material.runtime_id
        network_name = _network_name(request, runtime_id)
        runtime_labels = _runtime_labels(request, runtime_id)
        network = self.client.inspect_network(network_name)
        if network is None:
            self.client.create_network(name=network_name, labels=runtime_labels)
        else:
            _require_owned(network.labels, runtime_labels, "network")

        container_name = _container_name(request, material.node_id)
        labels = _node_labels(request, material)
        inspection = self.client.inspect_container(container_name)
        if inspection is None:
            self._create_node_container(request, material, container_name, labels)
            action = "created"
        else:
            _require_owned(inspection.labels, labels, "container")
            if inspection.running:
                action = "reused"
            else:
                self.client.start_container(container_name)
                action = "started"

        published = ()
        observed = self.client.inspect_container(container_name)
        if observed is not None:
            _require_owned(observed.labels, labels, "container")
            published = observed.published_ports
        port_bindings = _private_provider_ports(material)
        observations = runtime_endpoint_observations(
            subject_id=material.node_id,
            graph_id=request.source.desired_graph_id,
            private_host=material.node_id,
            provider_ports=port_bindings,
            published_ports=verify_published_ports((), published),
        )
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": action,
                "node_id": material.node_id,
                "runtime_id": runtime_id,
                "container": container_name,
                "network": network_name,
                "image": material.product.image.execution_reference,
            },
            observations=observations,
        )

    def _create_node_container(
        self,
        request: RuntimeEffectRequest,
        material: RuntimeProductMaterial,
        container_name: str,
        labels: Mapping[str, str],
    ) -> None:
        contract = material.product.runtime_contract
        retained_volumes = {
            _volume_name(request, material.node_id, mount.resource_id): mount.target_path
            for mount in contract.retained_data_mounts
        }
        configuration_mounts = []
        for artifact in contract.configuration_artifacts:
            volume_name = _volume_name(request, material.node_id, artifact.artifact_id)
            volume_labels = {
                **labels,
                f"{_LABEL_PREFIX}.volume.kind": "configuration",
                f"{_LABEL_PREFIX}.artifact": artifact.artifact_id,
                f"{_LABEL_PREFIX}.artifact.digest": artifact.content_digest,
            }
            inspection = self.client.inspect_volume(volume_name)
            if inspection is None:
                self.client.create_volume(name=volume_name, labels=volume_labels)
                self.client.materialize_configuration_artifact(volume_name, artifact)
            else:
                _require_owned(inspection.labels, volume_labels, "configuration volume")
                digest = self.client.configuration_artifact_digest(volume_name)
                if digest != artifact.content_digest:
                    raise _DockerInterpreterPreconditionError(
                        "docker.configuration-digest-conflict",
                        "owned configuration volume has unexpected digest",
                    )
            configuration_mounts.append(
                DockerSdkConfigurationMount(artifact, volume_name)
            )
        for volume_name in retained_volumes:
            volume_labels = {
                **labels,
                f"{_LABEL_PREFIX}.volume.kind": "retained-data",
            }
            inspection = self.client.inspect_volume(volume_name)
            if inspection is None:
                self.client.create_volume(name=volume_name, labels=volume_labels)
            else:
                _require_owned(inspection.labels, volume_labels, "retained volume")

        self.client.pull_image(material.product.image.execution_reference)
        self.client.run_container(
            name=container_name,
            image=material.product.image.execution_reference,
            network=_network_name(request, material.runtime_id),
            aliases=(material.node_id,),
            environment={
                binding.name: binding.value
                for binding in contract.public_environment
            },
            labels=labels,
            volumes=retained_volumes,
            configuration_mounts=tuple(configuration_mounts),
            port_bindings=(),
        )

    def _stop_node(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        material = _single_product(request)
        container_name = _container_name(request, material.node_id)
        labels = _node_labels(request, material)
        inspection = self.client.inspect_container(container_name)
        if inspection is None:
            action = "absent"
        else:
            _require_owned(inspection.labels, labels, "container")
            if inspection.running:
                self.client.stop_container(container_name)
                action = "stopped"
            else:
                action = "already-stopped"
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": action,
                "node_id": material.node_id,
                "container": container_name,
            },
        )

    def _remove_node(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        material = _single_product(request)
        container_name = _container_name(request, material.node_id)
        labels = _node_labels(request, material)
        inspection = self.client.inspect_container(container_name)
        if inspection is None:
            action = "absent"
        else:
            _require_owned(inspection.labels, labels, "container")
            self.client.remove_container(container_name)
            action = "removed"
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": action,
                "node_id": material.node_id,
                "container": container_name,
            },
        )


class _DockerInterpreterPreconditionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _unsupported(request: RuntimeEffectRequest, code: str) -> RuntimeEffectResult:
    return RuntimeEffectResult.unsupported(
        request.effect_id,
        RuntimeEffectFailure(code, "Docker runtime interpreter does not support request"),
    )


def _failed(
    request: RuntimeEffectRequest,
    code: str,
    message: str,
) -> RuntimeEffectResult:
    return RuntimeEffectResult.failed(
        request.effect_id,
        RuntimeEffectFailure(code, message),
    )


def _single_product(request: RuntimeEffectRequest) -> RuntimeProductMaterial:
    if len(request.products) != 1:
        raise _DockerInterpreterPreconditionError(
            "docker.product-material-required",
            "Docker node activity requires exactly one product material",
        )
    return request.products[0]


def _runtime_target(operation: ActivityOperation) -> str:
    target = getattr(operation, "target", None)
    runtime_id = getattr(target, "runtime_id", None)
    if not isinstance(runtime_id, str) or not runtime_id:
        raise _DockerInterpreterPreconditionError(
            "docker.runtime-target-required",
            "Docker runtime activity requires a runtime target",
        )
    return runtime_id


def _reject_unresolved_secret_deliveries(material: RuntimeProductMaterial) -> None:
    if material.product.runtime_contract.secret_deliveries:
        raise _DockerInterpreterPreconditionError(
            "docker.secret-resolution-required",
            "Docker runtime interpreter requires resolved secret material",
        )


def _private_provider_ports(
    material: RuntimeProductMaterial,
) -> tuple[DockerSdkPortBinding, ...]:
    sockets = material.product.runtime_contract.sockets
    ports = []
    for port in material.product.runtime_contract.provider_ports:
        provider = sockets.provider(port.provider_socket)
        ports.append(
            DockerSdkPortBinding(
                provider.name,
                provider.protocol,
                port.container_port,
                "127.0.0.1",
                None,
            )
        )
    return tuple(ports)


def _runtime_labels(
    request: RuntimeEffectRequest,
    runtime_id: str,
) -> dict[str, str]:
    return {
        f"{_LABEL_PREFIX}.kind": "runtime-network",
        f"{_LABEL_PREFIX}.workspace": request.source.workspace_id,
        f"{_LABEL_PREFIX}.runtime": runtime_id,
        f"{_LABEL_PREFIX}.plan": request.source.plan_id,
        f"{_LABEL_PREFIX}.desired-graph": request.source.desired_graph_id,
        f"{_LABEL_PREFIX}.fingerprint": _digest(
            "runtime",
            request.source.workspace_id,
            request.source.desired_graph_id,
            runtime_id,
        ),
    }


def _node_labels(
    request: RuntimeEffectRequest,
    material: RuntimeProductMaterial,
) -> dict[str, str]:
    return {
        f"{_LABEL_PREFIX}.kind": "container",
        f"{_LABEL_PREFIX}.workspace": request.source.workspace_id,
        f"{_LABEL_PREFIX}.runtime": material.runtime_id,
        f"{_LABEL_PREFIX}.node": material.node_id,
        f"{_LABEL_PREFIX}.plan": request.source.plan_id,
        f"{_LABEL_PREFIX}.desired-graph": request.source.desired_graph_id,
        f"{_LABEL_PREFIX}.product": material.reference.identity.key,
        f"{_LABEL_PREFIX}.descriptor": material.reference.descriptor_sha256.value,
        f"{_LABEL_PREFIX}.image": material.product.image.digest,
        f"{_LABEL_PREFIX}.fingerprint": _node_fingerprint(request, material),
    }


def _require_owned(
    observed: Mapping[str, str],
    expected: Mapping[str, str],
    resource: str,
) -> None:
    if observed.get(f"{_LABEL_PREFIX}.fingerprint") != expected[f"{_LABEL_PREFIX}.fingerprint"]:
        raise _DockerInterpreterPreconditionError(
            f"docker.{resource}-ownership-conflict",
            f"Docker {resource} is not owned by this runtime effect",
        )


def _node_fingerprint(
    request: RuntimeEffectRequest,
    material: RuntimeProductMaterial,
) -> str:
    product = material.product
    contract = product.runtime_contract
    return _digest(
        "node",
        request.source.workspace_id,
        request.source.desired_graph_id,
        material.node_id,
        material.runtime_id,
        material.reference.identity.key,
        material.reference.descriptor_sha256.value,
        product.image.execution_reference,
        repr(product.runtime_contract.descriptor()),
        repr(tuple(artifact.content_digest for artifact in contract.configuration_artifacts)),
        repr(tuple(mount.resource_id for mount in contract.retained_data_mounts)),
    )


def _network_name(request: RuntimeEffectRequest, runtime_id: str) -> str:
    return _resource_name("net", request.source.workspace_id, runtime_id)


def _container_name(request: RuntimeEffectRequest, node_id: str) -> str:
    return _resource_name("node", request.source.workspace_id, node_id)


def _volume_name(
    request: RuntimeEffectRequest,
    node_id: str,
    material_id: str,
) -> str:
    return _resource_name("vol", request.source.workspace_id, node_id, material_id)


def _resource_name(kind: str, *parts: str) -> str:
    readable = "-".join(_segment(part) for part in (kind, *parts))
    suffix = _digest(kind, *parts)[:12]
    value = f"cpk-{readable}-{suffix}".strip("-")
    return value[:63].rstrip("-.")


def _segment(value: str) -> str:
    cleaned = _SEGMENT.sub("-", value).strip("-.").lower()
    return cleaned or "x"


def _digest(*parts: str) -> str:
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(part.encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest()


def _bounded_error_message(error: Exception) -> str:
    text = type(error).__name__
    message = str(error)
    if message:
        text = f"{text}: {message}"
    return text[:512]
