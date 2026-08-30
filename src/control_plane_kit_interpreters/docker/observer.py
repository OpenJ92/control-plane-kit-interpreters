"""Inspect exact Docker postconditions without executing runtime effects."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from importlib import import_module

from control_plane_kit_core.planning import (
    ReconcileNode,
    ReconcileRuntime,
    RemoveNodeResource,
    RemoveRuntimeResource,
    StartNode,
    StartRuntime,
    StopNode,
    StopRuntime,
    WaitForHealthy,
)
from control_plane_kit_core.runtime_effect_observation import (
    RuntimeEffectObservationEvidence,
    RuntimeEffectObservationFailure,
    RuntimeEffectObservationRequest,
    RuntimeEffectObservationResult,
    RuntimeEffectObservedAbsent,
    RuntimeEffectObservedConflict,
    RuntimeEffectObservedIndeterminate,
    RuntimeEffectObservedSucceeded,
    RuntimeEffectObserverUnsupported,
)
from control_plane_kit_core.runtime_effects import (
    RuntimeEffectKind,
    RuntimeEffectRequest,
)
from control_plane_kit_core.secrets import (
    AuthorizedSecretResolver,
    SecretReference,
    SecretResolutionError,
    SecretUseIntent,
    require_authorized_secret,
)
from control_plane_kit_core.types import RuntimeKind

from control_plane_kit_interpreters.docker.runtime import (
    _cpk_ownership_labels,
    _container_name,
    _network_name,
    _node_labels,
    _runtime_labels,
)
from control_plane_kit_interpreters.docker.sdk import (
    DockerSdkClient,
    DockerSdkImageInspection,
    DockerSdkResourceInspection,
    DockerTlsClientConfig,
    _is_canonical_sha256_image_id,
)
from control_plane_kit_interpreters.secrets import secret_resolution_grant_for


class _Postcondition(Enum):
    CONFIRMED = "confirmed"
    ABSENT = "absent"
    CONFLICT = "conflict"
    UNESTABLISHED = "unestablished"
    UNSUPPORTED = "unsupported"


_OPERATIONS = {
    StartNode: "start-node",
    ReconcileNode: "reconcile-node",
    StopNode: "stop-node",
    RemoveNodeResource: "remove-node-resource",
    StartRuntime: "start-runtime",
    ReconcileRuntime: "reconcile-runtime",
    StopRuntime: "stop-runtime",
    RemoveRuntimeResource: "remove-runtime-resource",
    WaitForHealthy: "wait-for-healthy",
}
_RESULTS = {
    _Postcondition.CONFIRMED: (RuntimeEffectObservedSucceeded, None),
    _Postcondition.ABSENT: (RuntimeEffectObservedAbsent, None),
    _Postcondition.CONFLICT: (
        RuntimeEffectObservedConflict,
        RuntimeEffectObservationFailure(
            "docker.observation-conflict",
            "Docker resource conflicts with the requested postcondition.",
        ),
    ),
    _Postcondition.UNESTABLISHED: (
        RuntimeEffectObservedIndeterminate,
        RuntimeEffectObservationFailure(
            "docker.observation-indeterminate",
            "Docker resource postcondition could not be established.",
        ),
    ),
    _Postcondition.UNSUPPORTED: (
        RuntimeEffectObserverUnsupported,
        RuntimeEffectObservationFailure(
            "docker.observer-unsupported",
            "Docker observation is not supported for this request.",
        ),
    ),
}
_RUNTIME_READS = (StartRuntime, ReconcileRuntime, RemoveRuntimeResource)
_NODE_READS = (StartNode, ReconcileNode, StopNode, RemoveNodeResource)
_TLS_USES = (
    ("ca_certificate", SecretUseIntent.DOCKER_REMOTE_TLS_CA_CERTIFICATE),
    ("client_certificate", SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_CERTIFICATE),
    ("client_key", SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_KEY),
)
_MALFORMED_INSPECTIONS = frozenset({
    "Docker image inspection was malformed",
    "Docker container image inspection was malformed",
    "Docker container state inspection was malformed",
    "Docker network membership inspection was malformed",
    "Docker published port inspection was malformed",
    "Docker private address inspection was malformed",
})
_SDK_INSPECTION_ORIGINS = frozenset({
    DockerSdkClient.inspect_image.__code__,
    DockerSdkClient._image_id.__code__,
    DockerSdkClient._container_running.__code__,
    DockerSdkClient._network_names.__code__,
    DockerSdkClient._published_ports.__code__,
    DockerSdkClient._private_addresses.__code__,
})


@dataclass(frozen=True)
class DockerRuntimeEffectObserver:
    """Confirm resource postconditions, never content, readiness, or endpoints."""

    client: DockerSdkClient = field(repr=False)
    authorized_secret_resolver: AuthorizedSecretResolver | None = field(
        default=None, repr=False,
    )

    def observe(
        self,
        request: RuntimeEffectObservationRequest,
        authority: object | None,
    ) -> RuntimeEffectObservationResult:
        if type(request) is not RuntimeEffectObservationRequest:
            raise TypeError("Docker observer requires RuntimeEffectObservationRequest")
        runtime_request = request.runtime_request
        admission = _admit(runtime_request)
        if admission is not None:
            return _result(request, admission)

        try:
            binding = self._client_binding(runtime_request, authority)
        except Exception as error:
            if (
                not isinstance(error, SecretResolutionError)
                and not _provider_error(error)
            ):
                raise
            return _result(request, _Postcondition.UNESTABLISHED)
        if isinstance(binding, _Postcondition):
            return _result(request, binding)
        client, close_after_observation = binding

        postcondition = _Postcondition.UNESTABLISHED
        read_error: BaseException | None = None
        close_error: BaseException | None = None
        try:
            postcondition = _inspect(runtime_request, client)
        except BaseException as error:
            read_error = error
        if close_after_observation:
            try:
                client.close()
            except BaseException as error:
                close_error = error

        # Close outside the read exception handler so it cannot rewrite context.
        for error in (read_error, close_error):
            if error is not None and not _provider_error(error):
                raise error
        if read_error is not None or close_error is not None:
            postcondition = _Postcondition.UNESTABLISHED
        return _result(request, postcondition)

    def _client_binding(
        self,
        request: RuntimeEffectRequest,
        authority: object | None,
    ) -> tuple[DockerSdkClient, bool] | _Postcondition:
        if authority is None:
            if request.authority_ref is not None:
                return _Postcondition.UNESTABLISHED
            return self.client, False
        runtime_kind = getattr(authority, "runtime_kind", None)
        if getattr(runtime_kind, "value", runtime_kind) != RuntimeKind.DOCKER.value:
            return _Postcondition.UNSUPPORTED
        authority_kind = getattr(authority, "authority_kind", None)
        authority_kind = getattr(authority_kind, "value", authority_kind)
        if authority_kind == "local-docker-socket":
            return self.client, False
        if authority_kind != "remote-docker-tls":
            return _Postcondition.UNSUPPORTED

        material = getattr(authority, "authority", None)
        endpoint = getattr(material, "endpoint", None)
        if (
            not isinstance(endpoint, str)
            or not endpoint.startswith("tcp://")
            or self.authorized_secret_resolver is None
        ):
            return _Postcondition.UNESTABLISHED
        references = tuple(getattr(material, name, None) for name, _ in _TLS_USES)
        if not all(type(reference) is SecretReference for reference in references):
            return _Postcondition.UNESTABLISHED

        # Admit all three exact grants before consuming any connection secret.
        grants = tuple(
            secret_resolution_grant_for(request.secret_resolution_grants, reference, intent)
            for reference, (_, intent) in zip(references, _TLS_USES, strict=True)
        )
        ca, certificate, key = tuple(
            require_authorized_secret(self.authorized_secret_resolver, grant)
            for grant in grants
        )
        client = DockerSdkClient.from_authority(
            DockerTlsClientConfig(endpoint, ca, certificate, key),
            docker_module=self.client.docker_module,
        )
        return client, True


def _admit(request: RuntimeEffectRequest) -> _Postcondition | None:
    if (
        request.kind is not RuntimeEffectKind.REALIZE_ACTIVITY
        or request.runtime_kind is not RuntimeKind.DOCKER
    ):
        return _Postcondition.UNSUPPORTED
    operation_type = type(request.operation)
    if operation_type in _RUNTIME_READS:
        return None
    if operation_type not in _NODE_READS:
        return _Postcondition.UNSUPPORTED
    if (
        len(request.products) != 1
        or request.products[0].node_id != request.operation.target.node_id
    ):
        return _Postcondition.UNESTABLISHED
    if operation_type in (StartNode, ReconcileNode):
        contract = request.products[0].product.runtime_contract
        # Fingerprints attest declared intent, not delivered content bytes.
        if (
            contract.configuration_artifacts
            or contract.secret_deliveries
            or contract.retained_data_mounts
            or request.authority_deliveries
            or (operation_type is ReconcileNode and contract.verification.checks)
        ):
            return _Postcondition.UNSUPPORTED
    return None


def _inspect(request: RuntimeEffectRequest, client: DockerSdkClient) -> _Postcondition:
    operation_type = type(request.operation)
    if operation_type in _RUNTIME_READS:
        runtime_id = request.operation.target.runtime_id
        name = _network_name(request, runtime_id)
        network = client.inspect_network(name)
        if network is None:
            return _Postcondition.ABSENT
        ownership = _ownership(network, name, _runtime_labels(request, runtime_id))
        if ownership is not None:
            return ownership
        if operation_type is RemoveRuntimeResource:
            return _Postcondition.UNESTABLISHED
        return _Postcondition.CONFIRMED

    material = request.products[0]
    container_name = _container_name(request, material.node_id)
    network_name = _network_name(request, material.runtime_id)
    network = None
    if operation_type in (StartNode, ReconcileNode):
        network = client.inspect_network(network_name)
        if network is not None:
            ownership = _ownership(
                network, network_name, _runtime_labels(request, material.runtime_id),
            )
            if ownership is not None:
                return ownership
    container = client.inspect_container(container_name)
    if container is None:
        return _Postcondition.ABSENT
    ownership = _ownership(
        container,
        container_name,
        _node_labels(request, material),
        cpk_labels_only=True,
    )
    if ownership is not None:
        return ownership
    if operation_type is RemoveNodeResource:
        return _Postcondition.UNESTABLISHED
    if type(container.running) is not bool:
        return _Postcondition.UNESTABLISHED
    if operation_type is StopNode:
        return (
            _Postcondition.UNESTABLISHED
            if container.running else _Postcondition.CONFIRMED
        )
    if network is None or not container.running:
        return _Postcondition.UNESTABLISHED

    reference = material.product.image.execution_reference
    image = client.inspect_image(reference)
    if (
        not isinstance(image, DockerSdkImageInspection)
        or reference not in image.repo_digests
        or not _is_canonical_sha256_image_id(container.image_id)
    ):
        return _Postcondition.UNESTABLISHED
    if (
        container.image_id != image.image_id
        or container.network_names != (network_name,)
    ):
        return _Postcondition.CONFLICT
    return _Postcondition.CONFIRMED


def _ownership(
    inspection: DockerSdkResourceInspection,
    name: str,
    labels: Mapping[str, str],
    *,
    cpk_labels_only: bool = False,
) -> _Postcondition | None:
    if (
        not isinstance(inspection, DockerSdkResourceInspection)
        or not isinstance(inspection.labels, Mapping)
    ):
        return _Postcondition.UNESTABLISHED
    observed_labels = dict(inspection.labels)
    expected_labels = dict(labels)
    if cpk_labels_only:
        observed_labels = _cpk_ownership_labels(observed_labels)
        expected_labels = _cpk_ownership_labels(expected_labels)
    if inspection.name != name or observed_labels != expected_labels:
        return _Postcondition.CONFLICT
    return None


def _provider_error(error: BaseException) -> bool:
    if isinstance(error, OSError):
        return True
    if not isinstance(error, Exception):
        return False
    if type(error) is RuntimeError:
        # Recognize only fixed signals raised by the frozen SDK normalizers.
        traceback = error.__traceback__
        while traceback is not None and traceback.tb_next is not None:
            traceback = traceback.tb_next
        return (
            len(error.args) == 1
            and isinstance(error.args[0], str)
            and error.args[0] in _MALFORMED_INSPECTIONS
            and traceback is not None
            and traceback.tb_frame.f_code in _SDK_INSPECTION_ORIGINS
        )
    try:
        docker_errors = import_module("docker.errors")
        request_errors = import_module("requests.exceptions")
    except ImportError:
        return False
    return isinstance(error, (
        docker_errors.DockerException,
        request_errors.ConnectionError,
        request_errors.Timeout,
    ))


def _result(
    request: RuntimeEffectObservationRequest,
    postcondition: _Postcondition,
) -> RuntimeEffectObservationResult:
    result_type, failure = _RESULTS[postcondition]
    return result_type(
        effect_id=request.effect_id,
        request_fingerprint=request.request_fingerprint,
        evidence=RuntimeEffectObservationEvidence({
            "operation": _OPERATIONS.get(
                type(request.runtime_request.operation), "unsupported-operation",
            ),
            "postcondition": postcondition.value,
        }),
        failure=failure,
        observations=(),
    )
