from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import os
import re
import time
from typing import Mapping

from control_plane_kit_core.planning import (
    ActivityOperation,
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
from control_plane_kit_core.probe_intents import EndpointContext, LiteralEndpointMaterial
from control_plane_kit_core.runtime_authority import RuntimeAuthorityAccessDeliveryKind
from control_plane_kit_core.runtime_effects import (
    RuntimeEffectFailure,
    RuntimeEffectKind,
    RuntimeEffectRequest,
    RuntimeEffectResult,
    RuntimeProductMaterial,
)
from control_plane_kit_core.secrets import (
    AuthorizedSecretResolver,
    SecretReference,
    SecretResolutionCode,
    SecretResolutionError,
    SecretResolutionGrant,
    SecretResolver,
    SecretUseIntent,
    require_authorized_secret,
    require_resolved_secret,
)
from control_plane_kit_core.types import RuntimeKind
from control_plane_kit_core.verification import (
    HttpCheck,
    HttpVerificationEvidence,
    PostgresQueryCheck,
    VerificationCapability,
    VerificationCompleted,
    VerificationOutcome,
    VerificationUnsupported,
)

from control_plane_kit_interpreters.docker.sdk import (
    DockerLocalAmbientClientConfig,
    DockerRegistryAuthConfig,
    DockerSdkBindMount,
    DockerSdkClient,
    DockerTlsClientConfig,
    DockerSdkConfigurationMount,
    DockerSdkPortBinding,
    DockerSdkSecretMount,
    runtime_endpoint_observations,
    verify_published_ports,
)
from control_plane_kit_interpreters.probes.security import ProbeAddressPolicy
from control_plane_kit_interpreters.secrets import (
    ImagePullCredentialDenied,
    ImagePullCredentialMissing,
    ImagePullCredentialResolved,
    ImagePullCredentialResolver,
    ResolvedSecretDeliveries,
    SecretFileRuntimeMaterial,
    parse_image_pull_credential,
    resolve_authorized_secret_deliveries,
    resolve_secret_deliveries,
    secret_resolution_grant_for,
)
from control_plane_kit_interpreters.verification import (
    HttpVerificationInterpreter,
    PostgresSelectOneTransport,
    PostgresVerificationInterpreter,
    VerificationCheckMaterial,
    verification_identity,
)

_LOCAL_DOCKER_SOCKET_PATH = "/var/run/docker.sock"


_LABEL_PREFIX = "org.openj92.cpk"
_SEGMENT = re.compile(r"[^a-zA-Z0-9_.-]+")


@dataclass(frozen=True)
class _AuthorityDeliveryMaterial:
    mounts: tuple[DockerSdkBindMount, ...] = ()
    supplementary_groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class DockerRuntimeInterpreter:
    """Interpret pure runtime-effect requests with the Python Docker SDK."""

    client: DockerSdkClient
    http_transport: object | None = None
    postgres_transport: PostgresSelectOneTransport | None = None
    image_pull_credentials: ImagePullCredentialResolver | None = None
    secret_resolver: SecretResolver | None = None
    authorized_secret_resolver: AuthorizedSecretResolver | None = None

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
                case ReconcileRuntime():
                    return self._reconcile_runtime(request)
                case StopRuntime():
                    return self._stop_runtime(request)
                case RemoveRuntimeResource():
                    return self._remove_runtime(request)
                case StartNode():
                    return self._start_node(request)
                case ReconcileNode():
                    return self._reconcile_node(request)
                case WaitForHealthy():
                    return self._wait_for_healthy(request)
                case StopNode():
                    return self._stop_node(request)
                case RemoveNodeResource():
                    return self._remove_node(request)
                case _:
                    return _unsupported(
                        request,
                        "docker.unsupported-activity-operation",
                    )
        except _DockerInterpreterUnsupportedAuthorityError as error:
            return _unsupported(request, error.code)
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

    def execute_with_authority(
        self,
        request: RuntimeEffectRequest,
        authority: object,
    ) -> RuntimeEffectResult:
        if not isinstance(request, RuntimeEffectRequest):
            raise TypeError("DockerRuntimeInterpreter requires RuntimeEffectRequest")
        if request.kind is not RuntimeEffectKind.REALIZE_ACTIVITY:
            return _unsupported(request, "docker.unsupported-effect-kind")
        if request.runtime_kind is not RuntimeKind.DOCKER:
            return _unsupported(request, "docker.unsupported-runtime-kind")
        try:
            client = _client_for_runtime_authority(
                self.client,
                authority,
                request,
                self.authorized_secret_resolver,
                self.secret_resolver,
            )
        except _DockerInterpreterUnsupportedAuthorityError as error:
            return _unsupported(request, error.code)
        except _DockerInterpreterPreconditionError as error:
            return _failed(request, error.code, str(error))
        except Exception as error:
            return RuntimeEffectResult.uncertain(
                request.effect_id,
                RuntimeEffectFailure(
                    "docker.runtime-authority-uncertain",
                    _bounded_error_message(error),
                ),
            )
        return replace(self, client=client).execute(request)

    def _reconcile_runtime(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        runtime_id = _runtime_target(request.operation)
        network_name = _network_name(request, runtime_id)
        labels = _runtime_labels(request, runtime_id)
        inspection = self.client.inspect_network(network_name)
        if inspection is None:
            self.client.create_network(name=network_name, labels=labels)
            action = "created"
        else:
            _require_runtime_owner(inspection.labels, labels, "network")
            action = "reused"
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": action,
                "runtime_id": runtime_id,
                "network": network_name,
            },
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
            _require_runtime_owner(inspection.labels, labels, "network")
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": "logical-stop",
                "runtime_id": runtime_id,
                "network": network_name,
            },
        )

    def _remove_runtime(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        runtime_id = _runtime_target(request.operation)
        network_name = _network_name(request, runtime_id)
        labels = _runtime_labels(request, runtime_id)
        inspection = self.client.inspect_network(network_name)
        if inspection is None:
            action = "absent"
        else:
            _require_runtime_owner(inspection.labels, labels, "network")
            self.client.remove_network(network_name)
            action = "removed"
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": action,
                "runtime_id": runtime_id,
                "network": network_name,
            },
        )

    def _start_node(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        material = _single_product(request)
        authority_delivery = _authority_delivery_material(request)
        secrets = _resolve_product_secret_deliveries(
            material,
            request,
            self.authorized_secret_resolver,
            self.secret_resolver,
        )
        auth_config = _image_pull_auth_config(
            material,
            request,
            self.authorized_secret_resolver,
            self.image_pull_credentials,
        )
        runtime_id = material.runtime_id
        network_name = _network_name(request, runtime_id)
        runtime_labels = _runtime_labels(request, runtime_id)
        network = self.client.inspect_network(network_name)
        if network is None:
            self.client.create_network(name=network_name, labels=runtime_labels)
        else:
            _require_runtime_owner(network.labels, runtime_labels, "network")

        container_name = _container_name(request, material.node_id)
        labels = _node_labels(request, material)
        inspection = self.client.inspect_container(container_name)
        if inspection is None:
            self._create_node_container(
                request,
                material,
                container_name,
                labels,
                auth_config,
                secrets,
                authority_delivery,
            )
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
        private_host = material.node_id
        if observed is not None:
            _require_owned(observed.labels, labels, "container")
            published = observed.published_ports
            private_host = _private_host_for_runtime(request, material, observed)
        port_bindings = _private_provider_ports(material)
        observations = runtime_endpoint_observations(
            subject_id=material.node_id,
            graph_id=request.source.desired_graph_id,
            private_host=private_host,
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

    def _reconcile_node(self, request: RuntimeEffectRequest) -> RuntimeEffectResult:
        material = _single_product(request)
        authority_delivery = _authority_delivery_material(request)
        secrets = _resolve_product_secret_deliveries(
            material,
            request,
            self.authorized_secret_resolver,
            self.secret_resolver,
        )
        auth_config = _image_pull_auth_config(
            material,
            request,
            self.authorized_secret_resolver,
            self.image_pull_credentials,
        )
        runtime_id = material.runtime_id
        network_name = _network_name(request, runtime_id)
        runtime_labels = _runtime_labels(request, runtime_id)
        network = self.client.inspect_network(network_name)
        if network is None:
            self.client.create_network(name=network_name, labels=runtime_labels)
        else:
            _require_runtime_owner(network.labels, runtime_labels, "network")

        container_name = _container_name(request, material.node_id)
        labels = _node_labels(request, material)
        inspection = self.client.inspect_container(container_name)
        if inspection is None:
            self._create_node_container(
                request,
                material,
                container_name,
                labels,
                auth_config,
                secrets,
                authority_delivery,
            )
            action = "created"
        elif _fingerprint_matches(inspection.labels, labels):
            _require_owned(inspection.labels, labels, "container")
            if inspection.running:
                action = "reused"
            else:
                self.client.start_container(container_name)
                action = "started"
        else:
            _require_node_owner(inspection.labels, labels, "container")
            self.client.remove_container(container_name)
            self._create_node_container(
                request,
                material,
                container_name,
                labels,
                auth_config,
                secrets,
                authority_delivery,
            )
            action = "recreated"

        published = ()
        observed = self.client.inspect_container(container_name)
        private_host = material.node_id
        if observed is not None:
            _require_owned(observed.labels, labels, "container")
            published = observed.published_ports
            private_host = _private_host_for_runtime(request, material, observed)
        observations = runtime_endpoint_observations(
            subject_id=material.node_id,
            graph_id=request.source.desired_graph_id,
            private_host=private_host,
            provider_ports=_private_provider_ports(material),
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

    def _wait_for_healthy(
        self,
        request: RuntimeEffectRequest,
    ) -> RuntimeEffectResult:
        material = _single_product(request)
        checks = material.product.runtime_contract.verification.checks
        if not checks:
            return RuntimeEffectResult.succeeded(
                request.effect_id,
                evidence={
                    "action": "no-verification-contract",
                    "node_id": material.node_id,
                },
            )
        endpoints = {
            observation.socket_name: observation
            for observation in self._runtime_private_endpoint_observations(
                request,
                material,
            )
        }
        completed: list[dict[str, object]] = []
        for check in checks:
            endpoint = endpoints.get(check.provider_socket)
            if endpoint is None:
                return _failed(
                    request,
                    "docker.health-endpoint-missing",
                    "health check provider socket has no runtime endpoint",
                )
            if not isinstance(endpoint.address, LiteralEndpointMaterial):
                return _failed(
                    request,
                    "docker.health-endpoint-unresolved",
                    "health endpoint is not literal runtime material",
                )
            if isinstance(check, HttpCheck):
                result = self._execute_http_health_check(
                    material,
                    request,
                    check,
                    endpoint,
                )
            elif isinstance(check, PostgresQueryCheck):
                result = self._execute_postgres_health_check(
                    material,
                    request,
                    check,
                    endpoint,
                )
            else:
                return _unsupported(request, "docker.health-check-unsupported")
            if isinstance(result, VerificationUnsupported):
                return _unsupported(request, "docker.health-check-unsupported")
            if not isinstance(result, VerificationCompleted):
                return _failed(
                    request,
                    "docker.health-result-malformed",
                    "health verification returned malformed result",
                )
            completed.append(result.descriptor())
            if result.outcome is not VerificationOutcome.PASSED:
                return RuntimeEffectResult.failed(
                    request.effect_id,
                    RuntimeEffectFailure(
                        "docker.health-check-failed",
                        "health verification did not pass",
                        {"checks": completed},
                    ),
                )
        return RuntimeEffectResult.succeeded(
            request.effect_id,
            evidence={
                "action": "verified-healthy",
                "node_id": material.node_id,
                "checks": completed,
            },
        )

    def _execute_http_health_check(
        self,
        material: RuntimeProductMaterial,
        request: RuntimeEffectRequest,
        check: HttpCheck,
        endpoint,
    ):
        if endpoint.context is EndpointContext.RUNTIME_PRIVATE:
            return self._execute_runtime_private_http_health_check(
                material,
                request,
                check,
                endpoint,
            )
        single_attempt = replace(
            check,
            policy=replace(check.policy, maximum_attempts=1),
        )
        policy = ProbeAddressPolicy(
            runtime_private_authorities=frozenset((endpoint.address.value,)),
        )
        interpreter = HttpVerificationInterpreter(
            policy,
            transport=self.http_transport,
        )
        result = None
        for attempt in range(1, check.policy.maximum_attempts + 1):
            if attempt > 1:
                time.sleep(1)
            result = interpreter.execute(
                VerificationCheckMaterial(
                    material.node_id,
                    request.source.desired_graph_id,
                    single_attempt,
                    endpoint,
                )
            )
            if (
                isinstance(result, VerificationCompleted)
                and result.outcome is VerificationOutcome.PASSED
            ):
                return replace(result, attempts=attempt)
        assert result is not None
        if isinstance(result, VerificationCompleted):
            return replace(result, attempts=check.policy.maximum_attempts)
        return result

    def _execute_runtime_private_http_health_check(
        self,
        material: RuntimeProductMaterial,
        request: RuntimeEffectRequest,
        check: HttpCheck,
        endpoint,
    ):
        materialized = VerificationCheckMaterial(
            material.node_id,
            request.source.desired_graph_id,
            check,
            endpoint,
        )
        result = None
        for attempt in range(1, check.policy.maximum_attempts + 1):
            if attempt > 1:
                time.sleep(1)
            probe = self.client.run_http_probe(
                network=_network_name(request, material.runtime_id),
                url=endpoint.address.value + check.path,
                timeout_seconds=check.policy.timeout_seconds,
                maximum_response_bytes=check.policy.maximum_evidence_bytes,
            )
            evidence = (
                None
                if probe.status_code is None
                else HttpVerificationEvidence(
                    probe.status_code,
                    min(
                        probe.response_size,
                        check.policy.maximum_evidence_bytes,
                    ),
                )
            )
            if probe.timed_out:
                outcome = VerificationOutcome.TIMED_OUT
            elif probe.exit_code != 0 or probe.status_code is None:
                outcome = VerificationOutcome.FAILED
            elif probe.response_size > check.policy.maximum_evidence_bytes:
                outcome = VerificationOutcome.MALFORMED
            elif probe.status_code in check.expected_statuses:
                outcome = VerificationOutcome.PASSED
            else:
                outcome = VerificationOutcome.FAILED
            result = VerificationCompleted(
                verification_identity(materialized),
                VerificationCapability.HTTP,
                outcome,
                attempt,
                evidence,
            )
            if result.outcome is VerificationOutcome.PASSED:
                return result
        assert result is not None
        return replace(result, attempts=check.policy.maximum_attempts)

    def _execute_postgres_health_check(
        self,
        material: RuntimeProductMaterial,
        request: RuntimeEffectRequest,
        check: PostgresQueryCheck,
        endpoint,
    ):
        policy = ProbeAddressPolicy(
            runtime_private_authorities=frozenset((endpoint.address.value,)),
        )
        interpreter = PostgresVerificationInterpreter(
            policy,
            transport=self.postgres_transport,
            credential_resolver=(
                None
                if self.authorized_secret_resolver is not None
                else self.secret_resolver
            ),
            authorized_credential_resolver=self.authorized_secret_resolver,
            credential_grant=_optional_secret_resolution_grant(
                request,
                None
                if check.authentication is None
                else check.authentication.password_reference,
                SecretUseIntent.POSTGRES_PASSWORD,
            ),
        )
        return interpreter.execute(
            VerificationCheckMaterial(
                material.node_id,
                request.source.desired_graph_id,
                check,
                endpoint,
            )
        )

    def _runtime_private_endpoint_observations(
        self,
        request: RuntimeEffectRequest,
        material: RuntimeProductMaterial,
    ):
        private_host = material.node_id
        inspection = self._owned_container_inspection(request, material)
        if inspection is not None:
            private_host = _private_host_for_runtime(request, material, inspection)
        return runtime_endpoint_observations(
            subject_id=material.node_id,
            graph_id=request.source.desired_graph_id,
            private_host=private_host,
            provider_ports=_private_provider_ports(material),
            published_ports=(),
        )

    def _owned_container_inspection(
        self,
        request: RuntimeEffectRequest,
        material: RuntimeProductMaterial,
    ):
        container_name = _container_name(request, material.node_id)
        labels = _node_labels(request, material)
        inspection = self.client.inspect_container(container_name)
        if inspection is not None:
            _require_owned(inspection.labels, labels, "container")
        return inspection

    def _create_node_container(
        self,
        request: RuntimeEffectRequest,
        material: RuntimeProductMaterial,
        container_name: str,
        labels: Mapping[str, str],
        auth_config: DockerRegistryAuthConfig | None,
        secrets: ResolvedSecretDeliveries,
        authority_delivery: _AuthorityDeliveryMaterial,
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
                _require_node_owner(
                    inspection.labels,
                    volume_labels,
                    "configuration volume",
                )
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
                _require_node_owner(inspection.labels, volume_labels, "retained volume")

        secret_mounts = []
        for secret in secrets.files:
            volume_name = _secret_volume_name(request, material.node_id, secret)
            volume_labels = {
                **labels,
                f"{_LABEL_PREFIX}.volume.kind": "secret-file",
                f"{_LABEL_PREFIX}.secret.target": secret.target_path,
                f"{_LABEL_PREFIX}.secret.reference": secret.reference.reference_id,
            }
            inspection = self.client.inspect_volume(volume_name)
            expected_digest = _secret_value_digest(secret)
            if inspection is None:
                self.client.create_volume(name=volume_name, labels=volume_labels)
                self.client.materialize_secret_file(
                    volume_name,
                    secret.value,
                    secret.file_mode,
                )
            else:
                _require_node_owner(inspection.labels, volume_labels, "secret volume")
                digest = self.client.secret_file_digest(volume_name)
                if digest is None:
                    self.client.materialize_secret_file(
                        volume_name,
                        secret.value,
                        secret.file_mode,
                    )
                elif digest != expected_digest:
                    raise _DockerInterpreterPreconditionError(
                        "docker.secret-digest-conflict",
                        "owned secret volume has unexpected digest",
                    )
            secret_mounts.append(DockerSdkSecretMount(secret.target_path, volume_name))

        self.client.pull_image(
            material.product.image.execution_reference,
            auth_config=auth_config,
        )
        self.client.run_container(
            name=container_name,
            image=material.product.image.execution_reference,
            network=_network_name(request, material.runtime_id),
            aliases=(material.node_id,),
            environment=_container_environment(
                {
                    binding.name: binding.value
                    for binding in material.public_environment
                },
                {
                    binding.name: binding.value
                    for binding in material.socket_environment
                },
                secrets.environment,
            ),
            labels=labels,
            volumes=retained_volumes,
            configuration_mounts=tuple(configuration_mounts),
            secret_mounts=tuple(secret_mounts),
            bind_mounts=authority_delivery.mounts,
            supplementary_groups=authority_delivery.supplementary_groups,
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
            _require_node_owner(inspection.labels, labels, "container")
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
            _require_node_owner(inspection.labels, labels, "container")
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


class _DockerInterpreterUnsupportedAuthorityError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
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



def _client_for_runtime_authority(
    ambient_client: DockerSdkClient,
    authority: object,
    request: RuntimeEffectRequest,
    authorized_resolver: AuthorizedSecretResolver | None,
    legacy_resolver: SecretResolver | None,
) -> DockerSdkClient:
    if _authority_value(getattr(authority, "runtime_kind", None)) != RuntimeKind.DOCKER.value:
        raise _DockerInterpreterUnsupportedAuthorityError(
            "docker.runtime-authority-runtime-unsupported"
        )
    authority_kind = _authority_value(getattr(authority, "authority_kind", None))
    if authority_kind == "local-docker-socket":
        return DockerSdkClient.from_authority(
            DockerLocalAmbientClientConfig(),
            docker_module=ambient_client.docker_module,
        )
    if authority_kind != "remote-docker-tls":
        raise _DockerInterpreterUnsupportedAuthorityError(
            "docker.runtime-authority-kind-unsupported"
        )
    material = getattr(authority, "authority", None)
    endpoint = getattr(material, "endpoint", None)
    if not isinstance(endpoint, str) or not endpoint.startswith("tcp://"):
        raise _DockerInterpreterPreconditionError(
            "docker.runtime-authority-malformed",
            "remote Docker authority endpoint is malformed",
        )
    if authorized_resolver is None and legacy_resolver is None:
        raise _DockerInterpreterPreconditionError(
            "docker.runtime-authority-secret-resolver-required",
            "remote Docker authority requires a configured secret resolver",
        )
    ca_certificate = _resolve_runtime_authority_secret(
        request,
        authorized_resolver,
        legacy_resolver,
        getattr(material, "ca_certificate", None),
        SecretUseIntent.DOCKER_REMOTE_TLS_CA_CERTIFICATE,
    )
    client_certificate = _resolve_runtime_authority_secret(
        request,
        authorized_resolver,
        legacy_resolver,
        getattr(material, "client_certificate", None),
        SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_CERTIFICATE,
    )
    client_key = _resolve_runtime_authority_secret(
        request,
        authorized_resolver,
        legacy_resolver,
        getattr(material, "client_key", None),
        SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_KEY,
    )
    return DockerSdkClient.from_authority(
        DockerTlsClientConfig(
            endpoint=endpoint,
            ca_certificate=ca_certificate,
            client_certificate=client_certificate,
            client_key=client_key,
        ),
        docker_module=ambient_client.docker_module,
    )


def _authority_delivery_material(
    request: RuntimeEffectRequest,
) -> _AuthorityDeliveryMaterial:
    mounts = []
    supplementary_groups = []
    for delivery in request.authority_deliveries:
        if (
            delivery.delivery_kind
            is RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT
        ):
            mounts.append(
                DockerSdkBindMount(
                    source_path=_LOCAL_DOCKER_SOCKET_PATH,
                    target_path=_LOCAL_DOCKER_SOCKET_PATH,
                    read_only=False,
                )
            )
            supplementary_groups.append(_local_docker_socket_group())
            continue
        raise _DockerInterpreterUnsupportedAuthorityError(
            "docker.runtime-authority-delivery-unsupported"
        )
    return _AuthorityDeliveryMaterial(
        mounts=tuple(mounts),
        supplementary_groups=tuple(supplementary_groups),
    )


def _local_docker_socket_group() -> str:
    try:
        return str(os.stat(_LOCAL_DOCKER_SOCKET_PATH).st_gid)
    except OSError as error:
        raise _DockerInterpreterPreconditionError(
            "docker.local-socket-delivery-unavailable",
            "local Docker socket delivery requires an accessible Docker socket",
        ) from error


def _resolve_runtime_authority_secret(
    request: RuntimeEffectRequest,
    authorized_resolver: AuthorizedSecretResolver | None,
    legacy_resolver: SecretResolver | None,
    reference: object,
    intent: SecretUseIntent,
):
    if not isinstance(reference, SecretReference):
        raise _DockerInterpreterPreconditionError(
            "docker.runtime-authority-secret-reference-malformed",
            "remote Docker authority secret reference is malformed",
        )
    try:
        if authorized_resolver is not None:
            grant = secret_resolution_grant_for(
                request.secret_resolution_grants,
                reference,
                intent,
            )
            return require_authorized_secret(authorized_resolver, grant)
        assert legacy_resolver is not None
        return require_resolved_secret(legacy_resolver, reference)
    except SecretResolutionError as error:
        code = getattr(error, "code", None)
        suffix = _authority_value(code) if code is not None else "malformed"
        raise _DockerInterpreterPreconditionError(
            f"docker.runtime-authority-secret-{suffix}",
            "remote Docker authority secret could not be resolved",
        ) from error


def _authority_value(value: object) -> object:
    return getattr(value, "value", value)


def _image_pull_auth_config(
    material: RuntimeProductMaterial,
    request: RuntimeEffectRequest,
    authorized_resolver: AuthorizedSecretResolver | None,
    legacy_resolver: ImagePullCredentialResolver | None,
) -> DockerRegistryAuthConfig | None:
    authority = material.pull_authority
    if authority is None:
        return None
    if not authority.permits(material.product.image):
        raise _DockerInterpreterPreconditionError(
            "docker.image-pull-authority-scope-mismatch",
            "image pull authority does not cover product image",
        )
    if authorized_resolver is not None:
        try:
            grant = secret_resolution_grant_for(
                request.secret_resolution_grants,
                authority.credential_reference,
                SecretUseIntent.OCI_PULL_CREDENTIAL,
            )
            credential = parse_image_pull_credential(
                require_authorized_secret(authorized_resolver, grant)
            )
        except SecretResolutionError as error:
            if error.code is SecretResolutionCode.MISSING:
                error_code = "docker.image-pull-credential-missing"
                message = "image pull credential could not be resolved"
            elif error.code is SecretResolutionCode.DENIED:
                error_code = "docker.image-pull-credential-denied"
                message = "image pull credential is outside interpreter authority"
            else:
                error_code = "docker.image-pull-credential-malformed"
                message = "image pull credential resolver returned malformed result"
            raise _DockerInterpreterPreconditionError(error_code, message) from error
        return DockerRegistryAuthConfig(
            username=credential.username,
            password=credential.password,
            identitytoken=credential.identitytoken,
        )
    if legacy_resolver is None:
        raise _DockerInterpreterPreconditionError(
            "docker.image-pull-authority-required",
            "image pull authority requires a configured credential resolver",
        )
    result = legacy_resolver.resolve(authority)
    match result:
        case ImagePullCredentialResolved(credential=credential):
            return DockerRegistryAuthConfig(
                username=credential.username,
                password=credential.password,
                identitytoken=credential.identitytoken,
            )
        case ImagePullCredentialMissing():
            raise _DockerInterpreterPreconditionError(
                "docker.image-pull-credential-missing",
                "image pull credential could not be resolved",
            )
        case ImagePullCredentialDenied():
            raise _DockerInterpreterPreconditionError(
                "docker.image-pull-credential-denied",
                "image pull credential is outside interpreter authority",
            )
        case _:
            raise _DockerInterpreterPreconditionError(
                "docker.image-pull-credential-malformed",
                "image pull credential resolver returned malformed result",
            )

def _runtime_target(operation: ActivityOperation) -> str:
    target = getattr(operation, "target", None)
    runtime_id = getattr(target, "runtime_id", None)
    if not isinstance(runtime_id, str) or not runtime_id:
        raise _DockerInterpreterPreconditionError(
            "docker.runtime-target-required",
            "Docker runtime activity requires a runtime target",
        )
    return runtime_id


def _resolve_product_secret_deliveries(
    material: RuntimeProductMaterial,
    request: RuntimeEffectRequest,
    authorized_resolver: AuthorizedSecretResolver | None,
    legacy_resolver: SecretResolver | None,
) -> ResolvedSecretDeliveries:
    deliveries = material.product.runtime_contract.secret_deliveries
    try:
        if authorized_resolver is not None:
            return resolve_authorized_secret_deliveries(
                deliveries,
                grants=request.secret_resolution_grants,
                resolver=authorized_resolver,
            )
        return resolve_secret_deliveries(deliveries, resolver=legacy_resolver)
    except SecretResolutionError as error:
        if authorized_resolver is None and legacy_resolver is None and deliveries:
            error_code = "docker.secret-resolution-required"
            message = "Docker runtime interpreter requires secret resolver"
        else:
            error_code = f"docker.secret-resolution-{error.code.value}"
            message = "secret delivery could not be resolved"
        raise _DockerInterpreterPreconditionError(
            error_code,
            message,
        ) from error
    except Exception as error:
        raise _DockerInterpreterPreconditionError(
            "docker.secret-resolution-malformed",
            "secret resolver returned malformed material",
        ) from error


def _optional_secret_resolution_grant(
    request: RuntimeEffectRequest,
    reference: SecretReference | None,
    intent: SecretUseIntent,
) -> SecretResolutionGrant | None:
    if reference is None or not isinstance(reference, SecretReference):
        return None
    try:
        return secret_resolution_grant_for(
            request.secret_resolution_grants,
            reference,
            intent,
        )
    except SecretResolutionError:
        return None


def _container_environment(
    *parts: Mapping[str, str],
) -> dict[str, str]:
    values: dict[str, str] = {}
    for part in parts:
        for name, value in part.items():
            previous = values.setdefault(name, value)
            if previous != value:
                raise _DockerInterpreterPreconditionError(
                    "docker.environment-binding-conflict",
                    "container environment bindings conflict",
                )
    return values


def _secret_volume_name(
    request: RuntimeEffectRequest,
    node_id: str,
    secret: SecretFileRuntimeMaterial,
) -> str:
    return _volume_name(
        request,
        node_id,
        "secret-" + _digest(
            secret.target_path,
            secret.reference.reference_id,
        )[:16],
    )


def _secret_value_digest(secret: SecretFileRuntimeMaterial) -> str:
    return hashlib.sha256(secret.value.reveal().encode("utf-8")).hexdigest()


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


def _private_host_for_runtime(
    request: RuntimeEffectRequest,
    material: RuntimeProductMaterial,
    inspection,
) -> str:
    network_name = _network_name(request, material.runtime_id)
    address = inspection.private_addresses.get(network_name)
    return material.node_id if address is None else address


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
    if not _fingerprint_matches(observed, expected):
        raise _DockerInterpreterPreconditionError(
            f"docker.{resource}-ownership-conflict",
            f"Docker {resource} is not owned by this runtime effect",
        )


def _fingerprint_matches(
    observed: Mapping[str, str],
    expected: Mapping[str, str],
) -> bool:
    return (
        observed.get(f"{_LABEL_PREFIX}.fingerprint")
        == expected[f"{_LABEL_PREFIX}.fingerprint"]
    )


def _require_runtime_owner(
    observed: Mapping[str, str],
    expected: Mapping[str, str],
    resource: str,
) -> None:
    _require_label_owner(
        observed,
        expected,
        resource,
        ("kind", "workspace", "runtime"),
    )


def _require_node_owner(
    observed: Mapping[str, str],
    expected: Mapping[str, str],
    resource: str,
) -> None:
    _require_label_owner(
        observed,
        expected,
        resource,
        ("kind", "workspace", "runtime", "node"),
    )


def _require_label_owner(
    observed: Mapping[str, str],
    expected: Mapping[str, str],
    resource: str,
    keys: tuple[str, ...],
) -> None:
    for key in keys:
        label = f"{_LABEL_PREFIX}.{key}"
        if observed.get(label) != expected.get(label):
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
