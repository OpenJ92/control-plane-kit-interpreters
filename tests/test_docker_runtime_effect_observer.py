from __future__ import annotations

from dataclasses import replace
import inspect
import json
import unittest
from unittest.mock import patch

from docker import errors as docker_errors
from docker.errors import APIError, DockerException
from requests import Response
from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout

from control_plane_kit_core.planning import (
    NodeTarget, ReconcileNode, ReconcileRuntime, RemoveNodeResource, RemoveRuntimeResource,
    RuntimeTarget, StartNode, StartRuntime, StopNode, StopRuntime, WaitForHealthy,
)
from control_plane_kit_core.runtime_effect_observation import (
    RuntimeEffectObservationEvidence, RuntimeEffectObservationFailure,
    RuntimeEffectObservationRequest, RuntimeEffectObservedAbsent,
    RuntimeEffectObservedConflict, RuntimeEffectObservedIndeterminate,
    RuntimeEffectObservedSucceeded, RuntimeEffectObserverUnsupported,
    runtime_effect_observation_fingerprint,
)
from control_plane_kit_core.runtime_effects import EffectResultKind, ImagePullAuthority
from control_plane_kit_core.runtime_authority import (
    RuntimeAuthorityAccessDelivery, RuntimeAuthorityAccessDeliveryKind,
    RuntimeAuthorityDeliverySecretReference, RuntimeAuthorityReference,
    RuntimeEffectContractError,
)
from control_plane_kit_core.secrets import (
    SecretMissing, SecretReference, SecretResolved, SecretUseIntent, SecretValue,
)
from control_plane_kit_core.types import RuntimeKind

import control_plane_kit_interpreters.docker as docker_interpreters
from control_plane_kit_interpreters.docker.runtime import (
    _container_name, _network_name, _node_labels, _runtime_labels, _volume_name,
)
from control_plane_kit_interpreters.docker.sdk import (
    DockerSdkClient, DockerSdkImageInspection, DockerSdkResourceInspection,
    DockerTlsClientConfig,
)
from test_docker_start_node_phase_total import (
    HELLO_IMAGE_ID, HELLO_REFERENCE, _hello_request,
)
from test_docker_runtime_interpreter import (
    _grant, _local_runtime_authority, _material, _product_with_secret_delivery,
    _remote_tls_runtime_authority, _request, _unsupported_runtime_authority,
    _product_with_retained_data,
)
from test_docker_sdk_client import (
    FakeDockerClient, FakeDockerModule, FakeImage, FakeResource,
    MALFORMED_CONTAINER_STATES, MISLEADING_CONTAINER_STATUSES,
    StateInspectionResource, malform_container_state,
)


_OPERATIONS = {
    StartNode: "start-node", ReconcileNode: "reconcile-node",
    StopNode: "stop-node", RemoveNodeResource: "remove-node-resource",
    StartRuntime: "start-runtime", ReconcileRuntime: "reconcile-runtime",
    StopRuntime: "stop-runtime", RemoveRuntimeResource: "remove-runtime-resource",
    WaitForHealthy: "wait-for-healthy",
}
_RESULTS = {
    "succeeded": (RuntimeEffectObservedSucceeded, "confirmed", None),
    "absent": (RuntimeEffectObservedAbsent, "absent", None),
    "conflict": (
        RuntimeEffectObservedConflict, "conflict",
        ("docker.observation-conflict", "Docker resource conflicts with the requested postcondition."),
    ),
    "indeterminate": (
        RuntimeEffectObservedIndeterminate, "unestablished",
        ("docker.observation-indeterminate", "Docker resource postcondition could not be established."),
    ),
    "observer-unsupported": (
        RuntimeEffectObserverUnsupported, "unsupported",
        ("docker.observer-unsupported", "Docker observation is not supported for this request."),
    ),
}


def _grant_for(request, reference, intent):
    return replace(
        _grant(reference, intent), workspace_id=request.source.workspace_id,
        run_id=request.source.run_id.value, activity_id=request.activity_id.value,
        effect_id=request.effect_id,
    )


def _remote_request(request=None):
    request = _request(StartRuntime(RuntimeTarget("docker")), products=()) if request is None else request
    authority = _remote_tls_runtime_authority()
    material = authority.authority
    uses = (
        ("ca-cert", material.ca_certificate, SecretUseIntent.DOCKER_REMOTE_TLS_CA_CERTIFICATE),
        ("client-cert", material.client_certificate, SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_CERTIFICATE),
        ("client-key", material.client_key, SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_KEY),
    )
    reference = RuntimeAuthorityReference("remote-docker")
    request = replace(
        request, authority_ref=reference,
        authority_deliveries=(RuntimeAuthorityAccessDelivery(
            reference, RuntimeAuthorityAccessDeliveryKind.REMOTE_DOCKER_TLS_SECRET_FILES,
            tuple(RuntimeAuthorityDeliverySecretReference(label, secret) for label, secret, _ in uses),
        ),),
        secret_resolution_grants=tuple(_grant_for(request, secret, intent) for _, secret, intent in uses),
    )
    ordered_grants = tuple(
        next(grant for grant in request.secret_resolution_grants if grant.intent is intent)
        for _, _, intent in uses
    )
    return request, authority, ordered_grants


class _ReadClient:
    docker_module = object()

    def __init__(self, request, *, fault=None):
        self.calls = []
        self.mutations = []
        self.fault = fault
        self.close_calls = 0
        self.request = request
        material = request.products[0] if request.products else None
        runtime_id = request.operation.target.runtime_id if material is None else material.runtime_id
        network = _network_name(request, runtime_id)
        self.network = DockerSdkResourceInspection(
            network, False, None, _runtime_labels(request, runtime_id),
        )
        self.container = None
        self.image = None
        self.volumes = {}
        if material is None:
            return
        container = _container_name(request, material.node_id)
        self.container = DockerSdkResourceInspection(
            container, True, material.product.image.execution_reference, _node_labels(request, material),
            image_id=HELLO_IMAGE_ID, network_names=(network,),
            private_addresses={network: "172.31.0.8"},
        )
        self.image = DockerSdkImageInspection(HELLO_IMAGE_ID, (material.product.image.execution_reference,))

    def _read(self, operation, coordinate):
        self.calls.append((operation, coordinate))
        if self.fault == operation:
            raise OSError("token=private http://provider.internal:2376 /var/run/docker.sock")
        return getattr(self, operation.removeprefix("inspect_"))

    def inspect_image(self, reference):
        return self._read("inspect_image", reference)

    def inspect_network(self, name):
        return self._read("inspect_network", name)

    def inspect_container(self, name):
        return self._read("inspect_container", name)

    def inspect_volume(self, name):
        self.calls.append(("inspect_volume", name))
        if self.fault == "inspect_volume":
            raise OSError("token=private")
        return self.volumes.get(name)

    def close(self):
        self.close_calls += 1
        if self.fault == "close":
            raise OSError("token=private")

    def __getattr__(self, name):
        def forbidden(*args, **kwargs):
            self.mutations.append(name)
            raise AssertionError("observer attempted mutation")
        return forbidden


class _Resolver:
    def __init__(self, *, missing=None):
        self.calls = []
        self.missing = missing

    def resolve(self, grant):
        self.calls.append(grant)
        if grant is self.missing:
            return SecretMissing(grant.reference)
        return SecretResolved(grant.reference, SecretValue("private-" + grant.intent.value))


class DockerRuntimeEffectObserverTests(unittest.TestCase):
    def observer(self, client, **kwargs):
        observer_type = getattr(docker_interpreters, "DockerRuntimeEffectObserver", None)
        self.assertIsNotNone(observer_type, "missing separate inspect-only Docker observer")
        return observer_type(client, **kwargs)

    def observe(self, request, client):
        before = repr((client.network, client.container, client.image, client.volumes))
        result = self.observer(client).observe(RuntimeEffectObservationRequest(request), None)
        self.assertEqual(client.mutations, [])
        self.assertEqual(before, repr((client.network, client.container, client.image, client.volumes)))
        return self.assert_observation(result, request)

    def assert_observation(self, result, request):
        kind = result.descriptor()["kind"]
        self.assertIn(kind, _RESULTS)
        result_type, postcondition, failure = _RESULTS[kind]
        self.assertIs(type(result), result_type)
        self.assertEqual(result.effect_id, request.effect_id)
        self.assertEqual(result.request_fingerprint, RuntimeEffectObservationRequest(request).request_fingerprint)
        self.assertEqual(len(runtime_effect_observation_fingerprint(result)), 64)
        self.assertEqual(result.observations, ())
        descriptor = result.descriptor()
        expected_failure = None if failure is None else {
            "code": failure[0], "message": failure[1], "details": {},
        }
        self.assertEqual(descriptor, {
            "kind": kind, "effect_id": request.effect_id,
            "request_fingerprint": RuntimeEffectObservationRequest(request).request_fingerprint,
            "evidence": {"operation": _OPERATIONS[type(request.operation)], "postcondition": postcondition},
            "failure": expected_failure, "observations": [],
        })
        text = json.dumps(descriptor)
        decoded = json.loads(text)
        reconstructed = result_type(
            decoded["effect_id"], decoded["request_fingerprint"],
            RuntimeEffectObservationEvidence(decoded["evidence"]),
            None if failure is None else RuntimeEffectObservationFailure(
                decoded["failure"]["code"], decoded["failure"]["message"],
            ),
        )
        self.assertEqual(reconstructed.descriptor(), descriptor)
        self.assertEqual(runtime_effect_observation_fingerprint(reconstructed), runtime_effect_observation_fingerprint(result))
        for forbidden in ("172.31", "provider.internal", "token=", "/var/run", HELLO_IMAGE_ID, HELLO_REFERENCE, "labels", "private-material"):
            self.assertNotIn(forbidden, text)
            self.assertNotIn(forbidden, repr(result))
        if result.failure is not None:
            self.assertEqual(set(result.failure.descriptor()["details"]), set())
        return kind

    def test_observe_signature_matches_accepted_two_argument_protocol(self):
        observer = self.observer(_ReadClient(_hello_request()))
        signature = inspect.signature(observer.observe)
        self.assertEqual(tuple(signature.parameters), ("request", "authority"))
        for parameter in signature.parameters.values():
            self.assertIs(parameter.kind, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_owned_running_start_is_confirmed_by_exact_reads_only(self):
        request = _hello_request()
        client = _ReadClient(request)
        self.assertEqual(self.observe(request, client), "succeeded")
        self.assertEqual(client.calls, [
            ("inspect_network", client.network.name),
            ("inspect_container", client.container.name),
            ("inspect_image", HELLO_REFERENCE),
        ])
        self.assertEqual(client.close_calls, 0)

    def test_absent_and_partial_resource_sets_never_authorize_success(self):
        for network, container, expected in ((False, False, "absent"), (True, False, "absent"), (False, True, "indeterminate")):
            with self.subTest(network=network, container=container):
                request = _hello_request()
                client = _ReadClient(request)
                if not network:
                    client.network = None
                if not container:
                    client.container = None
                self.assertEqual(self.observe(request, client), expected)

    def test_every_ownership_label_and_exact_coordinate_is_required(self):
        request = _hello_request()
        template = _ReadClient(request)
        for resource in ("network", "container"):
            inspection = getattr(template, resource)
            for key in inspection.labels:
                for value in (None, "foreign"):
                    with self.subTest(resource=resource, key=key, value=value):
                        client = _ReadClient(request)
                        labels = dict(inspection.labels)
                        if value is None:
                            del labels[key]
                        else:
                            labels[key] = value
                        setattr(client, resource, replace(inspection, labels=labels))
                        self.assertEqual(self.observe(request, client), "conflict")
            with self.subTest(resource=resource, wrong_name=True):
                client = _ReadClient(request)
                setattr(client, resource, replace(inspection, name="foreign"))
                self.assertEqual(self.observe(request, client), "conflict")

    def test_container_ownership_ignores_only_non_cpk_image_metadata(self):
        request = _hello_request()
        client = _ReadClient(request)
        client.container = replace(
            client.container,
            labels={
                **client.container.labels,
                "CI_BUILD_DATE": "2026-06-18 14:45:41.322332",
                "org.opencontainers.image.source": "https://github.com/cloudflare/cloudflared",
                "org.openj92.cpkx.near-prefix": "foreign",
            },
        )
        self.assertEqual(self.observe(request, client), "succeeded")

        client.container = replace(
            client.container,
            labels={
                **client.container.labels,
                "org.openj92.cpk.unexpected": "foreign",
            },
        )
        self.assertEqual(self.observe(request, client), "conflict")

    def test_changed_material_or_graph_cannot_reuse_prior_success(self):
        request = _hello_request()
        for changed in (
            replace(request, source=replace(request.source, desired_graph_id="different-graph")),
            replace(request, source=replace(request.source, plan_id="different-plan")),
            replace(request, products=(replace(request.products[0], public_environment=()),)),
        ):
            with self.subTest(request=changed.source.desired_graph_id, material=changed.products[0].public_environment):
                self.assertEqual(self.observe(changed, _ReadClient(request)), "conflict")

    def test_image_identity_and_exact_network_are_required(self):
        request = _hello_request()
        for image_id, networks in (("sha256:" + "f" * 64, None), (None, ()), (None, ("foreign",)), (None, (_network_name(request, "docker"), "foreign"))):
            with self.subTest(image_id=image_id, networks=networks):
                client = _ReadClient(request)
                client.container = replace(client.container, image_id=image_id or HELLO_IMAGE_ID, network_names=client.container.network_names if networks is None else networks)
                self.assertEqual(self.observe(request, client), "conflict")
        for image in (None, DockerSdkImageInspection(HELLO_IMAGE_ID, ())):
            with self.subTest(image=image):
                client = _ReadClient(request)
                client.image = image
                self.assertEqual(self.observe(request, client), "indeterminate")
                self.assertEqual(client.calls[-1], ("inspect_image", HELLO_REFERENCE))

    def test_stopped_owned_container_is_not_a_confirmed_start(self):
        request = _hello_request()
        client = _ReadClient(request)
        client.container = replace(client.container, running=False)
        self.assertEqual(self.observe(request, client), "indeterminate")

    def test_each_read_fault_is_bounded_and_stops_before_later_reads(self):
        request = _hello_request()
        sequence = ["inspect_network", "inspect_container", "inspect_image"]
        for index, fault in enumerate(sequence):
            with self.subTest(fault=fault):
                client = _ReadClient(request, fault=fault)
                self.assertEqual(self.observe(request, client), "indeterminate")
                self.assertEqual([name for name, _ in client.calls], sequence[:index + 1])

    def test_runtime_postcondition_matrix_is_conservative(self):
        request = _hello_request()
        for operation in (StartRuntime(RuntimeTarget("docker")), ReconcileRuntime(RuntimeTarget("docker")), RemoveRuntimeResource(RuntimeTarget("docker"))):
            for present in (False, True):
                with self.subTest(operation=type(operation).__name__, present=present):
                    changed = replace(request, operation=operation, products=())
                    client = _ReadClient(request)
                    if not present:
                        client.network = None
                    expected = "absent" if not present else ("indeterminate" if isinstance(operation, RemoveRuntimeResource) else "succeeded")
                    self.assertEqual(self.observe(changed, client), expected)
                    self.assertEqual(client.calls, [("inspect_network", _network_name(request, "docker"))])

    def test_node_stop_remove_and_reconcile_postconditions(self):
        from test_docker_runtime_interpreter import _request
        request = _hello_request()
        for operation in (StopNode(NodeTarget("hello")), RemoveNodeResource(NodeTarget("hello")), ReconcileNode(NodeTarget("hello"))):
            for state in ("absent", "running", "stopped"):
                with self.subTest(operation=type(operation).__name__, state=state):
                    changed = replace(request, operation=operation)
                    if isinstance(operation, ReconcileNode):
                        changed = _plain_node_request(ReconcileNode)
                    client = _ReadClient(changed)
                    if state == "absent":
                        client.container = None
                    elif state == "stopped":
                        client.container = replace(client.container, running=False)
                    expected = "absent" if state == "absent" else "indeterminate"
                    if (isinstance(operation, StopNode) and state == "stopped") or (isinstance(operation, ReconcileNode) and state == "running"):
                        expected = "succeeded"
                    self.assertEqual(self.observe(changed, client), expected)

    def test_unobservable_logical_stop_and_health_are_unsupported(self):
        for operation in (StopRuntime(RuntimeTarget("docker")), WaitForHealthy(NodeTarget("hello"))):
            with self.subTest(operation=type(operation).__name__):
                request = replace(_hello_request(), operation=operation)
                client = _ReadClient(request)
                self.assertEqual(self.observe(request, client), "observer-unsupported")
                self.assertEqual(client.calls, [])

    def test_product_secret_and_registry_credentials_are_never_resolved(self):
        authority = ImagePullAuthority("ghcr.io", "openj92/control-plane-kit-servers/hello-server", SecretReference("secret://test/registry"))
        for request in (_hello_request(pull_authority=authority), _request(StartNode(NodeTarget("api")), products=(_material(_product_with_secret_delivery()),))):
            with self.subTest(secret=bool(request.products[0].product.runtime_contract.secret_deliveries)):
                contract = request.products[0].product.runtime_contract
                delivery = contract.secret_deliveries[0] if contract.secret_deliveries else None
                grant = _grant_for(
                    request, authority.credential_reference if delivery is None else delivery.reference,
                    SecretUseIntent.OCI_PULL_CREDENTIAL if delivery is None else delivery.intent,
                )
                request = replace(request, secret_resolution_grants=(grant,))
                client = _ReadClient(request)
                resolver = _Resolver()
                result = self.observer(client, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), None)
                self.assertEqual(resolver.calls, [])
                self.assertEqual(client.mutations, [])
                expected = "observer-unsupported" if request.products[0].product.runtime_contract.secret_deliveries else "succeeded"
                self.assertEqual(self.assert_observation(result, request), expected)

    def test_configuration_readback_is_unsupported_without_materialization(self):
        request = _hello_request(with_configuration=True)
        artifact = request.products[0].product.runtime_contract.configuration_artifacts[0]
        name = _volume_name(request, "hello", artifact.artifact_id)
        for state in ("absent", "foreign", "exact"):
            with self.subTest(state=state):
                client = _ReadClient(request)
                labels = {**client.container.labels, "org.openj92.cpk.volume.kind": "configuration", "org.openj92.cpk.artifact": artifact.artifact_id, "org.openj92.cpk.artifact.digest": artifact.content_digest}
                if state != "absent":
                    client.volumes[name] = DockerSdkResourceInspection(name, False, None, labels if state == "exact" else {})
                self.assertEqual(self.observe(request, client), "observer-unsupported")
                self.assertEqual(client.calls, [])

    def test_stop_node_needs_no_configuration_or_secret_content_readback(self):
        from test_docker_runtime_interpreter import _material, _product_with_secret_delivery, _request
        requests = (_hello_request(with_configuration=True), _request(StartNode(NodeTarget("api")), products=(_material(_product_with_secret_delivery()),)))
        for request in requests:
            with self.subTest(node=request.products[0].node_id):
                request = replace(request, operation=StopNode(NodeTarget(request.products[0].node_id)))
                client = _ReadClient(request)
                client.container = replace(client.container, running=False)
                self.assertEqual(self.observe(request, client), "succeeded")
                self.assertNotIn("inspect_volume", [name for name, _ in client.calls])

    def test_retained_mount_realization_is_unsupported_regardless_of_volume_records(self):
        for operation_type in (StartNode, ReconcileNode):
            for volume_state in ("absent", "foreign", "exact"):
                with self.subTest(operation=operation_type.__name__, volume=volume_state):
                    request, client = _retained_fixture(operation_type, volume_state)
                    contract = request.products[0].product.runtime_contract
                    self.assertEqual(len(contract.retained_data_mounts), 1)
                    self.assertEqual(contract.configuration_artifacts, ())
                    self.assertEqual(contract.secret_deliveries, ())
                    self.assertEqual(contract.verification.checks, ())
                    self.assertEqual(request.authority_deliveries, ())
                    before = repr(client.volumes)
                    resolver = _Resolver()
                    with patch.object(DockerSdkClient, "from_authority") as factory:
                        result = self.observer(client, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), None)
                    with self.subTest(boundary="no-io-or-resolution"):
                        self.assertEqual(client.calls, [])
                        self.assertEqual(resolver.calls, [])
                        factory.assert_not_called()
                    with self.subTest(boundary="fixed-unsupported"):
                        self.assertEqual(self.assert_observation(result, request), "observer-unsupported")
                    self.assertEqual(client.mutations, [])
                    self.assertEqual(repr(client.volumes), before)

    def test_retained_mounts_preserve_stop_and_remove_without_volume_reads(self):
        for operation_type in (StopNode, RemoveNodeResource):
            for volume_state in ("absent", "foreign", "exact"):
                for state in ("absent", "running", "stopped", "foreign"):
                    with self.subTest(operation=operation_type.__name__, volume=volume_state, state=state):
                        request, client = _retained_fixture(operation_type, volume_state)
                        if state == "absent":
                            client.container = None
                        elif state == "foreign":
                            client.container = replace(client.container, labels={})
                        else:
                            client.container = replace(client.container, running=state == "running")
                        expected = {"absent": "absent", "foreign": "conflict"}.get(state, "indeterminate")
                        if operation_type is StopNode and state == "stopped":
                            expected = "succeeded"
                        before = repr(client.volumes)
                        resolver = _Resolver()
                        result = self.observer(client, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), None)
                        self.assertEqual(client.calls, [("inspect_container", _container_name(request, "api"))])
                        self.assertEqual(client.mutations, [])
                        self.assertEqual(resolver.calls, [])
                        self.assertEqual(repr(client.volumes), before)
                        self.assertEqual(self.assert_observation(result, request), expected)

    def test_reconcile_with_verification_is_unsupported_but_start_needs_no_health_probe(self):
        request = _hello_request()
        changed = replace(request, operation=ReconcileNode(NodeTarget("hello")))
        client = _ReadClient(changed)
        self.assertEqual(self.observe(changed, client), "observer-unsupported")
        self.assertEqual(client.calls, [])

    def test_unexpected_programming_exception_is_not_normalized(self):
        request = _hello_request()
        for error in (AssertionError("programming defect"), RuntimeError("programming defect")):
            with self.subTest(error=type(error).__name__):
                client = _ReadClient(request)
                observer = self.observer(client)
                with patch.object(client, "inspect_network", side_effect=error):
                    with self.assertRaises(type(error)) as caught:
                        observer.observe(RuntimeEffectObservationRequest(request), None)
                self.assertIs(caught.exception, error)
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)
                self.assertEqual(client.mutations, [])

    def test_local_authority_uses_ambient_client_without_resolver_or_close(self):
        for authority in (None, _local_runtime_authority()):
            with self.subTest(authority=authority is not None):
                request = _hello_request()
                client, resolver = _ReadClient(request), _Resolver()
                result = self.observer(client, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), authority)
                self.assertEqual(resolver.calls, [])
                self.assertEqual(client.close_calls, 0)
                self.assertEqual(client.mutations, [])
                self.assertEqual(self.assert_observation(result, request), "succeeded")

    def test_remote_authority_closes_exact_client_on_success_read_and_close_fault(self):
        for fault in (None, "inspect_network", "close"):
            with self.subTest(fault=fault):
                request, authority, grants = _remote_request()
                ambient, remote = _ReadClient(request), _ReadClient(request, fault=fault)
                resolver = _Resolver()
                with patch.object(DockerSdkClient, "from_authority", return_value=remote) as factory:
                    result = self.observer(ambient, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), authority)
                self.assertEqual(ambient.calls, [])
                self.assertEqual(ambient.close_calls, 0)
                self.assertEqual(remote.close_calls, 1)
                self.assertEqual(remote.mutations, [])
                self.assertEqual(remote.calls, [("inspect_network", _network_name(request, "docker"))])
                self.assertEqual(resolver.calls, list(grants))
                self.assertEqual(factory.call_count, 1)
                config = factory.call_args.args[0]
                self.assertIs(type(config), DockerTlsClientConfig)
                self.assertEqual(config.endpoint, authority.authority.endpoint)
                self.assertEqual(config.ca_certificate.reveal(), "private-" + grants[0].intent.value)
                self.assertEqual(config.client_certificate.reveal(), "private-" + grants[1].intent.value)
                self.assertEqual(config.client_key.reveal(), "private-" + grants[2].intent.value)
                self.assertEqual(factory.call_args.kwargs, {"docker_module": ambient.docker_module})
                self.assertEqual(self.assert_observation(result, request), "succeeded" if fault is None else "indeterminate")

    def test_unsupported_authority_never_inspects_or_resolves(self):
        request = _hello_request()
        client, resolver = _ReadClient(request), _Resolver()
        result = self.observer(client, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), _unsupported_runtime_authority())
        self.assertEqual(client.calls, [])
        self.assertEqual(resolver.calls, [])
        self.assertEqual(client.mutations, [])
        self.assertEqual(self.assert_observation(result, request), "observer-unsupported")

    def test_remote_client_closes_before_unexpected_error_propagates(self):
        for close_fault in (None, "close"):
            for error_type in (AssertionError, RuntimeError):
                with self.subTest(close_fault=close_fault, error_type=error_type.__name__):
                    request, authority, _ = _remote_request()
                    ambient, remote = _ReadClient(request), _ReadClient(request, fault=close_fault)
                    error = error_type("programming defect")
                    observer = self.observer(ambient, authorized_secret_resolver=_Resolver())
                    with patch.object(DockerSdkClient, "from_authority", return_value=remote):
                        with patch.object(remote, "inspect_network", side_effect=error):
                            with self.assertRaises(error_type) as caught:
                                observer.observe(RuntimeEffectObservationRequest(request), authority)
                    self.assertIs(caught.exception, error)
                    self.assertIsNone(error.__cause__)
                    self.assertIsNone(error.__context__)
                    self.assertEqual(remote.close_calls, 1)
                    self.assertEqual(remote.mutations, [])
                    self.assertEqual(ambient.calls, [])

    def test_missing_remote_authority_material_is_bounded_before_inspection(self):
        request, authority, _ = _remote_request()
        for supplied in (None, authority):
            with self.subTest(authority=supplied is not None):
                ambient = _ReadClient(request)
                with patch.object(DockerSdkClient, "from_authority") as factory:
                    result = self.observer(ambient).observe(RuntimeEffectObservationRequest(request), supplied)
                self.assertEqual(ambient.calls, [])
                self.assertEqual(ambient.mutations, [])
                factory.assert_not_called()
                self.assertEqual(self.assert_observation(result, request), "indeterminate")

    def test_each_missing_tls_grant_blocks_before_any_resolution_or_inspection(self):
        for missing in range(3):
            with self.subTest(missing=missing):
                request, authority, grants = _remote_request()
                request = replace(request, secret_resolution_grants=tuple(grant for grant in grants if grant is not grants[missing]))
                ambient, resolver = _ReadClient(request), _Resolver()
                with patch.object(DockerSdkClient, "from_authority") as factory:
                    result = self.observer(ambient, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), authority)
                self.assertEqual(resolver.calls, [])
                self.assertEqual(ambient.calls, [])
                self.assertEqual(ambient.mutations, [])
                factory.assert_not_called()
                self.assertEqual(self.assert_observation(result, request), "indeterminate")

    def test_authority_reference_mismatch_cannot_consume_other_tls_grants(self):
        request, authority, _ = _remote_request()
        for field in ("ca_certificate", "client_certificate", "client_key"):
            with self.subTest(field=field):
                mismatched = replace(authority, authority=replace(authority.authority, **{field: SecretReference("secret://foreign/tls")}))
                ambient, resolver = _ReadClient(request), _Resolver()
                with patch.object(DockerSdkClient, "from_authority") as factory:
                    result = self.observer(ambient, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), mismatched)
                self.assertEqual(resolver.calls, [])
                self.assertEqual(ambient.calls, [])
                self.assertEqual(ambient.mutations, [])
                factory.assert_not_called()
                self.assertEqual(self.assert_observation(result, request), "indeterminate")

    def test_tls_resolution_failure_stops_at_exact_grant_without_fallback(self):
        for index in range(3):
            with self.subTest(index=index):
                request, authority, grants = _remote_request()
                ambient, resolver = _ReadClient(request), _Resolver(missing=grants[index])
                with patch.object(DockerSdkClient, "from_authority") as factory:
                    result = self.observer(ambient, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), authority)
                self.assertEqual(resolver.calls, list(grants[:index + 1]))
                self.assertEqual(ambient.calls, [])
                self.assertEqual(ambient.mutations, [])
                factory.assert_not_called()
                self.assertEqual(self.assert_observation(result, request), "indeterminate")

    def test_remote_observation_uses_tls_grants_but_never_product_or_pull_grants(self):
        pull = ImagePullAuthority("ghcr.io", None, SecretReference("secret://local/pull-token"))
        product = _product_with_secret_delivery()
        for request in (
            replace(_hello_request(pull_authority=pull), operation=StopNode(NodeTarget("hello"))),
            _request(StopNode(NodeTarget("api")), products=(_material(product, pull_authority=pull),)),
        ):
            with self.subTest(node=request.products[0].node_id):
                request, authority, grants = _remote_request(request)
                extras = [_grant_for(request, pull.credential_reference, SecretUseIntent.OCI_PULL_CREDENTIAL)]
                for delivery in request.products[0].product.runtime_contract.secret_deliveries:
                    extras.append(_grant_for(request, delivery.reference, delivery.intent))
                request = replace(request, secret_resolution_grants=(*grants, *extras))
                ambient, remote, resolver = _ReadClient(request), _ReadClient(request), _Resolver()
                remote.container = replace(remote.container, running=False)
                with patch.object(DockerSdkClient, "from_authority", return_value=remote):
                    result = self.observer(ambient, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), authority)
                self.assertEqual(resolver.calls, list(grants))
                self.assertFalse(any(grant in resolver.calls for grant in extras))
                self.assertEqual(ambient.calls, [])
                self.assertEqual(remote.mutations, [])
                self.assertEqual(remote.close_calls, 1)
                self.assertEqual(remote.calls, [("inspect_container", _container_name(request, request.products[0].node_id))])
                self.assertEqual(self.assert_observation(result, request), "succeeded")

    def test_node_realization_cannot_confirm_unobservable_authority_delivery(self):
        for operation_type in (StartNode, ReconcileNode):
            for delivery in ("none", "local", "remote"):
                with self.subTest(operation=operation_type.__name__, delivery=delivery):
                    request = _plain_node_request(operation_type)
                    contract = request.products[0].product.runtime_contract
                    self.assertEqual(contract.configuration_artifacts, ())
                    self.assertEqual(contract.secret_deliveries, ())
                    self.assertEqual(contract.retained_data_mounts, ())
                    self.assertEqual(contract.verification.checks, ())
                    self.assertEqual(request.authority_deliveries, ())
                    self.assertEqual(request.secret_resolution_grants, ())
                    if delivery == "remote":
                        request, authority, _ = _remote_request(request)
                    else:
                        reference = RuntimeAuthorityReference("local-docker")
                        request = replace(
                            request, authority_ref=reference,
                            authority_deliveries=() if delivery == "none" else (RuntimeAuthorityAccessDelivery(
                                reference, RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT,
                            ),),
                        )
                        authority = _local_runtime_authority()
                    self.assertEqual(len(request.authority_deliveries), 0 if delivery == "none" else 1)
                    client, resolver = _ReadClient(request), _Resolver()
                    before = repr((client.network, client.container, client.image, client.volumes))
                    with patch.object(DockerSdkClient, "from_authority") as factory:
                        result = self.observer(client, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), authority)
                    expected_reads = [] if delivery != "none" else [
                        ("inspect_network", _network_name(request, "docker")),
                        ("inspect_container", _container_name(request, "api")),
                        ("inspect_image", request.products[0].product.image.execution_reference),
                    ]
                    self.assertEqual(client.calls, expected_reads)
                    self.assertEqual(client.mutations, [])
                    self.assertEqual(client.close_calls, 0)
                    self.assertEqual(before, repr((client.network, client.container, client.image, client.volumes)))
                    self.assertEqual(resolver.calls, [])
                    factory.assert_not_called()
                    self.assertEqual(self.assert_observation(result, request), "succeeded" if delivery == "none" else "observer-unsupported")

    def test_node_target_and_single_product_are_admitted_before_reads(self):
        template = _request(StartNode(NodeTarget("api")))
        for operation_type in (StartNode, ReconcileNode, StopNode, RemoveNodeResource):
            for invalid in ("target", "empty", "multiple"):
                with self.subTest(operation=operation_type.__name__, invalid=invalid):
                    products = template.products
                    if invalid == "empty":
                        products = ()
                    elif invalid == "multiple":
                        products = (*products, replace(products[0], node_id="second"))
                    request = replace(template, operation=operation_type(NodeTarget("foreign" if invalid == "target" else "api")), products=products)
                    client = _ReadClient(template)
                    self.assertEqual(self.observe(request, client), "indeterminate")
                    self.assertEqual(client.calls, [])

    def test_non_docker_runtime_is_unsupported_before_authority_or_provider_io(self):
        for runtime_kind in (RuntimeKind.EXTERNAL, RuntimeKind.DRY_RUN, RuntimeKind.AWS, RuntimeKind.KUBERNETES):
            with self.subTest(runtime_kind=runtime_kind.value):
                request = replace(_hello_request(), runtime_kind=runtime_kind)
                client, resolver = _ReadClient(request), _Resolver()
                with patch.object(DockerSdkClient, "from_authority") as factory:
                    result = self.observer(client, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), _remote_tls_runtime_authority())
                self.assertEqual(client.calls, [])
                self.assertEqual(client.mutations, [])
                self.assertEqual(resolver.calls, [])
                factory.assert_not_called()
                self.assertEqual(self.assert_observation(result, request), "observer-unsupported")

    def test_every_runtime_branch_rejects_wrong_coordinate_or_ownership(self):
        template = _hello_request()
        for operation_type in (StartRuntime, ReconcileRuntime, RemoveRuntimeResource):
            for corruption in ("name", "missing-fingerprint", "wrong-fingerprint", "foreign"):
                with self.subTest(operation=operation_type.__name__, corruption=corruption):
                    request = replace(template, operation=operation_type(RuntimeTarget("docker")), products=())
                    client = _ReadClient(template)
                    client.network = _corrupt(client.network, corruption)
                    self.assertEqual(self.observe(request, client), "conflict")
                    self.assertEqual(client.calls, [("inspect_network", _network_name(request, "docker"))])

    def test_every_node_branch_rejects_wrong_coordinate_or_ownership(self):
        for operation_type in (StopNode, RemoveNodeResource, ReconcileNode):
            resources = ("network", "container") if operation_type is ReconcileNode else ("container",)
            for resource in resources:
                for corruption in ("name", "missing-fingerprint", "wrong-fingerprint", "foreign"):
                    with self.subTest(operation=operation_type.__name__, resource=resource, corruption=corruption):
                        request = _request(operation_type(NodeTarget("api")))
                        if operation_type is ReconcileNode:
                            request = _plain_node_request(operation_type)
                        client = _ReadClient(request)
                        if operation_type is StopNode:
                            client.container = replace(client.container, running=False)
                        setattr(client, resource, _corrupt(getattr(client, resource), corruption))
                        self.assertEqual(self.observe(request, client), "conflict")
                        expected = [("inspect_container", _container_name(request, "api"))]
                        if operation_type is ReconcileNode:
                            expected.insert(0, ("inspect_network", _network_name(request, "docker")))
                            if resource == "network":
                                expected = expected[:1]
                        self.assertEqual(client.calls, expected)

    def test_sdk_authorization_and_transport_faults_are_closed_at_each_read(self):
        for phase in ("network", "container", "image"):
            for fault in ("authorization", "server", "timeout", "connection", "sdk"):
                with self.subTest(phase=phase, fault=fault):
                    request = _hello_request()
                    sdk, raw, calls = _sdk_fixture(request)
                    manager = {"network": raw.networks, "container": raw.containers, "image": raw.images}[phase]
                    manager.get_error = _provider_fault(fault)
                    result = self.observer(sdk).observe(RuntimeEffectObservationRequest(request), None)
                    _assert_sdk_no_mutation(self, raw)
                    sequence = ["network", "container", "image"]
                    self.assertEqual([name for name, _ in calls], sequence[:sequence.index(phase) + 1])
                    self.assertEqual(self.assert_observation(result, request), "indeterminate")

    def test_actual_sdk_not_found_is_absence_not_authorization_uncertainty(self):
        request = _hello_request()
        sdk, raw, calls = _sdk_fixture(request)
        raw.containers.get_error = docker_errors.NotFound("private provider body")
        result = self.observer(sdk).observe(RuntimeEffectObservationRequest(request), None)
        _assert_sdk_no_mutation(self, raw)
        self.assertEqual([name for name, _ in calls], ["network", "container"])
        self.assertEqual(self.assert_observation(result, request), "absent")

    def test_actual_sdk_malformed_inspections_are_bounded_not_programming_errors(self):
        for corruption in ("network-ports", "container-image", "container-networks", "container-address", "image-id", "image-digests"):
            with self.subTest(corruption=corruption):
                request = _hello_request()
                sdk, raw, calls = _sdk_fixture(request)
                _malform_sdk(raw, request, corruption)
                result = self.observer(sdk).observe(RuntimeEffectObservationRequest(request), None)
                _assert_sdk_no_mutation(self, raw)
                phase = corruption.split("-", 1)[0]
                sequence = ["network", "container", "image"]
                self.assertEqual([name for name, _ in calls], sequence[:sequence.index(phase) + 1])
                self.assertEqual(self.assert_observation(result, request), "indeterminate")

    def test_actual_sdk_unknown_container_state_is_indeterminate_only(self):
        for operation_type in (StartNode, ReconcileNode, StopNode):
            for case in MALFORMED_CONTAINER_STATES:
                for status in MISLEADING_CONTAINER_STATUSES:
                    with self.subTest(operation=operation_type.__name__, case=case, status=status):
                        request = _plain_node_request(operation_type)
                        sdk, raw, calls, _ = _sdk_state_fixture(request, status, case=case)
                        result = self.observer(sdk).observe(RuntimeEffectObservationRequest(request), None)
                        _assert_sdk_no_mutation(self, raw)
                        expected = ["container"] if operation_type is StopNode else ["network", "container"]
                        with self.subTest(boundary="no-later-read"):
                            self.assertEqual([phase for phase, _ in calls], expected)
                        with self.subTest(boundary="indeterminate-only"):
                            self.assertEqual(self.assert_observation(result, request), "indeterminate")

    def test_actual_sdk_known_container_states_preserve_observation_postconditions(self):
        for operation_type in (StartNode, ReconcileNode, StopNode):
            for running in (True, False):
                for status in MISLEADING_CONTAINER_STATUSES:
                    with self.subTest(operation=operation_type.__name__, running=running, status=status):
                        request = _plain_node_request(operation_type)
                        sdk, raw, _, resource = _sdk_state_fixture(request, status, running=running)
                        result = self.observer(sdk).observe(RuntimeEffectObservationRequest(request), None)
                        _assert_sdk_no_mutation(self, raw)
                        self.assertEqual(resource.status_reads, 0)
                        succeeded = not running if operation_type is StopNode else running
                        self.assertEqual(self.assert_observation(result, request), "succeeded" if succeeded else "indeterminate")

    def test_same_state_error_text_outside_sdk_preserves_programming_exception(self):
        request = _plain_node_request(StopNode)
        client = _ReadClient(request)
        error = RuntimeError("Docker container state inspection was malformed")
        with patch.object(client, "inspect_container", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self.observer(client).observe(RuntimeEffectObservationRequest(request), None)
        self.assertIs(caught.exception, error)
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertEqual(client.mutations, [])

    def test_execute_unknown_preaction_state_blocks_all_later_mutation(self):
        for operation_type in (StartNode, StopNode, RemoveNodeResource):
            for case in MALFORMED_CONTAINER_STATES:
                for status in MISLEADING_CONTAINER_STATUSES:
                    with self.subTest(operation=operation_type.__name__, case=case, status=status):
                        request = _plain_node_request(operation_type)
                        sdk, raw, calls, _ = _sdk_state_fixture(request, status, case=case)
                        result = docker_interpreters.DockerRuntimeInterpreter(sdk).execute(request)
                        expected = ["image", "network", "container"] if operation_type is StartNode else ["container"]
                        with self.subTest(boundary="no-later-operation"):
                            self.assertEqual([phase for phase, _ in calls], expected)
                        with self.subTest(boundary="no-mutation"):
                            _assert_sdk_no_mutation(self, raw)
                        with self.subTest(boundary="uncertain-not-success-or-conflict"):
                            self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                            self.assertEqual(result.observations, ())
                            if operation_type is StartNode:
                                self.assertEqual(dict(result.failure.details), {"phase": "container-create"})

    def test_execute_known_start_state_preserves_success_and_private_endpoints(self):
        for running in (True, False):
            for status in MISLEADING_CONTAINER_STATUSES:
                with self.subTest(running=running, status=status):
                    request = _plain_node_request(StartNode)
                    sdk, raw, _, resource = _sdk_state_fixture(request, status, running=running)
                    result = docker_interpreters.DockerRuntimeInterpreter(sdk).execute(request)
                    self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
                    self.assertEqual(resource.status_reads, 0)
                    self.assertEqual(resource.started, not running)
                    self.assertEqual(result.evidence["action"], "reused" if running else "started")
                    self.assertEqual([
                        (value.subject_id, value.socket_name, value.address.value)
                        for value in result.observations
                    ], [("api", "http", "http://172.31.0.8:8080")])
                    for manager in (raw.networks, raw.containers, raw.images, raw.volumes):
                        self.assertEqual(manager.created, [])
                        self.assertEqual(manager.pulled, [])

    def test_remote_client_construction_faults_never_use_ambient_client(self):
        for fault in ("authorization", "timeout", "connection", "sdk"):
            with self.subTest(fault=fault):
                request, authority, grants = _remote_request()
                ambient, resolver = _ReadClient(request), _Resolver()
                with patch.object(DockerSdkClient, "from_authority", side_effect=_provider_fault(fault)) as factory:
                    result = self.observer(ambient, authorized_secret_resolver=resolver).observe(RuntimeEffectObservationRequest(request), authority)
                self.assertEqual(factory.call_count, 1)
                self.assertEqual(resolver.calls, list(grants))
                self.assertEqual(ambient.calls, [])
                self.assertEqual(ambient.mutations, [])
                self.assertEqual(ambient.close_calls, 0)
                self.assertEqual(self.assert_observation(result, request), "indeterminate")

    def test_unexpected_factory_exception_identity_is_preserved(self):
        request, authority, grants = _remote_request()
        ambient, resolver = _ReadClient(request), _Resolver()
        error = AssertionError("factory programming defect")
        observer = self.observer(ambient, authorized_secret_resolver=resolver)
        with patch.object(DockerSdkClient, "from_authority", side_effect=error):
            with self.assertRaises(AssertionError) as caught:
                observer.observe(RuntimeEffectObservationRequest(request), authority)
        self.assertIs(caught.exception, error)
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertEqual(resolver.calls, list(grants))
        self.assertEqual(ambient.calls, [])
        self.assertEqual(ambient.close_calls, 0)


def _plain_node_request(operation_type):
    request = _request(operation_type(NodeTarget("api")))
    material = request.products[0]
    product = replace(material.product, runtime_contract=replace(
        material.product.runtime_contract, configuration_artifacts=(),
    ))
    return replace(request, products=(replace(material, product=product),))


def _retained_fixture(operation_type, volume_state):
    product = _product_with_retained_data()
    product = replace(product, runtime_contract=replace(
        product.runtime_contract, configuration_artifacts=(),
    ))
    request = _request(operation_type(NodeTarget("api")), products=(_material(product),))
    client = _ReadClient(request)
    mount = product.runtime_contract.retained_data_mounts[0]
    name = _volume_name(request, "api", mount.resource_id)
    if volume_state != "absent":
        labels = {**client.container.labels, "org.openj92.cpk.volume.kind": "retained-data"}
        client.volumes[name] = DockerSdkResourceInspection(
            name, False, None, labels if volume_state == "exact" else {},
        )
    return request, client


def _sdk_state_fixture(request, status, *, case=None, running=True):
    sdk, raw, calls = _sdk_fixture(request)
    material = request.products[0]
    name = _container_name(request, material.node_id)
    resource = StateInspectionResource(
        name, image=material.product.image.execution_reference,
        image_id=HELLO_IMAGE_ID, labels=_node_labels(request, material),
        running=running, misleading_status=status,
        private_addresses={_network_name(request, material.runtime_id): "172.31.0.8"},
    )
    if case is not None:
        malform_container_state(resource, case)
    raw.containers.resources[name] = resource
    return sdk, raw, calls, resource


def _provider_fault(kind):
    message = "private-provider-body /run/docker.sock token=private https://private.invalid"
    if kind in ("authorization", "server"):
        response = Response()
        response.status_code = 403 if kind == "authorization" else 500
        response.url = "http://private.invalid"
        return APIError(message, response=response, explanation=message)
    return {"timeout": Timeout, "connection": RequestsConnectionError, "sdk": DockerException}[kind](message)


def _sdk_fixture(request):
    raw = FakeDockerClient()
    module = FakeDockerModule(raw)
    module.errors = docker_errors
    material = request.products[0]
    network = _network_name(request, material.runtime_id)
    container = _container_name(request, material.node_id)
    raw.networks.resources[network] = FakeResource(network, labels=_runtime_labels(request, material.runtime_id))
    raw.containers.resources[container] = FakeResource(
        container, labels=_node_labels(request, material),
        image=material.product.image.execution_reference, image_id=HELLO_IMAGE_ID,
        running=True, private_addresses={network: "172.31.0.8"},
    )
    raw.images.resources[material.product.image.execution_reference] = FakeImage(
        [], image_id=HELLO_IMAGE_ID, repo_digests=(material.product.image.execution_reference,),
    )
    calls = []
    for phase, manager in (("network", raw.networks), ("container", raw.containers), ("image", raw.images)):
        original = manager.get

        def record(name, *, phase=phase, original=original):
            calls.append((phase, name))
            return original(name)

        manager.get = record
    return DockerSdkClient(client=raw, docker_module=module), raw, calls


def _malform_sdk(raw, request, corruption):
    material = request.products[0]
    network = raw.networks.resources[_network_name(request, material.runtime_id)]
    container = raw.containers.resources[_container_name(request, material.node_id)]
    image = raw.images.resources[material.product.image.execution_reference]
    if corruption == "network-ports":
        network.attrs["NetworkSettings"]["Ports"] = ["private-provider-body"]
    elif corruption == "container-image":
        container.image.id = "sha256:bad"
    elif corruption == "container-networks":
        container.attrs["NetworkSettings"]["Networks"] = ["private-provider-body"]
    elif corruption == "container-address":
        container.attrs["NetworkSettings"]["Networks"][_network_name(request, material.runtime_id)]["IPAddress"] = "not-an-address"
    elif corruption == "image-id":
        image.id = "sha256:bad"
    else:
        image.attrs["RepoDigests"] = [""]


def _assert_sdk_no_mutation(test, raw):
    test.assertEqual(raw.close_calls, 0)
    for manager in (raw.networks, raw.containers, raw.volumes, raw.images):
        test.assertEqual(manager.created, [])
        test.assertEqual(manager.pulled, [])
        test.assertEqual(manager.created_containers, [])
        test.assertEqual(manager.volume_archives, {})
        for resource in manager.resources.values():
            if isinstance(resource, FakeResource):
                test.assertFalse(resource.started or resource.stopped or resource.removed)
                test.assertEqual(resource.archives, {})
                test.assertEqual(resource.execs, [])
                test.assertEqual(resource.connections, [])


def _corrupt(inspection, corruption):
    if corruption == "name":
        return replace(inspection, name="foreign-coordinate")
    labels = dict(inspection.labels)
    if corruption == "missing-fingerprint":
        del labels["org.openj92.cpk.fingerprint"]
    elif corruption == "wrong-fingerprint":
        labels["org.openj92.cpk.fingerprint"] = "f" * 64
    else:
        labels = {}
    return replace(inspection, labels=labels)


class DockerObservationGrantContractTests(unittest.TestCase):
    def test_current_core_cannot_admit_ordinary_remote_node_tls_grants_without_workload_delivery(self):
        authority = _remote_tls_runtime_authority().authority
        uses = (
            (authority.ca_certificate, SecretUseIntent.DOCKER_REMOTE_TLS_CA_CERTIFICATE),
            (authority.client_certificate, SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_CERTIFICATE),
            (authority.client_key, SecretUseIntent.DOCKER_REMOTE_TLS_CLIENT_KEY),
        )
        for operation_type in (StartNode, ReconcileNode):
            with self.subTest(operation=operation_type.__name__):
                request = replace(
                    _request(operation_type(NodeTarget("api"))),
                    authority_ref=RuntimeAuthorityReference("remote-docker"),
                )
                self.assertEqual(request.authority_deliveries, ())
                self.assertIs(RuntimeEffectObservationRequest(request).runtime_request, request)
                request = replace(request, secret_resolution_grants=tuple(
                    _grant_for(request, reference, intent) for reference, intent in uses
                ))
                self.assertEqual(request.descriptor()["authority_deliveries"], [])
                with self.assertRaisesRegex(RuntimeEffectContractError, "^runtime observation grant is not admitted$"):
                    RuntimeEffectObservationRequest(request)

    def test_current_core_accepts_exact_grants_and_string_run_correlation(self):
        request, _, grants = _remote_request()
        observation = RuntimeEffectObservationRequest(request)
        self.assertIs(observation.runtime_request, request)
        self.assertEqual({grant.run_id for grant in grants}, {request.source.run_id.value})
        self.assertTrue(all(type(grant.run_id) is str for grant in grants))
        self.assertEqual({grant.effect_id for grant in grants}, {request.source.intent_event_id})
        self.assertEqual({grant.activity_id for grant in grants}, {request.activity_id.value})

    def test_current_core_rejects_every_wrong_tls_grant_correlation_and_intent(self):
        for index in range(3):
            for field, value in (
                ("workspace_id", "other-workspace"), ("run_id", "other-run"),
                ("activity_id", "other-activity"), ("effect_id", "other-event"),
                ("intent", SecretUseIntent.OCI_PULL_CREDENTIAL),
                ("reference", SecretReference("secret://foreign/tls")),
            ):
                with self.subTest(index=index, field=field):
                    request, _, grants = _remote_request()
                    with self.assertRaises(RuntimeEffectContractError):
                        changed = list(grants)
                        changed[index] = replace(changed[index], **{field: value})
                        RuntimeEffectObservationRequest(replace(request, secret_resolution_grants=tuple(changed)))

    def test_sdk_malformed_rows_reach_the_existing_exact_sdk_boundary(self):
        for corruption in ("network-ports", "container-image", "container-networks", "container-address", "image-id", "image-digests"):
            with self.subTest(corruption=corruption):
                request = _hello_request()
                sdk, raw, _ = _sdk_fixture(request)
                _malform_sdk(raw, request, corruption)
                phase = corruption.split("-", 1)[0]
                coordinate = {
                    "network": _network_name(request, "docker"),
                    "container": _container_name(request, "hello"),
                    "image": HELLO_REFERENCE,
                }[phase]
                with self.assertRaises(RuntimeError):
                    getattr(sdk, "inspect_" + phase)(coordinate)
                _assert_sdk_no_mutation(self, raw)
