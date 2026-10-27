"""Adapter call ordering with real requests and opaque admission permits."""
from dataclasses import replace
import inspect
import unittest
from unittest.mock import patch

from control_plane_kit_core.planning import NodeTarget, StartNode, StartRuntime, RuntimeTarget
from control_plane_kit_core.runtime_effects import EffectResultKind, ImagePullAuthority
from control_plane_kit_core.runtime_effect_observation import (
    RuntimeEffectObservationRequest, RuntimeEffectObservedSucceeded,
    RuntimeEffectObserverUnsupported,
)
from control_plane_kit_core.secrets import SecretReference, SecretUseIntent
from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter, DockerRuntimeEffectObserver
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient
from test_health_invocations import RecordingPort, Denied, RecordingUncertain
from test_docker_runtime_interpreter import (
    FakeAuthorizedSecretResolver, _grant, _local_runtime_authority, _material,
    _product_with_secret_delivery, _product_with_postgres_health_check,
    _request, _selected_request, _selected_fixture_client, _workload_container_record,
)
from test_docker_runtime_effect_observer import (
    _remote_request, _connection_admission, _ReadClient, _Resolver,
)
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule, unix_policy


def distinct_grants(request):
    return replace(request, secret_resolution_grants=tuple(
        replace(grant, authorization_id="suse_" + format(index + 1, "064x"))
        for index, grant in enumerate(request.secret_resolution_grants)))


class OrderedResolver(FakeAuthorizedSecretResolver):
    def __init__(self, raw, values, events):
        super().__init__(raw, values)
        self.events = events

    def resolve(self, grant):
        self.events.append(("resolve", grant.authorization_id))
        return super().resolve(grant)


class RuntimeInvocationTests(unittest.TestCase):
    def setUp(self):
        self.events = []

    def execute(self, interpreter, request, port, authority=None):
        method = interpreter.execute if authority is None else interpreter.execute_with_authority
        self.assertIn("invocations", inspect.signature(method).parameters,
            "#226 runtime does not yet consume semantic invocations")
        args = (request,) if authority is None else (request, authority)
        return method(*args, invocations=port)

    def workload(self, *, probe=False):
        raw = _selected_fixture_client()
        product = _product_with_secret_delivery()
        reference = product.runtime_contract.secret_deliveries[0].reference
        if probe:
            checked = _product_with_postgres_health_check()
            product = replace(checked, runtime_contract=replace(checked.runtime_contract,
                secret_deliveries=product.runtime_contract.secret_deliveries))
        material = _material(product, pull_authority=ImagePullAuthority(
            "ghcr.io", "openj92/runtime-fixture", reference))
        request = _selected_request(StartNode(NodeTarget("api")), products=(material,))
        grants = (*request.secret_resolution_grants, _grant(reference, SecretUseIntent.OCI_PULL_CREDENTIAL))
        if probe:
            grants += (_grant(product.runtime_contract.verification.checks[0].authentication.password_reference,
                SecretUseIntent.POSTGRES_PASSWORD),)
        request = distinct_grants(replace(request, secret_resolution_grants=grants))
        consumer, pull = request.secret_resolution_grants[:2]
        values = {(consumer.selection.reference, consumer.selection.intent): "private-consumer",
            (reference, pull.intent): '{"username":"cpk","password":"private-pull"}'}
        resolver = OrderedResolver(raw, values, self.events)
        sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
        return request, resolver, sdk, DockerRuntimeInterpreter(sdk, authorized_secret_resolver=resolver)

    def test_selected_consumer_and_pull_are_prepared_once_before_any_inspection(self):
        request, resolver, sdk, interpreter = self.workload()
        original = sdk.inspect_container
        def inspect_container(*args, **kwargs):
            self.events.append(("inspect",))
            return original(*args, **kwargs)
        with patch.object(sdk, "inspect_container", side_effect=inspect_container):
            result = self.execute(interpreter, request, RecordingPort(self.events))
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, list(request.secret_resolution_grants))
        expected = []
        for grant in request.secret_resolution_grants:
            expected.extend((("admit", "secret-resolution", grant.authorization_id),
                ("resolve", grant.authorization_id),
                ("record", "secret-resolution", grant.authorization_id, "returned")))
        self.assertEqual(self.events[:8], expected + [
            ("admit", "prepared-runtime-dispatch", None), ("inspect",)])
        self.assertEqual(self.events[-1], ("record", "prepared-runtime-dispatch", None, "returned"))
        self.assertNotIn("private-consumer", repr(result.descriptor()))
        self.assertNotIn("private-pull", repr(self.events))
        self.assertEqual(_workload_container_record(resolver.fake_client)["environment"]["API_TOKEN"],
            "private-consumer")

    def test_declared_but_unreached_probe_credential_is_not_prepared(self):
        request, resolver, _, interpreter = self.workload(probe=True)
        result = self.execute(interpreter, request, RecordingPort(self.events))
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, list(request.secret_resolution_grants[:2]))
        self.assertNotIn(request.secret_resolution_grants[-1].authorization_id, repr(self.events))

    def test_final_denial_prevents_workload_inspection_after_preparation(self):
        request, resolver, sdk, interpreter = self.workload()
        denied = Denied("closed-control")
        def before(kind, _):
            if kind == "prepared-runtime-dispatch":
                raise denied
        with patch.object(sdk, "inspect_container") as inspection:
            with self.assertRaises(Denied) as caught:
                self.execute(interpreter, request, RecordingPort(self.events, before=before))
        self.assertIs(caught.exception, denied)
        inspection.assert_not_called()
        self.assertEqual(resolver.requests, list(request.secret_resolution_grants))

    def test_consumer_record_failure_survives_helper_and_prevents_pull_and_docker(self):
        request, resolver, sdk, interpreter = self.workload()
        uncertain = RecordingUncertain("closed-control")
        def after(*_):
            raise uncertain
        with patch.object(sdk, "inspect_container") as inspection:
            with self.assertRaises(RecordingUncertain) as caught:
                self.execute(interpreter, request, RecordingPort(self.events, after=after))
        self.assertIs(caught.exception, uncertain)
        inspection.assert_not_called()
        self.assertEqual(resolver.requests, [request.secret_resolution_grants[0]])

    def remote(self):
        request, authority, _ = _remote_request()
        request = distinct_grants(request)
        raw = FakeDockerClient()
        sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
        resolver = OrderedResolver(raw, {(g.reference, g.intent): "private-tls"
            for g in request.secret_resolution_grants}, self.events)
        interpreter = DockerRuntimeInterpreter(sdk, authorized_secret_resolver=resolver)
        return request, authority, resolver, sdk, interpreter

    def test_remote_tls_resolutions_precede_acquisition_and_record_follows_close(self):
        request, authority, resolver, sdk, interpreter = self.remote()
        def acquire(*_, **__):
            self.events.append(("acquire",))
            return sdk
        with patch.object(DockerSdkClient, "from_authority", side_effect=acquire), \
                patch.object(sdk, "close", side_effect=lambda: self.events.append(("close",))):
            result = self.execute(interpreter, request, RecordingPort(self.events), authority)
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(resolver.requests, list(request.secret_resolution_grants))
        self.assertEqual(self.events[9:], [("admit", "prepared-runtime-dispatch", None),
            ("acquire",), ("close",), ("record", "prepared-runtime-dispatch", None, "returned")])

    def test_remote_final_denial_prevents_eager_client_factory(self):
        request, authority, resolver, _, interpreter = self.remote()
        denied = Denied("closed-control")
        def before(kind, _):
            if kind == "prepared-runtime-dispatch":
                raise denied
        with patch.object(DockerSdkClient, "from_authority") as factory:
            with self.assertRaises(Denied) as caught:
                self.execute(interpreter, request, RecordingPort(self.events, before=before), authority)
        self.assertIs(caught.exception, denied)
        factory.assert_not_called()
        self.assertEqual(len(resolver.requests), 3)

    def test_owned_local_final_denial_prevents_eager_client_factory(self):
        interpreter = DockerRuntimeInterpreter(local_client_config=unix_policy(self))
        request = _request(StartRuntime(RuntimeTarget("docker")), products=())
        denied = Denied("closed-control")
        def before(*_):
            raise denied
        with patch.object(DockerSdkClient, "from_authority") as factory:
            with self.assertRaises(Denied) as caught:
                self.execute(interpreter, request, RecordingPort(self.events, before=before),
                    _local_runtime_authority())
        self.assertIs(caught.exception, denied)
        factory.assert_not_called()

    def test_final_record_failure_propagates_after_owned_client_cleanup(self):
        request, authority, _, sdk, interpreter = self.remote()
        uncertain = RecordingUncertain("closed-control")
        def after(kind, *_):
            if kind == "prepared-runtime-dispatch":
                raise uncertain
        with patch.object(DockerSdkClient, "from_authority", return_value=sdk), \
                patch.object(sdk, "close", side_effect=lambda: self.events.append(("close",))):
            with self.assertRaises(RecordingUncertain) as caught:
                self.execute(interpreter, request, RecordingPort(self.events, after=after), authority)
        self.assertIs(caught.exception, uncertain)
        self.assertEqual(self.events[-2:], [("close",),
            ("record", "prepared-runtime-dispatch", None, "returned")])

    def test_required_or_malformed_port_refuses_before_io(self):
        raw = FakeDockerClient()
        sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
        request = _request(StartRuntime(RuntimeTarget("docker")), products=())
        self.assertIn("require_invocations", inspect.signature(DockerRuntimeInterpreter).parameters)
        for required, port in ((True, None), (True, object()), (False, object())):
            with self.subTest(required=required, port=type(port).__name__):
                with patch.object(sdk, "inspect_network") as inspection:
                    with self.assertRaisesRegex(RuntimeError, "semantic invocation port"):
                        self.execute(DockerRuntimeInterpreter(sdk, require_invocations=required), request, port)
                inspection.assert_not_called()


class ObservationInvocationTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        request, self.authority, _ = _remote_request()
        self.request = distinct_grants(request)
        self.client = _ReadClient(self.request)
        self.resolver = _Resolver()
        original = self.resolver.resolve
        def resolve(grant):
            self.events.append(("resolve", grant.authorization_id))
            return original(grant)
        self.resolver.resolve = resolve
        self.observation = RuntimeEffectObservationRequest(self.request,
            connection_admission=_connection_admission())
        self.observer = DockerRuntimeEffectObserver(self.client, self.resolver)

    def observe(self, port):
        self.assertIn("invocations", inspect.signature(self.observer.observe).parameters,
            "#226 original observer does not yet consume semantic invocations")
        return self.observer.observe(self.observation, self.authority, invocations=port)

    def test_remote_observation_prepares_exact_tls_then_admits_before_factory(self):
        def acquire(*_, **__):
            self.events.append(("acquire",))
            return self.client
        original = self.client.close
        def close():
            self.events.append(("close",))
            original()
        with patch.object(DockerSdkClient, "from_authority", side_effect=acquire), \
                patch.object(self.client, "close", side_effect=close):
            result = self.observe(RecordingPort(self.events))
        self.assertIs(type(result), RuntimeEffectObservedSucceeded)
        self.assertEqual(self.resolver.calls, list(self.request.secret_resolution_grants))
        self.assertEqual(self.events[9:], [("admit", "reconciliation-observation", None),
            ("acquire",), ("close",), ("record", "reconciliation-observation", None, "returned")])
        self.assertEqual(self.client.mutations, [])

    def test_final_observation_denial_prevents_factory_and_inspection(self):
        denied = Denied("closed-control")
        def before(kind, _):
            if kind == "reconciliation-observation":
                raise denied
        with patch.object(DockerSdkClient, "from_authority") as factory:
            with self.assertRaises(Denied) as caught:
                self.observe(RecordingPort(self.events, before=before))
        self.assertIs(caught.exception, denied)
        factory.assert_not_called()
        self.assertEqual(self.client.calls, [])
        self.assertEqual(len(self.resolver.calls), 3)

    def test_secret_record_failure_prevents_remaining_tls_and_inspection(self):
        uncertain = RecordingUncertain("closed-control")
        def after(*_):
            raise uncertain
        with patch.object(DockerSdkClient, "from_authority") as factory:
            with self.assertRaises(RecordingUncertain) as caught:
                self.observe(RecordingPort(self.events, after=after))
        self.assertIs(caught.exception, uncertain)
        factory.assert_not_called()
        self.assertEqual(self.resolver.calls, [self.request.secret_resolution_grants[0]])

    def test_final_record_failure_propagates_after_observation_cleanup(self):
        uncertain = RecordingUncertain("closed-control")
        def after(kind, *_):
            if kind == "reconciliation-observation":
                raise uncertain
        with patch.object(DockerSdkClient, "from_authority", return_value=self.client):
            with self.assertRaises(RecordingUncertain) as caught:
                self.observe(RecordingPort(self.events, after=after))
        self.assertIs(caught.exception, uncertain)
        self.assertEqual(self.client.close_calls, 1)

    def test_unsupported_secret_shape_refuses_before_any_resolution_or_admission(self):
        request = _selected_request(StartNode(NodeTarget("api")),
            products=(_material(_product_with_secret_delivery()),))
        self.observation = RuntimeEffectObservationRequest(request)
        with patch.object(DockerSdkClient, "from_authority") as factory:
            result = self.observe(RecordingPort(self.events))
        self.assertIs(type(result), RuntimeEffectObserverUnsupported)
        self.assertEqual(self.events, [])
        factory.assert_not_called()

    def test_required_or_malformed_port_refuses_before_resolution(self):
        self.assertIn("require_invocations", inspect.signature(DockerRuntimeEffectObserver).parameters)
        for required, port in ((True, None), (True, object()), (False, object())):
            with self.subTest(required=required, port=type(port).__name__):
                self.observer = DockerRuntimeEffectObserver(self.client, self.resolver,
                    require_invocations=required)
                with self.assertRaisesRegex(RuntimeError, "semantic invocation port"):
                    self.observe(port)
        self.assertEqual(self.resolver.calls, [])
        self.assertEqual(self.client.calls, [])
