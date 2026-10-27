"""Reached-check admission through actual runtime/verification adapters."""
import asyncio
from dataclasses import replace
import inspect
import unittest
from unittest.mock import patch

from control_plane_kit_core.planning import NodeTarget, WaitForHealthy
from control_plane_kit_core.runtime_effects import EffectResultKind
from control_plane_kit_core.secrets import SecretMissing, SecretResolved, SecretUseIntent, SecretValue
from control_plane_kit_core.verification import VerificationContract, VerificationOutcome
from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient
from control_plane_kit_interpreters.probes.security import ProbeAddressPolicy
from control_plane_kit_interpreters.verification import PostgresVerificationInterpreter
from test_health_invocations import RecordingPort, Denied, RecordingUncertain
from test_docker_runtime_interpreter import (
    _grant, _local_runtime_authority, _material, _product,
    _product_with_postgres_health_check, _product_with_health_check, _request,
    RuntimeHttpProbeResult,
)
from test_docker_runtime_effect_observer import _remote_request
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule, unix_policy
from test_verification_adapters import _postgres_material


class CheckPorts(RecordingPort):
    def __init__(self, case, events, grants):
        super().__init__(events, before=lambda kind, _: case.assertIn(
            kind, ("secret-resolution", "ordinary-verification-acquisition"),
            "#226 WaitForHealthy still dispatches as a prepared runtime effect"))
        self.children = {}
        for check_id, grant in grants.items():
            child = RecordingPort(events)
            child.credential_grant = grant
            self.children[check_id] = child

    def for_check(self, check_id):
        self.events.append(("check", check_id))
        return self.children[check_id]


class Resolver:
    def __init__(self, events, values):
        self.events, self.values, self.calls = events, values, []

    def resolve(self, grant):
        self.calls.append(grant)
        self.events.append(("resolve", grant.authorization_id))
        value = self.values[grant.authorization_id]
        if isinstance(value, BaseException):
            raise value
        if value is None:
            return SecretMissing(grant.reference)
        return SecretResolved(grant.reference, SecretValue(value))


class QueryTransport:
    def __init__(self, events, results):
        self.events, self.results, self.passwords = events, iter(results), []

    def select_one(self, target, *, password, **kwargs):
        self.passwords.append(password.reveal())
        self.events.append(("query", len(self.passwords)))
        result = next(self.results)
        if isinstance(result, BaseException):
            raise result
        return result


class OrdinaryInvocationTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        product = _product_with_postgres_health_check()
        check, = product.runtime_contract.verification.checks
        self.checks = (replace(check, check_id="first"), replace(check, check_id="second"))
        product = replace(product, runtime_contract=replace(product.runtime_contract,
            verification=VerificationContract(self.checks)))
        self.request = _request(WaitForHealthy(NodeTarget("api")), products=(_material(product),))
        reference = check.authentication.password_reference
        self.grants = tuple(replace(_grant(reference, SecretUseIntent.POSTGRES_PASSWORD),
            authorization_id="suse_" + format(index + 1, "064x")) for index in range(2))
        self.port = CheckPorts(self, self.events, dict(zip(("first", "second"), self.grants)))
        self.resolver = Resolver(self.events, dict(zip(
            (grant.authorization_id for grant in self.grants), ("private-first", "private-second"))))
        self.transport = QueryTransport(self.events, (True, True))
        raw = FakeDockerClient()
        self.client = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
        self.interpreter = DockerRuntimeInterpreter(self.client,
            authorized_secret_resolver=self.resolver, postgres_transport=self.transport)

    def execute(self):
        return self.interpreter.execute(self.request, invocations=self.port)

    def owned(self):
        self.interpreter = replace(self.interpreter, client=None, local_client_config=unix_policy(self))

    def execute_owned(self):
        return self.interpreter.execute_with_authority(self.request, _local_runtime_authority(),
            invocations=self.port)

    def test_checks_sharing_password_reference_use_distinct_child_grants_in_order(self):
        self.assertEqual(self.request.secret_resolution_grants, ())
        with patch.object(self.client, "close") as close:
            result = self.execute()
        close.assert_not_called()
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        expected = [("admit", "ordinary-verification-acquisition", None),
            ("record", "ordinary-verification-acquisition", None, "returned")]
        for index, (check, grant) in enumerate(zip(self.checks, self.grants), 1):
            expected.extend((("check", check.check_id),
                ("admit", "secret-resolution", grant.authorization_id),
                ("resolve", grant.authorization_id),
                ("record", "secret-resolution", grant.authorization_id, "returned"),
                ("admit", "ordinary-verification-check", None), ("query", index),
                ("record", "ordinary-verification-check", None, "returned")))
        self.assertEqual(self.events, expected)
        self.assertEqual(self.resolver.calls, list(self.grants))
        self.assertEqual(self.transport.passwords, ["private-first", "private-second"])
        self.assertNotIn("private-", repr(result.descriptor()))

    def test_second_credential_denial_stops_after_first_check_without_second_read(self):
        denied = Denied("closed-control")
        self.port.children["second"].before = lambda *_: (_ for _ in ()).throw(denied)
        with self.assertRaises(Denied) as caught:
            self.execute()
        self.assertIs(caught.exception, denied)
        self.assertEqual(self.resolver.calls, [self.grants[0]])
        self.assertEqual(len(self.transport.passwords), 1)

    def test_second_check_denial_after_its_secret_stops_before_second_query(self):
        denied = Denied("closed-control")
        def before(kind, _):
            if kind == "ordinary-verification-check":
                raise denied
        self.port.children["second"].before = before
        with self.assertRaises(Denied) as caught:
            self.execute()
        self.assertIs(caught.exception, denied)
        self.assertEqual(self.resolver.calls, list(self.grants))
        self.assertEqual(len(self.transport.passwords), 1)

    def test_secret_acknowledgement_failure_prevents_query_and_later_secret(self):
        uncertain = RecordingUncertain("closed-control")
        self.port.children["first"].after = lambda *_: (_ for _ in ()).throw(uncertain)
        with self.assertRaises(RecordingUncertain) as caught:
            self.execute()
        self.assertIs(caught.exception, uncertain)
        self.assertEqual(self.resolver.calls, [self.grants[0]])
        self.assertEqual(self.transport.passwords, [])

    def test_check_acknowledgement_failure_prevents_later_secret(self):
        uncertain = RecordingUncertain("closed-control")
        def after(kind, *_):
            if kind == "ordinary-verification-check":
                raise uncertain
        self.port.children["first"].after = after
        with self.assertRaises(RecordingUncertain) as caught:
            self.execute()
        self.assertIs(caught.exception, uncertain)
        self.assertEqual(self.resolver.calls, [self.grants[0]])
        self.assertEqual(len(self.transport.passwords), 1)

    def test_returned_failed_health_stops_before_selecting_later_check(self):
        self.transport.results = iter((False,))
        result = self.execute()
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(self.resolver.calls, [self.grants[0]])
        self.assertNotIn(("check", "second"), self.events)
        self.assertEqual(self.events[-1], ("record", "ordinary-verification-check", None, "returned"))

    def test_missing_secret_is_returned_resolution_and_rejected_health_without_query(self):
        self.resolver.values[self.grants[0].authorization_id] = None
        result = self.execute()
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(self.events[-1], ("record", "secret-resolution",
            self.grants[0].authorization_id, "returned"))
        self.assertEqual(self.transport.passwords, [])
        self.assertEqual(self.resolver.calls, [self.grants[0]])

    def test_thrown_secret_failure_is_unknown_and_overall_uncertain(self):
        self.resolver.values[self.grants[0].authorization_id] = OSError("private-provider")
        result = self.execute()
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(self.events[-1], ("record", "secret-resolution",
            self.grants[0].authorization_id, "unknown"))
        self.assertEqual(self.transport.passwords, [])
        self.assertNotIn("private-provider", repr(result.descriptor()))

    def test_acquisition_record_failure_closes_owned_client_before_propagating(self):
        self.owned()
        uncertain = RecordingUncertain("closed-control")
        self.port.after = lambda *_: (_ for _ in ()).throw(uncertain)
        with patch.object(DockerSdkClient, "from_authority", return_value=self.client), \
                patch.object(self.client, "close") as close:
            with self.assertRaises(RecordingUncertain) as caught:
                self.execute_owned()
        self.assertIs(caught.exception, uncertain)
        close.assert_called_once_with()
        self.assertEqual(self.resolver.calls, [])

    def test_endpoint_read_failure_records_unknown_and_closes_without_check(self):
        self.owned()
        with patch.object(DockerSdkClient, "from_authority", return_value=self.client), \
                patch.object(self.client, "inspect_container", side_effect=OSError("private-read")), \
                patch.object(self.client, "close") as close:
            result = self.execute_owned()
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        close.assert_called_once_with()
        self.assertEqual(self.events[-1], ("record", "ordinary-verification-acquisition", None, "unknown"))
        self.assertEqual(self.resolver.calls, [])
        self.assertNotIn("private-read", repr(result.descriptor()))

    def test_empty_contract_has_acquisition_only_and_owned_cleanup_without_endpoint_read(self):
        self.owned()
        self.request = _request(WaitForHealthy(NodeTarget("api")), products=(_material(_product()),))
        with patch.object(DockerSdkClient, "from_authority", return_value=self.client), \
                patch.object(self.client, "inspect_container") as inspection, \
                patch.object(self.client, "close") as close:
            result = self.execute_owned()
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(result.evidence["action"], "no-verification-contract")
        inspection.assert_not_called()
        close.assert_called_once_with()
        self.assertEqual(self.events, [("admit", "ordinary-verification-acquisition", None),
            ("record", "ordinary-verification-acquisition", None, "returned")])

    def test_cancellation_is_primary_even_when_owned_close_fails(self):
        self.owned()
        cancelled = asyncio.CancelledError()
        self.transport.results = iter((cancelled,))
        with patch.object(DockerSdkClient, "from_authority", return_value=self.client), \
                patch.object(self.client, "close", side_effect=OSError("private-close")) as close:
            with self.assertRaises(asyncio.CancelledError) as caught:
                self.execute_owned()
        self.assertIs(caught.exception, cancelled)
        self.assertIsNone(caught.exception.__context__)
        close.assert_called_once_with()
        self.assertEqual(self.resolver.calls, [self.grants[0]])
        self.assertEqual(self.events[-1], ("record", "ordinary-verification-check", None, "unknown"))

    def test_close_only_failure_after_successful_checks_is_uncertain(self):
        self.owned()
        with patch.object(DockerSdkClient, "from_authority", return_value=self.client), \
                patch.object(self.client, "close", side_effect=OSError("private-close")) as close:
            result = self.execute_owned()
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(len(self.transport.passwords), 2)
        close.assert_called_once_with()
        self.assertNotIn("private-close", repr(result.descriptor()))

    def test_acquisition_denial_prevents_owned_factory(self):
        self.owned()
        denied = Denied("closed-control")
        original = self.port.before
        def before(kind, identity):
            original(kind, identity)
            raise denied
        self.port.before = before
        with patch.object(DockerSdkClient, "from_authority") as factory:
            with self.assertRaises(Denied) as caught:
                self.execute_owned()
        self.assertIs(caught.exception, denied)
        factory.assert_not_called()

    def test_finite_retries_stay_inside_one_check_admission(self):
        first = replace(self.checks[0], policy=replace(self.checks[0].policy,
            maximum_attempts=2, interval_seconds=0.01))
        material = self.request.products[0]
        product = replace(material.product, runtime_contract=replace(material.product.runtime_contract,
            verification=VerificationContract((first,))))
        self.request = replace(self.request, products=(replace(material, product=product),))
        self.transport.results = iter((False, True))
        with patch("control_plane_kit_interpreters.timing.time.sleep") as sleep:
            result = self.execute()
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(self.events.count(("admit", "ordinary-verification-check", None)), 1)
        self.assertEqual(self.resolver.calls, [self.grants[0]])
        self.assertEqual(len(self.transport.passwords), 2)
        sleep.assert_called_once_with(0.01)

    def test_postgres_endpoint_rejection_precedes_secret_or_check_admission(self):
        material = _postgres_material()
        interpreter = PostgresVerificationInterpreter(ProbeAddressPolicy(
            runtime_private_authorities=frozenset(("postgres://other:5432",))),
            transport=self.transport, authorized_credential_resolver=self.resolver,
            credential_grant=self.grants[0])
        self.assertIn("invocations", inspect.signature(interpreter.execute).parameters,
            "#226 Postgres capability does not yet accept its reached-check invocation port")
        result = interpreter.execute(material, invocations=self.port.children["first"])
        self.assertIs(result.outcome, VerificationOutcome.REJECTED)
        self.assertEqual(self.events, [])
        self.assertEqual(self.resolver.calls, [])

    def test_http_checks_each_admit_and_preserve_declared_order(self):
        product = _product_with_health_check()
        first = replace(product.runtime_contract.verification.checks[0], check_id="first")
        second = replace(first, check_id="second", path="/second")
        product = replace(product, runtime_contract=replace(product.runtime_contract,
            verification=VerificationContract((first, second))))
        self.request = _request(WaitForHealthy(NodeTarget("api")), products=(_material(product),))
        self.port = CheckPorts(self, self.events, {"first": None, "second": None})
        def probe(**kwargs):
            self.events.append(("http", kwargs["url"]))
            return RuntimeHttpProbeResult(200, 0, 0, "completed", None)
        with patch.object(self.client, "run_http_probe", side_effect=probe):
            result = self.execute()
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(self.events[2:], [("check", "first"),
            ("admit", "ordinary-verification-check", None), ("http", "http://api:8080/health/ready"),
            ("record", "ordinary-verification-check", None, "returned"), ("check", "second"),
            ("admit", "ordinary-verification-check", None), ("http", "http://api:8080/second"),
            ("record", "ordinary-verification-check", None, "returned")])
        self.assertEqual(self.resolver.calls, [])

    def test_remote_tls_parent_preparation_finishes_before_acquisition_and_child_secrets(self):
        request, authority, _ = _remote_request(self.request)
        tls = tuple(replace(grant, authorization_id="suse_" + format(index + 100, "064x"))
            for index, grant in enumerate(request.secret_resolution_grants))
        self.request = replace(request, secret_resolution_grants=tls)
        self.resolver.values.update({grant.authorization_id: "private-tls" for grant in tls})
        with patch.object(DockerSdkClient, "from_authority", return_value=self.client) as factory, \
                patch.object(self.client, "close") as close:
            result = self.interpreter.execute_with_authority(self.request, authority, invocations=self.port)
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(self.resolver.calls, [*tls, *self.grants])
        self.assertEqual(self.events[9:11], [("admit", "ordinary-verification-acquisition", None),
            ("record", "ordinary-verification-acquisition", None, "returned")])
        factory.assert_called_once()
        close.assert_called_once_with()

    def test_missing_per_check_port_refuses_before_acquisition(self):
        self.owned()
        self.port = RecordingPort(self.events)
        with patch.object(DockerSdkClient, "from_authority") as factory:
            with self.assertRaisesRegex(RuntimeError, "per-check invocation port"):
                self.execute_owned()
        factory.assert_not_called()
        self.assertEqual(self.events, [])
        self.assertEqual(self.resolver.calls, [])


if __name__ == "__main__":
    unittest.main()
