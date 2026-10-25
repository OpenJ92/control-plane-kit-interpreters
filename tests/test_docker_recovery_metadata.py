"""#224 current metadata laws, exercised at actual SDK request boundaries."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from docker.errors import NotFound
from requests.exceptions import Timeout
import rfc8785

from control_plane_kit_core.runtime_effect_observation import (
    RuntimeEffectObservationRequest, RuntimeEffectObservedIndeterminate,
    RuntimeEffectObserverUnsupported, runtime_effect_observation_fingerprint,
)
from control_plane_kit_interpreters.docker import DockerRuntimeEffectObserver
from control_plane_kit_interpreters.docker.configuration import (
    configuration_volume_labels, configuration_volume_name,
)
from control_plane_kit_interpreters.docker.runtime import (
    _container_name, _network_name, _node_labels, _runtime_labels,
    _secret_volume_name, _selected_secret_identity,
)
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient
from test_docker_sdk_client import FakeDockerModule, UnixAcquisitionRawClient, unix_policy
from test_docker_selected_secrets import request_for, LOCAL
from configuration_replacement_fixtures import selected_request


DAEMON = "fixture-daemon:224"
PREFIX = "org.openj92.cpk."
CANARY = "private-provider-body-DO-NOT-EMIT"


class Forbidden:
    def __getattr__(self, name):
        raise AssertionError("forbidden provider capability: " + name)


class MetadataRaw(UnixAcquisitionRawClient):
    """Only the bounded Engine metadata endpoints exist on this fixture."""

    def __init__(self, request):
        super().__init__()
        self.calls = []
        self.rows = {}
        self.attached = set()
        self.hook = None
        self.api.info = lambda: self.read("daemon", None)
        self.api.inspect_image = lambda name: self.read("image", name)
        self.api.inspect_container = lambda name: self.read("container", name)
        self.api.inspect_network = lambda name: self.read("network", name)
        self.api.inspect_volume = lambda name: self.read("volume", name)
        self.api.containers = self.holders
        self.images = self.containers = self.volumes = self.networks = Forbidden()
        material, = request.products
        image = material.product.image.execution_reference
        self.rows["daemon", None] = {"ID": DAEMON, "Private": CANARY}
        self.rows["image", image] = {"Id": "sha256:" + "a" * 64,
            "RepoDigests": [image], "Config": {"User": "10006", "Env": Forbidden()}}
        self.rows["container", _container_name(request, material.node_id)] = {
            "Id": "b" * 64, "Config": {"Labels": _node_labels(request, material), "Env": Forbidden()}}
        self.rows["network", _network_name(request, material.runtime_id)] = {
            "Id": "c" * 64, "Labels": _runtime_labels(request, material.runtime_id)}
        if request.configuration_instances is not None:
            for ref in request.configuration_instances.instances:
                self.volume(configuration_volume_name(ref), configuration_volume_labels(ref))
        for secret in material.product.runtime_contract.secret_deliveries:
            if not hasattr(secret, "target_path"):
                continue
            selection, = (s for s in material.secret_selections
                          if s.reference == secret.reference and s.intent is secret.intent)
            name = _secret_volume_name(request, material.node_id, secret, owner_uid=10006)
            labels = {**_node_labels(request, material), PREFIX + "volume.kind": "secret-file",
                PREFIX + "secret.target": secret.target_path,
                PREFIX + "secret.reference": secret.reference.reference_id,
                PREFIX + "secret.identity": _selected_secret_identity(
                    request, material.node_id, secret, selection, 10006)}
            self.volume(name, labels)

    def volume(self, name, labels):
        self.rows["volume", name] = {"Name": name, "Labels": labels,
            "Driver": "local", "Scope": "local", "Mountpoint": CANARY}
        self.attached.add(name)

    def read(self, role, name):
        self.calls.append((role, name))
        if self.hook:
            self.hook(role, name)
        value = self.rows.get((role, name))
        if value is None:
            raise NotFound(CANARY)
        if isinstance(value, BaseException):
            raise value
        # Deliberately do not traverse unrelated raw provider fields.
        return value

    def holders(self, *, all, filters, limit):
        if all is not True or limit != 1 or set(filters) != {"volume"}:
            raise AssertionError("attachment query widened")
        name = filters["volume"]
        self.calls.append(("attachment", name))
        return [{"Id": "d" * 64, "Private": CANARY}] if name in self.attached else []


class DockerRecoveryMetadataTests(unittest.TestCase):
    def fixture(self, request=None, *, timeout=5):
        request = request or request_for(configuration=True, grants=False)
        raw = MetadataRaw(request)
        self.addCleanup(raw.adapter.close)
        module = FakeDockerModule(raw)
        observer = DockerRuntimeEffectObserver(local_client_config=unix_policy(self, timeout=timeout),
                                               docker_module=module)
        method = getattr(observer, "observe_metadata", None)
        self.assertTrue(callable(method), "#224 metadata-only observer is missing")
        return request, raw, module, method

    def observe(self, method, request, *, authority=LOCAL, expected=DAEMON):
        result = method(RuntimeEffectObservationRequest(request), authority,
                        expected_daemon_id=expected)
        self.assertIn(type(result), (RuntimeEffectObservedIndeterminate, RuntimeEffectObserverUnsupported))
        self.assertEqual(result.observations, ())
        self.assertIsNone(result.failure.details)
        runtime_effect_observation_fingerprint(result)
        evidence = result.evidence.descriptor()
        self.assertEqual(set(evidence), {"profile", "provider_binding_fingerprint", "coverage", "resources"})
        self.assertEqual(evidence["profile"], "docker.recovery-metadata.v1")
        self.assertLessEqual(len(rfc8785.dumps(evidence)), 4096)
        text = json.dumps(result.descriptor()) + repr(result)
        for private in (CANARY, DAEMON, "/run/secrets/token", "secret://", "/var/run/cpk-owned.sock"):
            self.assertNotIn(private, text)
        for row in evidence["resources"]:
            self.assertEqual(set(row), {"role", "index", "selector", "state", "ownership", "identity", "attachment", "reason"})
            if row["state"] in ("unknown", "unsupported"):
                self.assertNotEqual(row["ownership"], "matching")
        return result, evidence

    def test_current_complete_metadata_remains_indeterminate_without_forbidden_reads(self):
        request, raw, module, method = self.fixture()
        result, evidence = self.observe(method, request)
        self.assertIs(type(result), RuntimeEffectObservedIndeterminate)
        self.assertEqual(result.failure.code, "docker.recovery-metadata-indeterminate")
        self.assertEqual(evidence["coverage"], "selected-addresses-observed")
        self.assertEqual(evidence["provider_binding_fingerprint"], sha256(
            b"control-plane-kit.docker-provider-binding.v1\0" + DAEMON.encode("ascii")).hexdigest())
        self.assertEqual([r["role"] for r in evidence["resources"]],
                         ["container", "network", "image", "configuration-volume", "secret-volume"])
        self.assertTrue(all(r["state"] == "present" for r in evidence["resources"]))
        self.assertEqual(len(raw.calls), 16)
        self.assertEqual(raw.events.count("version"), 1)
        self.assertEqual(raw.close_calls, 1)
        self.assertEqual(module.from_env_calls, 0)

    def test_invalid_daemon_or_authority_refuses_before_acquisition(self):
        for expected, authority in ((None, LOCAL), ("/socket?private", LOCAL), ("a" * 129, LOCAL),
                                    (" x", LOCAL), ("é", LOCAL), (DAEMON, None),
                                    (DAEMON, SimpleNamespace(runtime_kind="docker", authority_kind="remote-docker-tls"))):
            with self.subTest(expected=expected, authority=authority):
                request, raw, module, method = self.fixture()
                result, _ = self.observe(method, request, authority=authority, expected=expected)
                self.assertIs(type(result), RuntimeEffectObserverUnsupported)
                self.assertEqual(module.docker_clients, [])
                self.assertEqual(raw.calls, [])

    def test_grants_and_excess_scope_and_timeout_refuse_before_acquisition(self):
        for request, timeout in ((request_for(grants=True), 5),
                                 (request_for(file_count=9, grants=False), 5),
                                 (request_for(grants=False), 11)):
            with self.subTest(timeout=timeout, count=len(request.products[0].product.runtime_contract.secret_deliveries)):
                request, raw, module, method = self.fixture(request, timeout=timeout)
                result, _ = self.observe(method, request)
                self.assertIs(type(result), RuntimeEffectObserverUnsupported)
                self.assertEqual(module.docker_clients, [])

    def test_injected_client_mode_cannot_acquire_metadata(self):
        request, raw, module, _ = self.fixture()
        observer = DockerRuntimeEffectObserver(DockerSdkClient(raw, docker_module=module))
        result, _ = self.observe(observer.observe_metadata, request)
        self.assertIs(type(result), RuntimeEffectObserverUnsupported)
        self.assertEqual(raw.calls, [])
        self.assertEqual(raw.close_calls, 0)

    def test_missing_or_unsupported_image_user_preserves_unaddressable_file_row(self):
        for user in (None, "named-user", "2147483648", "01"):
            with self.subTest(user=user):
                request, raw, _, method = self.fixture()
                image = request.products[0].product.image.execution_reference
                if user is None:
                    del raw.rows["image", image]
                else:
                    raw.rows["image", image]["Config"]["User"] = user
                _, evidence = self.observe(method, request)
                self.assertEqual(evidence["coverage"], "incomplete")
                row = evidence["resources"][-1]
                self.assertEqual(row["role"], "secret-volume")
                self.assertIsNone(row["selector"])
                self.assertNotIn(row["state"], ("present", "absent"))
                self.assertFalse(any(role == "volume" and name.startswith("cpk-sec-") for role, name in raw.calls))
                self.assertEqual(raw.close_calls, 1)

    def test_typed_absence_and_transport_failure_are_distinct(self):
        for failure, state in ((NotFound(CANARY), "absent"), (Timeout(CANARY), "unknown")):
            request, raw, _, method = self.fixture()
            raw.rows["container", _container_name(request, request.products[0].node_id)] = failure
            _, evidence = self.observe(method, request)
            self.assertEqual(evidence["resources"][0]["state"], state)
            self.assertEqual(evidence["coverage"], "selected-addresses-observed" if state == "absent" else "incomplete")
            self.assertEqual(raw.close_calls, 1)

    def test_foreign_ownership_is_preserved_as_conflict(self):
        request, raw, _, method = self.fixture()
        raw.rows["container", _container_name(request, request.products[0].node_id)]["Config"]["Labels"][PREFIX + "workspace"] = CANARY
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["resources"][0]["ownership"], "conflicting")
        self.assertEqual(evidence["resources"][0]["reason"], "ownership-conflict")

    def test_eight_volume_scope_fits_actual_core_codec_and_call_budget(self):
        request, raw, _, method = self.fixture(selected_request(count=8))
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "selected-addresses-observed")
        self.assertEqual(len(evidence["resources"]), 11)
        self.assertEqual(len(raw.calls) + raw.events.count("version"), 41)

    def test_daemon_mismatch_stops_before_resource_queries(self):
        request, raw, _, method = self.fixture()
        raw.rows["daemon", None]["ID"] = "another-daemon"
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        self.assertIsNone(evidence["provider_binding_fingerprint"])
        self.assertEqual(raw.calls, [("daemon", None)])
        self.assertEqual(len(evidence["resources"]), 5)

    def test_drift_is_incomplete_and_never_historical_success(self):
        request, raw, _, method = self.fixture()
        def drift(role, name):
            if role == "container" and raw.calls.count((role, name)) == 2:
                raw.rows[role, name]["Id"] = "e" * 64
        raw.hook = drift
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        self.assertEqual(evidence["resources"][0]["reason"], "drift")

    def test_deadline_stops_scheduling_and_closes(self):
        request, raw, module, method = self.fixture()
        with patch("control_plane_kit_interpreters.docker.recovery_metadata.monotonic", side_effect=[0, 0, 31]):
            _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        self.assertLessEqual(len(raw.calls), 1)
        self.assertEqual(raw.close_calls, len(module.docker_clients))

    def test_known_close_fault_is_incomplete_and_programming_fault_propagates(self):
        request, raw, _, method = self.fixture()
        raw.close_error = Timeout(CANARY)
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        request, raw, _, method = self.fixture()
        raw.rows["daemon", None] = AssertionError("internal bug")
        with self.assertRaisesRegex(AssertionError, "internal bug"):
            method(RuntimeEffectObservationRequest(request), LOCAL, expected_daemon_id=DAEMON)
        self.assertEqual(raw.close_calls, 1)
