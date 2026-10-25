"""#224 current metadata laws, exercised at actual SDK request boundaries."""
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
from control_plane_kit_core.runtime_effects import RuntimeEffectKind
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
            "Id": "b" * 64, "Name": "/" + _container_name(request, material.node_id),
            "Image": "sha256:" + "a" * 64,
            "NetworkSettings": {"Networks": {_network_name(request, material.runtime_id): {"NetworkID": "c" * 64}}},
            "Mounts": [], "State": {"Running": True, "Status": "running"},
            "Config": {"Labels": _node_labels(request, material), "Env": Forbidden()}}
        self.rows["network", _network_name(request, material.runtime_id)] = {
            "Id": "c" * 64, "Name": _network_name(request, material.runtime_id),
            "Labels": _runtime_labels(request, material.runtime_id)}
        mounts = self.rows["container", _container_name(request, material.node_id)]["Mounts"]
        if request.configuration_instances is not None:
            for ref in request.configuration_instances.instances:
                self.volume(configuration_volume_name(ref), configuration_volume_labels(ref))
                mounts.append({"Type": "volume", "Name": configuration_volume_name(ref), "Destination": ref.target_path, "RW": False})
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
            mounts.append({"Type": "volume", "Name": name, "Destination": secret.target_path, "RW": False})

    def volume(self, name, labels):
        self.rows["volume", name] = {"Name": name, "Labels": labels,
            "Driver": "local", "Scope": "local", "CreatedAt": "2026-01-01T00:00:00Z", "Mountpoint": CANARY}
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
        return [{"Id": "d" * 64, "Mounts": [{"Type": "volume", "Name": name}], "Private": CANARY}] if name in self.attached else []


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

    def test_malformed_provider_fields_are_closed_unknown_not_absence(self):
        for change in (lambda row: row.update(Id=CANARY),
                       lambda row: row["Config"].update(Labels={str(i): "x" for i in range(65)}),
                       lambda row: row["Config"].update(Labels={"x": "y" * 2049}),
                       lambda row: row["Config"].update(Labels={str(i): "y" * 2048 for i in range(9)})):
            request, raw, _, method = self.fixture()
            change(raw.rows["container", _container_name(request, request.products[0].node_id)])
            _, evidence = self.observe(method, request)
            row = evidence["resources"][0]
            self.assertEqual((row["state"], row["reason"]), ("unknown", "malformed"))
            self.assertEqual(evidence["coverage"], "incomplete")

    def test_wrong_digest_cannot_supply_file_uid(self):
        request, raw, _, method = self.fixture()
        raw.rows["image", request.products[0].product.image.execution_reference]["RepoDigests"] = ["example.invalid/other@sha256:" + "f" * 64]
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["resources"][2]["ownership"], "conflicting")
        self.assertIsNone(evidence["resources"][-1]["selector"])
        self.assertEqual(evidence["coverage"], "incomplete")

    def test_environment_delivery_needs_no_uid_or_resource_row(self):
        request, raw, _, method = self.fixture(request_for(files=False, grants=False))
        raw.rows["image", request.products[0].product.image.execution_reference]["Config"]["User"] = "named-user"
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "selected-addresses-observed")
        self.assertEqual(len(evidence["resources"]), 3)
        self.assertEqual(len(raw.calls), 8)

    def test_duplicate_uid_dependent_selectors_stop_before_volume_read(self):
        request, raw, _, method = self.fixture(request_for(file_count=2, grants=False))
        with patch("control_plane_kit_interpreters.docker.recovery_metadata._secret_volume_name",
                   return_value="cpk-sec-collision"):
            _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        self.assertFalse(any(role in ("volume", "attachment") for role, _ in raw.calls))
        self.assertEqual(len(evidence["resources"]), 5)

    def test_nonfinite_backwards_or_failed_clock_never_schedules_unbounded_reads(self):
        for ticks in ([float("nan")], [10, 9], [0, 0, 0, 0, float("inf")],
                      [0, 0, 0, 0, OSError(CANARY)]):
            with self.subTest(ticks=ticks):
                request, raw, module, method = self.fixture()
                with patch("control_plane_kit_interpreters.docker.recovery_metadata.monotonic", side_effect=ticks):
                    _, evidence = self.observe(method, request)
                self.assertEqual(evidence["coverage"], "incomplete")
                self.assertEqual(raw.calls, [])
                self.assertEqual(raw.close_calls, len(module.docker_clients))

    def test_deadline_after_returned_client_stops_before_negotiation(self):
        request, raw, module, method = self.fixture()
        with patch("control_plane_kit_interpreters.docker.recovery_metadata.monotonic", side_effect=[0, 0, 0, 30]):
            _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        self.assertEqual(len(module.docker_clients), 1)
        self.assertNotIn("version", raw.events)
        self.assertEqual(raw.close_calls, 1)

    def test_provider_binding_drift_discards_selected_coverage(self):
        request, raw, _, method = self.fixture()
        def drift(role, name):
            if role == "daemon" and raw.calls.count((role, name)) == 2:
                raw.rows[role, name]["ID"] = "another-daemon"
        raw.hook = drift
        _, evidence = self.observe(method, request)
        self.assertIsNone(evidence["provider_binding_fingerprint"])
        self.assertEqual(evidence["coverage"], "incomplete")
        self.assertTrue(all(row["state"] == "unknown" for row in evidence["resources"]))

    def test_attachment_fault_is_incomplete_and_stopped_holders_count(self):
        request, raw, _, method = self.fixture()
        raw.api.containers = lambda **kwargs: [{"Id": CANARY}]
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        self.assertTrue(all(row["attachment"] == "unknown" for row in evidence["resources"][3:]))

    def test_legacy_configuration_without_allocations_is_unsupported_before_io(self):
        request = replace(selected_request(), kind=RuntimeEffectKind.REALIZE_ACTIVITY, configuration_instances=None)
        request, raw, module, method = self.fixture(request)
        result, _ = self.observe(method, request)
        self.assertIs(type(result), RuntimeEffectObserverUnsupported)
        self.assertEqual(module.docker_clients, [])
        self.assertEqual(raw.calls, [])

    def test_exact_names_extra_cpk_labels_and_container_image_network_mounts(self):
        changes = (
            lambda row: row.update(Name="/foreign-name"),
            lambda row: row["Config"]["Labels"].update({PREFIX + "foreign": "unexpected"}),
            lambda row: row.update(Image="sha256:" + "f" * 64),
            lambda row: row["NetworkSettings"].update(Networks={"foreign-network": {"NetworkID": "c" * 64}}),
            lambda row: row["Mounts"][0].update(Name="foreign-volume"),
            lambda row: row["Mounts"][0].update(Destination="/foreign-path"),
            lambda row: row["Mounts"][0].update(RW=True),
        )
        for change in changes:
            request, raw, _, method = self.fixture()
            change(raw.rows["container", _container_name(request, request.products[0].node_id)])
            _, evidence = self.observe(method, request)
            self.assertNotEqual(evidence["resources"][0]["ownership"], "matching")
        request, raw, _, method = self.fixture()
        raw.rows["network", _network_name(request, request.products[0].runtime_id)]["Name"] = "foreign-network"
        _, evidence = self.observe(method, request)
        self.assertNotEqual(evidence["resources"][1]["ownership"], "matching")

    def test_selected_mount_and_volume_incarnation_drift_are_detected(self):
        for which in ("mount", "created", "state", "network-identity"):
            request, raw, _, method = self.fixture()
            def drift(role, name):
                if raw.calls.count((role, name)) != 2:
                    return
                if role == "container":
                    if which == "mount":
                        raw.rows[role, name]["Mounts"][0]["RW"] = True
                    elif which == "state":
                        raw.rows[role, name]["State"].update(Running=False, Status="exited")
                    elif which == "network-identity":
                        next(iter(raw.rows[role, name]["NetworkSettings"]["Networks"].values()))["NetworkID"] = "f" * 64
                if role == "volume" and which == "created":
                    raw.rows[role, name]["CreatedAt"] = "2026-01-02T00:00:00Z"
            raw.hook = drift
            _, evidence = self.observe(method, request)
            self.assertEqual(evidence["coverage"], "incomplete", which)
            self.assertTrue(any(row["reason"] == "drift" for row in evidence["resources"]), which)

    def test_attachment_requires_exact_mount_and_cannot_contradict_absence(self):
        for mounts in (None, [], [{"Type": "volume", "Name": "foreign-volume"}]):
            request, raw, _, method = self.fixture()
            raw.api.containers = lambda **kwargs: [{"Id": "d" * 64, "Mounts": mounts}]
            _, evidence = self.observe(method, request)
            self.assertEqual(evidence["coverage"], "incomplete")
            self.assertEqual(evidence["resources"][3]["attachment"], "unknown")
        request, raw, _, method = self.fixture()
        name = configuration_volume_name(request.configuration_instances.instances[0])
        del raw.rows["volume", name]
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        request, raw, _, method = self.fixture()
        name = configuration_volume_name(request.configuration_instances.instances[0])
        del raw.rows["volume", name]
        raw.attached.remove(name)
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")

    def test_every_failed_metadata_read_stops_all_later_calls(self):
        for role in ("image", "container", "network", "volume"):
            for malformed in (False, True):
                request, raw, _, method = self.fixture()
                key = next(key for key in raw.rows if key[0] == role)
                raw.rows[key] = {} if malformed else Timeout(CANARY)
                _, evidence = self.observe(method, request)
                self.assertEqual(evidence["coverage"], "incomplete")
                self.assertEqual(raw.calls[-1], key)
                self.assertEqual(raw.calls.count(key), 1)
                self.assertEqual(raw.close_calls, 1)

    def test_file_indices_are_independent_of_environment_delivery_indices(self):
        request = request_for(file_count=2, grants=False)
        material, = request.products
        contract = material.product.runtime_contract
        env = contract.secret_deliveries[0]
        contract = replace(contract, secret_deliveries=tuple(replace(env, environment_name=f"TOKEN_{i}") for i in range(9)) + contract.secret_deliveries[1:])
        request = replace(request, products=(replace(material, product=replace(material.product, runtime_contract=contract)),))
        request, raw, _, method = self.fixture(request)
        _, evidence = self.observe(method, request)
        self.assertEqual([row["index"] for row in evidence["resources"] if row["role"] == "secret-volume"], [0, 1])

    def test_malformed_unicode_volume_label_is_closed_and_stops(self):
        request, raw, _, method = self.fixture()
        key = next(key for key in raw.rows if key[0] == "volume")
        raw.rows[key]["Labels"]["provider.label"] = "\ud800"
        _, evidence = self.observe(method, request)
        self.assertEqual(evidence["coverage"], "incomplete")
        self.assertEqual(evidence["resources"][3]["reason"], "malformed")
        self.assertEqual(raw.calls[-1], key)

    def test_official_image_spelling_reuses_existing_exact_repository_matching(self):
        for spelling, supported in (("postgres", True), ("library/postgres", True),
                                    ("docker.io/postgres", True), ("redis", False),
                                    ("ghcr.io/library/postgres", False)):
            request = request_for(grants=False)
            material, = request.products
            image = replace(material.product.image, registry="docker.io", repository="library/postgres")
            request = replace(request, products=(replace(material, product=replace(material.product, image=image)),))
            request, raw, _, method = self.fixture(request)
            raw.rows["image", image.execution_reference]["RepoDigests"] = [spelling + "@" + image.digest]
            _, evidence = self.observe(method, request)
            self.assertEqual(evidence["coverage"], "selected-addresses-observed" if supported else "incomplete")
            self.assertEqual(evidence["resources"][-1]["selector"] is not None, supported)
