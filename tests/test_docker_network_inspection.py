"""#194 exact same-payload network identity, membership and unavailable facts."""
from dataclasses import FrozenInstanceError
import unittest

import control_plane_kit_interpreters.docker as public
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule, FakeResource


NETWORK_A = "a" * 64
NETWORK_B = "b" * 64
CONTAINER = "c" * 64
MISSING = object()


class RecordingManager:
    def __init__(self, resources):
        self.resources, self.calls = resources, []
        self.error = None

    def get(self, identity):
        self.calls.append(identity)
        if self.error is not None:
            raise self.error
        from test_docker_sdk_client import FakeNotFound
        if identity not in self.resources:
            raise FakeNotFound(identity)
        return self.resources[identity]


class DockerNetworkInspectionTests(unittest.TestCase):
    def setUp(self):
        self.raw = FakeDockerClient()
        self.network = FakeResource("runtime", labels={"owner": "workspace"})
        self.network.attrs["Id"] = NETWORK_A
        self.container = FakeResource("gateway", image="fixture", running=True)
        self.container.attrs["Id"] = CONTAINER
        self.raw.networks = RecordingManager({NETWORK_A: self.network, "runtime": self.network})
        self.raw.containers = RecordingManager({CONTAINER: self.container, "gateway": self.container})
        self.sdk = DockerSdkClient(client=self.raw, docker_module=FakeDockerModule(self.raw))
        self.addCleanup(self.sdk.close)

    def attachments(self, networks):
        self.container.attrs["NetworkSettings"]["Networks"] = networks
        result = self.sdk.inspect_container(CONTAINER)
        values = getattr(result, "network_attachments", MISSING)
        self.assertIsNot(values, MISSING, "network membership projection is missing")
        return result, values

    def test_network_id_survives_exact_name_and_id_lookups(self):
        for lookup in (NETWORK_A, "runtime"):
            result = self.sdk.inspect_network(lookup)
            self.assertEqual(getattr(result, "network_id", None), NETWORK_A)
            self.assertEqual(result.name, "runtime")
            self.assertEqual(result.labels, {"owner": "workspace"})
            self.assertIsNone(getattr(result, "network_attachments", MISSING))
        self.assertEqual(self.raw.networks.calls, [NETWORK_A, "runtime"])
        self.assertEqual(self.raw.containers.calls, [])
        self.assertFalse(self.network.started or self.network.stopped or self.network.removed)

    def test_same_payload_memberships_preserve_identity_address_and_snapshot(self):
        networks = {"z-first": {"NetworkID": NETWORK_B, "IPAddress": "172.19.0.3"},
            "a-second": {"NetworkID": NETWORK_A, "IPAddress": "172.18.0.2"}}
        result, values = self.attachments(networks)
        self.assertEqual(result.container_id, CONTAINER)
        self.assertEqual(tuple((item.network_id, item.private_address) for item in values),
            ((NETWORK_A, "172.18.0.2"), (NETWORK_B, "172.19.0.3")))
        self.assertEqual(result.network_names, ("a-second", "z-first"))
        self.assertEqual(result.private_addresses, {"a-second": "172.18.0.2", "z-first": "172.19.0.3"})
        self.assertIsNone(result.network_id)
        networks["a-second"]["NetworkID"] = NETWORK_B
        networks["a-second"]["IPAddress"] = "172.19.0.9"
        self.assertEqual((values[0].network_id, values[0].private_address), (NETWORK_A, "172.18.0.2"))
        self.assertEqual(self.raw.containers.calls, [CONTAINER])
        self.assertEqual(self.raw.networks.calls, [])
        self.assertFalse(self.container.started or self.container.stopped or self.container.removed)

    def test_same_names_do_not_hide_changed_network_identity(self):
        first = self.sdk.inspect_network("runtime")
        self.network.attrs["Id"] = NETWORK_B
        second = self.sdk.inspect_network("runtime")
        self.assertNotEqual(first, second)
        first, left = self.attachments({"runtime": {"NetworkID": NETWORK_A, "IPAddress": "172.18.0.2"}})
        second, right = self.attachments({"runtime": {"NetworkID": NETWORK_B, "IPAddress": "172.18.0.2"}})
        self.assertEqual(first.name, second.name)
        self.assertNotEqual(left, right)
        self.assertNotEqual(first, second)

    def test_unknown_empty_and_known_addressless_are_distinct(self):
        for networks in ({}, {"runtime": {"IPAddress": "172.18.0.2"}},
                {"runtime": {"NetworkID": NETWORK_A}},
                {"runtime": {"NetworkID": NETWORK_A, "IPAddress": ""}}):
            with self.subTest(networks=networks):
                _result, values = self.attachments(networks)
                if not networks:
                    self.assertEqual(values, ())
                elif "NetworkID" not in networks["runtime"]:
                    self.assertIsNone(values)
                else:
                    self.assertEqual(tuple((item.network_id, item.private_address) for item in values),
                        ((NETWORK_A, None),))
        for missing in ("Networks", "NetworkSettings"):
            self.container.attrs["NetworkSettings"] = {}
            if missing == "NetworkSettings":
                del self.container.attrs["NetworkSettings"]
            result = self.sdk.inspect_container(CONTAINER)
            self.assertIsNone(getattr(result, "network_attachments", MISSING))
        del self.network.attrs["Id"]
        self.assertIsNone(getattr(self.sdk.inspect_network("runtime"), "network_id", MISSING))

    def test_malformed_duplicate_and_excessive_memberships_never_become_empty(self):
        cases = [
            {"runtime": {"NetworkID": value, "IPAddress": "172.18.0.2"}}
            for value in ("", "A" * 64, "a" * 63, 42, None)]
        cases.extend(({"one": {"NetworkID": NETWORK_A}, "two": {"NetworkID": NETWORK_A}},
            {f"net-{index}": {"NetworkID": f"{index:064x}"} for index in range(65)},
            {"runtime": {"NetworkID": NETWORK_A, "IPAddress": "PRIVATE.invalid"}},
            {"runtime": {"NetworkID": NETWORK_A, "IPAddress": "x" * 1000}},
            {"runtime": {"NetworkID": NETWORK_A, "IPAddress": "fe80::1%PRIVATE"}}))
        for networks in cases:
            with self.subTest(case=cases.index(networks)):
                self.container.attrs["NetworkSettings"]["Networks"] = networks
                with self.assertRaises(RuntimeError) as caught:
                    self.sdk.inspect_container(CONTAINER)
                self.assertNotIn("PRIVATE", str(caught.exception))
                self.assertLess(len(str(caught.exception)), 100)
        for identity in ("", "A" * 64, "a" * 63, 42, None):
            self.network.attrs["Id"] = identity
            with self.assertRaises(RuntimeError):
                self.sdk.inspect_network("runtime")

    def test_public_attachment_value_is_immutable_and_validated(self):
        attachment = getattr(public, "DockerSdkNetworkAttachment", None)
        self.assertIsNotNone(attachment, "public network attachment value is missing")
        value = attachment(NETWORK_A, "172.18.0.2")
        with self.assertRaises(FrozenInstanceError):
            value.network_id = NETWORK_B
        self.assertEqual(attachment(NETWORK_A, None).network_id, NETWORK_A)
        for identity, address in (("bad", None), (NETWORK_A, "PRIVATE.invalid"),
                (NETWORK_A, "fe80::1%PRIVATE"), (NETWORK_A, 1)):
            with self.assertRaises(ValueError) as caught:
                attachment(identity, address)
            self.assertNotIn("PRIVATE", str(caught.exception))
            self.assertLess(len(str(caught.exception)), 100)

    def test_absence_failure_and_client_lifetime_retain_existing_semantics(self):
        self.assertIsNone(self.sdk.inspect_network("missing"))
        self.assertIsNone(self.sdk.inspect_container("missing"))
        failure = RuntimeError("provider-failure")
        self.raw.networks.error = failure
        with self.assertRaises(RuntimeError) as caught:
            self.sdk.inspect_network(NETWORK_A)
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.raw.close_calls, 0)
        self.sdk.close()
        self.sdk.close()
        self.assertEqual(self.raw.close_calls, 1)
        self.assertEqual(self.raw.networks.calls, ["missing", NETWORK_A])
        self.assertEqual(self.raw.containers.calls, ["missing"])
