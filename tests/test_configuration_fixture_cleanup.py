"""Finite witness bookkeeping laws; no Docker engine access in package tests."""
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
import unittest

from docker.errors import NotFound
from live_docker_configuration import ConfigurationFixtureResources, LABEL


class Resource:
    def __init__(self, manager, identity, attrs):
        self.manager, self.id, self.name, self.attrs = manager, identity, identity, attrs
        self.fail_remove = False
        self.retain = False
        manager.values[identity] = self

    def reload(self):
        return None

    def remove(self, **_kwargs):
        self.manager.removals.append(self.id)
        self.manager.events.append(self.id)
        if self.fail_remove:
            raise RuntimeError("fixture removal failed")
        if not self.retain:
            del self.manager.values[self.id]


class Manager:
    def __init__(self, events):
        self.values, self.removals = {}, []
        self.events = events

    def get(self, identity):
        if identity not in self.values:
            raise NotFound("absent")
        return self.values[identity]


class ConfigurationFixtureCleanupTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.client = SimpleNamespace(volumes=Manager(self.events), containers=Manager(self.events))
        self.resources = ConfigurationFixtureResources(self.client, "run-a", "reader-image", "helper-image")

    def volume(self, name="volume-a", owner="run-a"):
        return self.resources.create("volume", name,
            lambda: Resource(self.client.volumes, name, {"Labels": {LABEL: owner}}))

    def helper(self, *, image="helper-image", volume="volume-a"):
        return self.resources.create("helper", "volume-a",
            lambda: Resource(self.client.containers, "helper-id", {"Image": image,
                "Mounts": [{"Type": "volume", "Name": volume, "Destination": "/artifact", "RW": True}]}),
            volume="volume-a", readonly=False)

    def hold(self):
        with redirect_stdout(StringIO()) as output, self.assertRaises(RuntimeError):
            self.resources.cleanup()
        self.assertIn('"configuration_mounts": "HOLD"', output.getvalue())

    def test_unacknowledged_second_create_cleans_prior_volume_but_retains_uncertainty(self):
        self.volume()
        calls = []

        def uncertain_create():
            calls.append(True)
            raise TimeoutError("no acknowledgement")

        with self.assertRaises(RuntimeError):
            self.resources.create("volume", "volume-b", uncertain_create)
        self.hold()
        self.assertEqual(calls, [True])
        self.assertEqual(self.client.volumes.values, {})
        self.assertEqual(self.resources.uncertain, [{"kind": "volume", "coordinate": "volume-b"}])

    def test_foreign_label_or_helper_image_or_binding_never_authorizes_deletion(self):
        self.volume(owner="foreign")
        self.helper(volume="foreign-volume")
        self.hold()
        self.assertEqual(self.client.volumes.removals, [])
        self.assertEqual(self.client.containers.removals, [])
        self.client.containers.values["helper-id"].attrs["Mounts"][0]["Name"] = "volume-a"
        self.client.containers.values["helper-id"].attrs["Image"] = "foreign-image"
        self.hold()
        self.assertEqual(self.client.containers.removals, [])

    def test_remaining_owned_helpers_are_removed_before_volumes_and_absence_is_required(self):
        self.volume()
        helper = self.helper()
        helper.retain = True
        self.hold()
        self.assertEqual(self.client.containers.removals, ["helper-id"])
        self.assertIn("helper-id", self.client.containers.values)
        self.assertEqual(self.client.volumes.values, {})

    def test_failed_helper_removal_does_not_skip_other_owned_cleanup(self):
        self.volume()
        self.helper().fail_remove = True
        self.hold()
        self.assertEqual(self.client.volumes.values, {})
        self.assertIn("helper-id", self.client.containers.values)

    def test_already_absent_resources_and_owned_helper_fallback_are_accepted(self):
        self.volume()
        self.helper()
        self.resources.create("reader", "reader-name", lambda: Resource(self.client.containers,
            "reader-id", {"Image": "reader-image", "Config": {"Labels": {LABEL: "run-a"}}}))
        self.resources.cleanup()
        self.resources.cleanup()
        self.assertEqual(self.events, ["reader-id", "helper-id", "volume-a"])
        self.assertEqual(self.client.volumes.values, {})
        self.assertEqual(self.client.containers.values, {})
