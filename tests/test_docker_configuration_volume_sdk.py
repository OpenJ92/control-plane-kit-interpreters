"""C SDK laws: authoritative bounded use and guarded non-forced volume delete."""
import unittest
from configuration_cleanup_fixtures import cleanup_fixture, holder, conflict


class DockerConfigurationVolumeSdkTests(unittest.TestCase):
    def methods(self, sdk):
        for name in ("inspect_configuration_volume", "configuration_volume_in_use", "remove_configuration_volume"):
            self.assertTrue(callable(getattr(sdk, name, None)), f"missing cleanup SDK method {name}")

    def test_actual_local_volume_facts_and_nonforced_delete(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
        self.methods(sdk)
        name = resources[0].name
        observed = sdk.inspect_configuration_volume(name)
        self.assertEqual(observed.name, name)
        self.assertEqual(observed.created_at, resources[0].attrs["CreatedAt"])
        self.assertEqual(observed.labels, resources[0].attrs["Labels"])
        self.assertTrue(observed.local_storage)
        self.assertIs(sdk.configuration_volume_in_use(name), False)
        sdk.remove_configuration_volume(observed)
        self.assertIsNone(sdk.inspect_configuration_volume(name))
        self.assertIn(("remove-volume", name, False), events)

    def test_all_states_exact_volume_filter_limit_and_positive_mount_fact(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
        self.methods(sdk)
        name = resources[0].name
        holders.append(holder(name, "exited"))
        self.assertIs(sdk.configuration_volume_in_use(name), True)
        self.assertEqual(events, [("use-query", {"all": True, "limit": 1, "filters": {"volume": name}})])

    def test_malformed_or_unbounded_use_and_failed_provider_are_never_false(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
        self.methods(sdk)
        name = resources[0].name
        for rows in (None, {}, [holder(name)] * 2, [{}], [holder("other")],
                     [{**holder(name), "Id": "short"}], [{**holder(name), "Mounts": []}]):
            with self.subTest(rows=rows):
                raw.api.containers = lambda **kwargs: rows
                with self.assertRaises(Exception):
                    sdk.configuration_volume_in_use(name)
        def unavailable(**kwargs):
            raise TimeoutError("private")
        raw.api.containers = unavailable
        with self.assertRaises(TimeoutError):
            sdk.configuration_volume_in_use(name)

    def test_changed_volume_is_never_removed_and_typed_conflict_is_distinct(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
        self.methods(sdk)
        observed = sdk.inspect_configuration_volume(resources[0].name)
        resources[0].attrs["CreatedAt"] = "2026-10-09T00:01:00Z"
        with self.assertRaises(Exception):
            sdk.remove_configuration_volume(observed)
        self.assertFalse(any(event[0] == "remove-volume" for event in events))
        observed = sdk.inspect_configuration_volume(resources[0].name)
        def in_use(**kwargs):
            raise conflict()
        resources[0].remove = in_use
        with self.assertRaises(Exception) as raised:
            sdk.remove_configuration_volume(observed)
        self.assertEqual(type(raised.exception).__name__, "DockerSdkConfigurationVolumeInUse")
        self.assertNotIn("private", str(raised.exception))

    def test_admitted_labels_are_an_independent_snapshot(self):
        raw, sdk, interpreter, request, resources, holders, events = cleanup_fixture()
        self.methods(sdk)
        observed = sdk.inspect_configuration_volume(resources[0].name)
        original_labels = dict(observed.labels)
        resources[0].attrs["Labels"]["org.openj92.cpk.node"] = "foreign"
        self.assertEqual(observed.labels, original_labels)
        with self.assertRaises(Exception):
            sdk.remove_configuration_volume(observed)
        self.assertFalse(any(event[0] == "remove-volume" for event in events))
