"""#148 managed profile laws through actual Core selection and SDK projections."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import tarfile
import unittest
from unittest.mock import patch

from control_plane_kit_core.products import ProductDescriptorCodec, ProductReference
from control_plane_kit_core.capabilities import CapabilityName
from control_plane_kit_core.runtime_effects import RuntimeEffectKind
from control_plane_kit_core.topology import validate_graph
from control_plane_kit_interpreters.docker import connector_connection as module
from docker_connector_fixtures import CONTAINER_ID, sample
from managed_connector_fixtures import managed_world, observer, observe, TARGET
from test_docker_configuration_readback import archive_bytes


class ManagedConnectorTests(unittest.TestCase):
    def assert_result(self, world, expected, **changes):
        result = observe(world, **changes)
        self.assertEqual(result.outcome.value, expected)
        for text in ("PRIVATE-CANDIDATE", world.artifact.content, world.configuration_volume):
            self.assertNotIn(text, repr(result))
        return result

    def shape(self, world, document=None):
        def no_clock():
            raise AssertionError("qualification must not read time")
        return observer(world, clock=no_clock).qualify_shape(activity_id=world.request.activity_id,
            plan=world.plan, current=world.current, desired=world.desired,
            product_document=document or world.document, authority_ref=world.request.authority_ref)

    def test_declared_shape_and_actual_material_are_pure_explicit_profiles(self):
        for retained in (False, True):
            with self.subTest(retained=retained):
                world = managed_world(retained=retained, lazy=True)
                expected = (module.ConnectorConnectionQualification.RETAINED_CONTENT_UPDATE if retained
                            else module.ConnectorConnectionQualification.FRESH)
                self.assertIs(self.shape(world), expected)
                options = dict(activity_id=world.request.activity_id, plan=world.plan,
                    current=world.current, desired=world.desired, material=world.material,
                    authority_ref=world.request.authority_ref)
                self.assertIs(observer(world).qualify(**options), expected)
                self.assertIsNone(observer(world, managed=False).qualify(**options))
                self.assertEqual(world.initializations + world.api.calls + world.archive_calls, [])

    def test_declared_shape_does_not_accept_foreign_or_mutated_document(self):
        for case in ("bytes", "required-target", "surface", "extra-environment"):
            with self.subTest(case=case):
                world = managed_world(lazy=True)
                document = world.document
                if case == "bytes":
                    document = replace(document, content=document.content + b"\n")
                else:
                    contract = document.product.runtime_contract
                    if case == "required-target":
                        contract = replace(contract, configuration_requirements=(replace(
                            contract.configuration_requirements[0], target_path="/etc/other.json"),))
                    elif case == "surface":
                        contract = replace(contract, control_surfaces=(), capabilities=tuple(
                            value for value in contract.capabilities if value is not CapabilityName.NODE_CONTROLLABLE))
                    else: contract = replace(contract, public_environment=())
                    document = ProductDescriptorCodec().encode_document(replace(document.product, runtime_contract=contract))
                    world.reference = ProductReference.from_document(document)
                    node = world.desired.graph.nodes["connector"]
                    world.desired = validate_graph(world.desired.graph.update_node(replace(node, metadata={
                        "product_identity": world.reference.identity.key,
                        "product_descriptor_digest": world.reference.descriptor_sha256.value})))
                    world.recompile()
                self.assertIsNone(self.shape(world, document))
                self.assertEqual(world.initializations + world.api.calls + world.archive_calls, [])

    def test_fresh_and_retained_read_selected_content_without_helper(self):
        for retained in (False, True):
            for outcome in ("connected", "disconnected", "unknown"):
                with self.subTest(retained=retained, outcome=outcome):
                    world = managed_world(retained=retained)
                    world.mutate("State", "Health", {"Status": "healthy", "Log": [sample(), sample(outcome)]})
                    with patch.object(world.client, "inspect_configuration_file", side_effect=AssertionError("staging forbidden")), \
                         patch.object(world.client, "run_http_probe", side_effect=AssertionError("probe forbidden")):
                        self.assert_result(world, outcome)
                    self.assertEqual(world.archive_calls, [("get", CONTAINER_ID), ("archive", TARGET)])
                    self.assertEqual(world.api.calls, [("container", world.name),
                        ("image", world.material.product.image.execution_reference), ("container", CONTAINER_ID)])

    def test_actual_material_scope_and_current_authority_refuse_before_io(self):
        for case in ("body", "target", "environment", "authority"):
            with self.subTest(case=case):
                world = managed_world(lazy=True)
                request = world.request
                material = world.material
                if case in ("body", "target"):
                    artifact = replace(world.artifact, **({"content": "{}", "source_digest": None}
                        if case == "body" else {"target_path": "/etc/other.json"}))
                    material = replace(material, product=replace(material.product,
                        runtime_contract=replace(material.product.runtime_contract, configuration_artifacts=(artifact,))))
                elif case == "environment": material = replace(material, public_environment=())
                else: request = replace(request, authority_ref=replace(request.authority_ref, reference_id="foreign"))
                self.assert_result(world, "refused", request=replace(request, products=(material,)))
                self.assertEqual(world.initializations + world.api.calls + world.archive_calls, [])

    def test_retained_missing_or_incompatible_selection_never_becomes_fresh(self):
        for case in ("request", "receipt", "missing-selection", "foreign-receipt", "wrong-volume", "incarnation"):
            with self.subTest(case=case):
                world = managed_world(retained=True, lazy=True)
                changes = {}
                expected = "refused"
                if case == "request": changes["installation_request"] = None
                elif case == "receipt": changes["installation_receipt"] = None
                elif case == "missing-selection":
                    world.installation_request = replace(world.installation_request,
                        kind=RuntimeEffectKind.REALIZE_ACTIVITY,
                        configuration_instances=None)
                    world.install_receipt()
                elif case == "foreign-receipt":
                    changes["installation_receipt"] = replace(world.installation_receipt, request_fingerprint="f" * 64)
                elif case == "wrong-volume":
                    for container in world.containers:
                        container["HostConfig"]["Mounts"][1]["Source"] = "foreign-candidate"
                        container["Mounts"][1]["Name"] = "foreign-candidate"
                    expected = "unknown"
                else:
                    world.install_receipt(container_id="e" * 64)
                    expected = "unknown"
                self.assert_result(world, expected, **changes)
                if expected == "refused": self.assertEqual(world.initializations + world.api.calls, [])
                self.assertEqual(world.archive_calls, [])

    def test_fresh_rejects_unsolicited_installation_pair(self):
        world = managed_world(lazy=True)
        retained = managed_world(retained=True)
        self.assert_result(world, "refused", installation_request=retained.installation_request,
                           installation_receipt=retained.installation_receipt)
        self.assertEqual(world.initializations + world.api.calls + world.archive_calls, [])

    def test_configuration_content_mode_regular_file_and_unavailability_are_not_success(self):
        for case in ("body", "mode", "symlink", "extra", "oversize", "provider"):
            with self.subTest(case=case):
                world = managed_world()
                options = dict(name="control.json", body=world.artifact.content.encode())
                if case == "body": options["body"] = b"PRIVATE-CANDIDATE"
                elif case == "mode": options["mode"] = 0o644
                elif case == "symlink": options["kind"] = tarfile.SYMTYPE
                elif case == "extra": options["extra"] = True
                elif case == "oversize": options["body"] = b"x" * 262145
                else: world.archive_error = TimeoutError("PRIVATE-CANDIDATE")
                world.archive = archive_bytes(**options)
                self.assert_result(world, "unknown")
                self.assertEqual(world.archive_calls, [("get", CONTAINER_ID), ("archive", TARGET)])

    def test_managed_launch_is_exact_for_image_and_effective_container(self):
        for owner in ("image", "container"):
            for case in ("entrypoint", "cmd", "user", "cwd", "signal", "environment", "health", "shell", "volumes"):
                with self.subTest(owner=owner, case=case):
                    world = managed_world()
                    config = world.image["Config"] if owner == "image" else world.containers[0]["Config"]
                    key, value = {
                        "entrypoint": ("Entrypoint", ["PRIVATE-CANDIDATE"]), "cmd": ("Cmd", ["other"]),
                        "user": ("User", "0"), "cwd": ("WorkingDir", "/tmp"), "signal": ("StopSignal", "SIGKILL"),
                        "environment": ("Env", config["Env"] + ["TUNNEL_TOKEN=PRIVATE-CANDIDATE"]),
                        "health": ("Healthcheck", {**config["Healthcheck"], "Retries": 2}),
                        "shell": ("Shell", ["sh"]), "volumes": ("Volumes", {"/other": {}}),
                    }[case]
                    config[key] = value
                    self.assert_result(world, "unknown")
                    self.assertEqual(world.archive_calls, [])

    def test_two_mount_profile_rejects_extra_shadowed_writable_or_drifted_mounts(self):
        for case in ("extra", "duplicate", "shadow", "writable", "subpath", "observed-name", "bind", "tmpfs", "volumes-from"):
            with self.subTest(case=case):
                world = managed_world()
                container = world.containers[0]
                configured, effective = container["HostConfig"]["Mounts"], container["Mounts"]
                if case in ("extra", "duplicate"):
                    configured.append(deepcopy(configured[1]))
                    effective.append(deepcopy(effective[1]))
                    if case == "extra":
                        configured[-1]["Target"] = "/other"
                        effective[-1]["Destination"] = "/other"
                elif case == "shadow":
                    configured[0]["Target"] = "/etc/cpk"
                    effective[0]["Destination"] = "/etc/cpk"
                elif case == "writable": configured[1]["ReadOnly"] = False
                elif case == "subpath": configured[1]["VolumeOptions"]["Subpath"] = "other"
                elif case == "observed-name": effective[1]["Name"] = "other"
                else: container["HostConfig"][{"bind":"Binds", "tmpfs":"Tmpfs", "volumes-from":"VolumesFrom"}[case]] = ["PRIVATE-CANDIDATE"]
                self.assert_result(world, "unknown")
                self.assertEqual(world.archive_calls, [])

    def test_final_mount_sample_and_incarnation_drift_remain_unknown(self):
        for case in ("mount", "sample", "id", "launch", "during-archive"):
            with self.subTest(case=case):
                world = managed_world()
                final = world.containers[1]
                if case == "mount":
                    final["HostConfig"]["Mounts"][1]["Source"] = "other"
                    final["Mounts"][1]["Name"] = "other"
                elif case == "sample": final["State"]["Health"]["Log"] = [sample("disconnected")]
                elif case == "id": final["Id"] = "e" * 64
                elif case == "launch": final["Config"]["Env"].append("OTHER=changed")
                else:
                    def drift():
                        world.containers[0]["Mounts"][1]["Name"] = "changed-during-read"
                    world.archive_after_read = drift
                self.assert_result(world, "unknown")

    def test_stale_sample_and_late_archive_do_not_reuse_earlier_success(self):
        for late in (False, True):
            with self.subTest(late=late):
                world = managed_world()
                if late:
                    def advance(): world.now += timedelta(seconds=11)
                    world.archive_after_read = advance
                else: world.now += timedelta(seconds=11)
                self.assert_result(world, "unknown")

    def test_profile_selector_is_closed(self):
        world = managed_world()
        with self.assertRaises(TypeError):
            module.DockerConnectorConnectionObserver(world.client, world.reference,
                world.material.product.image.execution_reference, lambda: world.now, profile="managed-wrapper-v1")
