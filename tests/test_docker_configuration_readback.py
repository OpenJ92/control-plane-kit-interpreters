"""I177-A: SDK provider facts, not lifecycle authority or a second interpreter."""
from dataclasses import replace
from io import BytesIO
import hashlib
import tarfile
import unittest
from unittest.mock import patch

from control_plane_kit_core.configuration import ConfigurationFileMode
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient, DockerSdkConfigurationMount
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule, FakeResource, FakeNotFound, _artifact


def archive_bytes(*, name="content", body=b"selected configuration", mode=0o444, kind=tarfile.REGTYPE, extra=False):
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.mode, member.type = mode, kind
        member.size = len(body) if kind == tarfile.REGTYPE else 0
        if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            member.linkname = "unrelated"
        archive.addfile(member, BytesIO(body) if member.size else None)
        if extra:
            archive.addfile(tarfile.TarInfo("extra"))
    return output.getvalue()


class DockerConfigurationReadbackTests(unittest.TestCase):
    def sdk(self):
        raw = FakeDockerClient()
        return raw, DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))

    def method(self, sdk, name):
        method = getattr(sdk, name, None)
        self.assertTrue(callable(method), "missing SDK configuration readback")
        return method

    def installed(self):
        raw, sdk = self.sdk()
        identity = "a" * 64
        mount = DockerSdkConfigurationMount(_artifact(), "selected-volume")
        resource = FakeResource("logical-name", running=True)
        resource.attrs["Id"] = identity
        resource.attrs["HostConfig"]["Mounts"] = [dict(mount.docker_mount())]
        resource.attrs["Mounts"] = [{"Type": "volume", "Name": mount.volume_name,
            "Destination": mount.artifact.target_path, "RW": False}]
        raw.containers.resources[identity] = resource
        resource.get_archive = lambda path: ([archive_bytes(name="config.json")], {})
        return raw, sdk, identity, resource, mount

    def test_staged_file_observes_bytes_mode_and_readonly_helper(self):
        for mode in ConfigurationFileMode:
            with self.subTest(mode=mode):
                raw, sdk = self.sdk()
                method = self.method(sdk, "inspect_configuration_file")
                artifact = replace(_artifact(), file_mode=mode)
                sdk.materialize_configuration_artifact("selected-volume", artifact)
                observed = method("selected-volume")
                self.assertEqual(observed.content_digest, artifact.content_digest)
                self.assertEqual(observed.mode, int(mode.value, 8))
                self.assertTrue(observed.regular_file)
                self.assertNotIn(artifact.content, repr(observed))
                self.assertEqual(raw.containers.created[-1]["volumes"],
                                 {"selected-volume": {"bind": "/artifact", "mode": "ro"}})
                self.assertTrue(all(value.force_removed for value in raw.containers.created_containers))

    def test_staged_file_distinguishes_absent_and_malformed_bounded_evidence(self):
        raw, sdk = self.sdk()
        method = self.method(sdk, "inspect_configuration_file")
        self.assertIsNone(method("empty-volume"))
        malformed = (
            archive_bytes(kind=tarfile.SYMTYPE), archive_bytes(kind=tarfile.LNKTYPE),
            archive_bytes(kind=tarfile.DIRTYPE), archive_bytes(extra=True),
            archive_bytes(name="wrong"), archive_bytes(body=b"x" * 262145),
            archive_bytes()[:520], b"invalid archive", b"x" * 1048577,
        )
        for index, payload in enumerate(malformed):
            with self.subTest(case=index):
                raw.containers.volume_archives["selected-volume"] = {"/artifact": payload}
                with self.assertRaisesRegex(RuntimeError, "configuration.*evidence"):
                    method("selected-volume")
        self.assertTrue(all(value.force_removed for value in raw.containers.created_containers))

    def test_stream_and_helper_cleanup_failures_remain_provider_uncertainty(self):
        raw, sdk = self.sdk()
        method = self.method(sdk, "inspect_configuration_file")
        def incomplete():
            yield b"prefix"
            raise TimeoutError("incomplete provider stream")
        with patch.object(FakeResource, "get_archive", return_value=(incomplete(), {})):
            with self.assertRaises(TimeoutError):
                method("selected-volume")
        self.assertTrue(raw.containers.created_containers[-1].force_removed)
        with patch.object(FakeResource, "remove", side_effect=TimeoutError("helper cleanup unknown")):
            with self.assertRaises(TimeoutError):
                method("empty-volume")
        with patch.object(FakeResource, "get_archive", return_value=(iter([b""] * 1025), {})):
            with self.assertRaisesRegex(RuntimeError, "configuration.*evidence"):
                method("selected-volume")

    def test_installed_mount_reads_actual_file_on_exact_container_identity(self):
        raw, sdk, identity, resource, mount = self.installed()
        method = self.method(sdk, "inspect_configuration_mount")
        inspection = sdk.inspect_container(identity)
        self.assertEqual(inspection.container_id, identity)
        with patch.object(resource, "get_archive", wraps=resource.get_archive) as read:
            observed = method(identity, mount)
        read.assert_called_once_with(mount.artifact.target_path)
        self.assertEqual(observed.container_id, identity)
        self.assertEqual(observed.volume_name, mount.volume_name)
        self.assertEqual(observed.target_path, mount.artifact.target_path)
        self.assertEqual(observed.subpath, "content")
        self.assertIs(observed.read_only, True)
        self.assertEqual(observed.file.content_digest, hashlib.sha256(b"selected configuration").hexdigest())
        self.assertNotEqual(observed.file.content_digest, mount.artifact.content_digest)
        self.assertEqual(observed.file.mode, 0o444)
        self.assertTrue(observed.file.regular_file)
        self.assertEqual(raw.containers.created, [])

    def test_installed_mount_rejects_conflicting_ambiguous_or_missing_provider_facts(self):
        for case in ("identity", "missing-id", "configured-source", "configured-target", "subpath",
                     "configured-rw", "observed-source", "observed-rw", "typed-rw", "duplicate-configured",
                     "duplicate-observed", "missing-configured", "missing-observed"):
            with self.subTest(case=case):
                raw, sdk, identity, resource, mount = self.installed()
                method = self.method(sdk, "inspect_configuration_mount")
                configured = resource.attrs["HostConfig"]["Mounts"]
                observed = resource.attrs["Mounts"]
                if case == "identity": resource.attrs["Id"] = "b" * 64
                elif case == "missing-id": del resource.attrs["Id"]
                elif case == "configured-source": configured[0]["Source"] = "other"
                elif case == "configured-target": configured[0]["Target"] = "/other"
                elif case == "subpath": configured[0]["VolumeOptions"] = {"Subpath": "other"}
                elif case == "configured-rw": configured[0]["ReadOnly"] = False
                elif case == "observed-source": observed[0]["Name"] = "other"
                elif case == "observed-rw": observed[0]["RW"] = True
                elif case == "typed-rw": observed[0]["RW"] = 0
                elif case == "duplicate-configured": configured.append(configured[0].copy())
                elif case == "duplicate-observed": observed.append(observed[0].copy())
                elif case == "missing-configured": del resource.attrs["HostConfig"]["Mounts"]
                elif case == "missing-observed": del resource.attrs["Mounts"]
                with patch.object(resource, "get_archive", wraps=resource.get_archive) as read:
                    with self.assertRaisesRegex(RuntimeError, "configuration.*evidence"):
                        method(identity, mount)
                    read.assert_not_called()
                self.assertEqual(raw.containers.created, [])

    def test_installed_absence_or_provider_failure_is_not_installation_success(self):
        raw, sdk, identity, resource, mount = self.installed()
        method = self.method(sdk, "inspect_configuration_mount")
        self.assertIsNone(method("b" * 64, mount))
        with patch.object(resource, "get_archive", side_effect=FakeNotFound("missing")):
            self.assertIsNone(method(identity, mount))
        with patch.object(resource, "get_archive", side_effect=TimeoutError("provider read unknown")):
            with self.assertRaises(TimeoutError):
                method(identity, mount)
        with self.assertRaises(ValueError):
            method("logical-name", mount)
        self.assertEqual(raw.containers.created, [])
