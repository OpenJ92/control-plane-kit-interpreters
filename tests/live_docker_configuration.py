"""#156 disposable selected-byte mount witness, called only by the owning gate."""
from __future__ import annotations

import json
from uuid import uuid4

from docker.errors import NotFound
from control_plane_kit_interpreters.docker import DockerSdkConfigurationMount
from health_signing_fixtures import world
from receiver_configuration_fixtures import receiver_artifacts

LABEL = "org.openj92.cpk.test-run"


class ConfigurationFixtureResources:
    """Finite bookkeeping for this witness, including unacknowledged creates."""
    def __init__(self, client, run_id, reader_image, helper_image):
        self.client, self.run_id = client, run_id
        self.reader_image, self.helper_image = reader_image, helper_image
        self.entries = []
        self.uncertain = []

    def create(self, kind, coordinate, operation, *, volume=None, readonly=None):
        try:
            resource = operation()
            identity = resource.name if kind == "volume" else resource.id
            if type(identity) is not str or not identity:
                raise ValueError
            self.entries.append((kind, identity, volume, readonly))
            return resource
        except Exception:
            attempt = {"kind": kind, "coordinate": coordinate}
            if kind in ("helper", "reader"):
                attempt["image"] = self.helper_image if kind == "helper" else self.reader_image
            self.uncertain.append(attempt)
        raise RuntimeError("configuration fixture create outcome uncertain")

    def cleanup(self):
        failed = []
        # All acknowledged containers precede volume removal, including SDK
        # helpers whose normal finally-removal failed.
        for kind in ("reader", "helper", "volume"):
            for entry_kind, identity, volume, readonly in reversed(self.entries):
                if entry_kind != kind:
                    continue
                manager = self.client.volumes if kind == "volume" else self.client.containers
                try:
                    resource = manager.get(identity)
                    resource.reload()
                    attrs = resource.attrs
                    if kind == "helper":
                        mounts = attrs.get("Mounts", [])
                        owned = (attrs.get("Image") == self.helper_image and len(mounts) == 1
                            and mounts[0].get("Type") == "volume" and mounts[0].get("Name") == volume
                            and mounts[0].get("Destination") == "/artifact"
                            and mounts[0].get("RW") is (not readonly))
                    else:
                        labels = attrs.get("Labels") if kind == "volume" else attrs.get("Config", {}).get("Labels")
                        owned = (labels or {}).get(LABEL) == self.run_id
                        if kind == "reader":
                            owned = owned and attrs.get("Image") == self.reader_image
                    if not owned:
                        failed.append({"kind": kind, "identity": identity, "reason": "ownership"})
                        continue
                    if kind == "volume":
                        resource.remove()
                    else:
                        resource.remove(force=True)
                    try:
                        manager.get(identity)
                    except NotFound:
                        continue
                    failed.append({"kind": kind, "identity": identity, "reason": "residue"})
                except NotFound:
                    continue
                except Exception:
                    failed.append({"kind": kind, "identity": identity, "reason": "cleanup"})
        if failed or self.uncertain:
            print(json.dumps({"configuration_mounts": "HOLD", "uncertain": self.uncertain,
                              "cleanup": failed}, sort_keys=True))
            raise RuntimeError("configuration fixture cleanup or create outcome unresolved")


def _numeric_read_script(expected):
    return (
        "import hashlib,os,pathlib,stat\n"
        "assert (os.getuid(),os.getgid()) == (10006,10008)\n"
        f"expected={expected!r}\n"
        "for target,selected,original in expected:\n"
        " p=pathlib.Path(target); s=p.lstat()\n"
        " assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o444\n"
        " digest=hashlib.sha256(p.read_bytes()).hexdigest()\n"
        " assert digest==selected and digest!=original\n"
    )


def _readonly_script(paths):
    return (
        "import errno,os\n"
        "assert os.getuid()==0\n"
        f"paths={paths!r}\n"
        "for target in paths:\n"
        " try: fd=os.open(target,os.O_WRONLY|os.O_TRUNC)\n"
        " except OSError as error:\n"
        "  assert error.errno==errno.EROFS\n"
        " else:\n"
        "  os.close(fd); raise SystemExit(5)\n"
    )


def run_configuration_witness(client, sdk, run_id, reader_image_id, helper_image_id):
    resources = ConfigurationFixtureResources(client, run_id, reader_image_id, helper_image_id)
    original_helper = sdk._create_configuration_helper

    def tracked_helper(volume_name, *, readonly):
        return resources.create("helper", volume_name,
            lambda: original_helper(volume_name, readonly=readonly), volume=volume_name, readonly=readonly)

    sdk._create_configuration_helper = tracked_helper
    try:
        reader_image = client.images.get(reader_image_id)
        assert reader_image.id == reader_image_id and reader_image.labels.get(LABEL) == run_id
        assert reader_image.attrs["Config"]["User"] == "10006:10008"
        assert client.images.get(helper_image_id).id == helper_image_id
        assert sdk.configuration_helper_image == helper_image_id
        original, selected = receiver_artifacts(world()), receiver_artifacts(world())
        expected, mounts = [], []
        token = uuid4().hex
        for index, (old, chosen) in enumerate(zip(original, selected, strict=True)):
            assert chosen.target_path == old.target_path and chosen.content_digest != old.content_digest
            name = f"cpk-config-volume-{token}-{index}"
            try:
                client.volumes.get(name)
            except NotFound:
                exists = False
            else:
                exists = True
            if exists:
                raise RuntimeError("configuration fixture volume already exists")
            volume = resources.create("volume", name,
                lambda: client.volumes.create(name=name, labels={LABEL: run_id}))
            assert volume.name == name
            volume.reload()
            assert volume.attrs.get("Labels", {}).get(LABEL) == run_id
            sdk.materialize_configuration_artifact(volume.name, chosen)
            assert sdk.configuration_artifact_digest(volume.name) == chosen.content_digest
            mounts.append(DockerSdkConfigurationMount(chosen, volume.name))
            expected.append((chosen.target_path, chosen.content_digest, old.content_digest))
        name = f"cpk-config-reader-{token}"
        reader = resources.create("reader", name, lambda: client.containers.create(
            reader_image_id, name=name, labels={LABEL: run_id}, network_disabled=True,
            command=["python", "-B", "-c", "import time; time.sleep(120)"],
            mounts=[dict(mount.docker_mount()) for mount in mounts], read_only=True,
            cap_drop=["ALL"], cap_add=["DAC_OVERRIDE"], security_opt=["no-new-privileges"]))
        reader.reload()
        assert reader.attrs["Image"] == reader_image_id
        assert reader.attrs["Config"]["User"] == "10006:10008"
        assert reader.attrs["Config"].get("Labels", {}).get(LABEL) == run_id
        reader.start()
        reader.reload()
        actual = reader.attrs["Mounts"]
        assert len(actual) == len(mounts)
        for mount in mounts:
            matching = [value for value in actual if value["Destination"] == mount.artifact.target_path]
            assert len(matching) == 1 and matching[0]["RW"] is False
            assert matching[0]["Type"] == "volume" and matching[0]["Name"] == mount.volume_name
        result = reader.exec_run(["python", "-B", "-c", _numeric_read_script(expected)], user="10006:10008")
        assert result.exit_code == 0, "selected configuration numeric read failed"
        result = reader.exec_run(["python", "-B", "-c", _readonly_script([item[0] for item in expected])], user="0:0")
        assert result.exit_code == 0, "configuration mount did not prove EROFS"
    finally:
        sdk._create_configuration_helper = original_helper
        resources.cleanup()
    print(json.dumps({"configuration_mounts": "passed", "slots": 2, "selected_not_default": True,
        "numeric_reader": True, "mode": "0444", "engine_readonly": True,
        "write_errno": "EROFS", "residue": "absent"}, sort_keys=True))
