"""Provider fixture with immutable IDs and actual staged archive-backed mounts."""
from dataclasses import replace
from io import BytesIO
from pathlib import PurePosixPath
import tarfile

from control_plane_kit_core.configuration_instances import ConfigurationInstanceRef, ConfigurationInstanceSelection
from control_plane_kit_core.planning import NodeTarget, ReconcileNode, StartNode
from control_plane_kit_core.runtime_effects import RuntimeEffectKind
from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter, DockerSdkClient
from test_docker_runtime_interpreter import _artifact, _material, _product, _request
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule, FakeManager, FakeNotFound


class ConfigurationContainers(FakeManager):
    def __init__(self, events):
        super().__init__()
        self.events = events
        self.after_create = None

    def get(self, identity):
        self.events.append(("get", identity))
        for resource in reversed(self.created_containers):
            if resource.attrs.get("Id") == identity and not resource.removed:
                return resource
        resource = super().get(identity)
        if resource.removed:
            raise FakeNotFound(identity)
        return resource

    def create_container(self, image, **kwargs):
        resource = super().create_container(image, **kwargs)
        identity = format(len(self.created_containers), "064x")
        resource.attrs["Id"] = identity
        is_workload = "org.openj92.cpk.node" in kwargs.get("labels", {})
        kind = "workload" if is_workload else "helper"
        self.events.append(("create", kind, identity))
        remove, start, read = resource.remove, resource.start, resource.get_archive

        def removed(**arguments):
            self.events.append(("remove", kind, identity))
            return remove(**arguments)

        def started():
            self.events.append(("start", kind, identity))
            return start()

        def archive(path):
            self.events.append(("read", kind, identity, path))
            if not is_workload:
                return read(path)
            mounts = [item for item in resource.attrs["Mounts"] if item["Destination"] == path]
            if len(mounts) != 1:
                raise FakeNotFound(path)
            payload = self.volume_archives.get(mounts[0]["Name"], {}).get("/artifact")
            if payload is None:
                raise FakeNotFound(path)
            with tarfile.open(fileobj=BytesIO(payload)) as source:
                member = source.getmember("content")
                body = source.extractfile(member).read()
            output = BytesIO()
            with tarfile.open(fileobj=output, mode="w") as target:
                observed = tarfile.TarInfo(PurePosixPath(path).name)
                observed.mode, observed.size = member.mode, len(body)
                target.addfile(observed, BytesIO(body))
            return [output.getvalue()], {}

        resource.remove, resource.start, resource.get_archive = removed, started, archive
        if is_workload and self.after_create is not None:
            self.after_create(resource)
        return resource


def fixture():
    raw = FakeDockerClient()
    events = []
    raw.containers = ConfigurationContainers(events)
    raw.containers.image_resources = raw.images.resources
    raw.containers.create = raw.containers.create_container
    sdk = DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
    return raw, sdk, DockerRuntimeInterpreter(sdk), events


def selected_request(*, reconcile=False, generation="a", count=1, content=None):
    base = _artifact()
    artifacts = tuple(replace(base, artifact_id=f"config-{index}",
        target_path=f"/etc/service/config-{index}.json",
        content=base.content if content is None else content) for index in range(count))
    product = _product()
    product = replace(product, runtime_contract=replace(product.runtime_contract,
        configuration_artifacts=artifacts))
    request = _request(ReconcileNode(NodeTarget("api")) if reconcile else StartNode(NodeTarget("api")),
        products=(_material(product),))
    selection = ConfigurationInstanceSelection(tuple(ConfigurationInstanceRef(
        f"allocation-{generation}-{index}", request.source.workspace_id, "docker", "api",
        artifact.artifact_id, artifact.target_path, artifact.media_type,
        artifact.file_mode, artifact.content_digest,
    ) for index, artifact in enumerate(artifacts)))
    return replace(request, kind=RuntimeEffectKind.CONFIGURATION_ACTIVITY_V1,
                   configuration_instances=selection)


def legacy_start(interpreter):
    """Accepted old path establishes old compute without depending on B2."""
    return interpreter.execute(_request(StartNode(NodeTarget("api"))))
