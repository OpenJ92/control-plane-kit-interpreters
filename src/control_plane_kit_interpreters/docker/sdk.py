from __future__ import annotations

from dataclasses import dataclass
import hashlib
from io import BytesIO
from importlib import import_module
import tarfile
from typing import Any, Mapping, Sequence
from uuid import uuid4

from control_plane_kit_core.configuration import ConfigurationArtifact
from control_plane_kit_core.secrets import SecretFileMode, SecretValue


@dataclass(frozen=True)
class DockerSdkResourceInspection:
    name: str
    running: bool
    image: str | None
    labels: Mapping[str, str]


@dataclass(frozen=True)
class DockerSdkConfigurationMount:
    artifact: ConfigurationArtifact
    volume_name: str

    def docker_mount(self) -> Mapping[str, object]:
        return {
            "Type": "volume",
            "Source": self.volume_name,
            "Target": self.artifact.target_path,
            "ReadOnly": True,
            "VolumeOptions": {"Subpath": "content"},
        }


@dataclass(frozen=True)
class DockerSdkSecretMount:
    target_path: str
    volume_name: str

    def docker_mount(self) -> Mapping[str, object]:
        return {
            "Type": "volume",
            "Source": self.volume_name,
            "Target": self.target_path,
            "ReadOnly": True,
            "VolumeOptions": {"Subpath": "content"},
        }


@dataclass
class DockerSdkClient:
    client: Any | None = None
    docker_module: Any | None = None
    configuration_helper_image: str = (
        "python:3.14-slim@sha256:"
        "cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6"
    )

    def __post_init__(self) -> None:
        if self.client is not None:
            return

        docker_module = self.docker_module
        if docker_module is None:
            docker_module = import_module("docker")

        self.docker_module = docker_module
        self.client = docker_module.from_env()

    def inspect_network(self, name: str) -> DockerSdkResourceInspection | None:
        try:
            network = self.client.networks.get(name)
        except Exception as error:
            if self._is_not_found(error):
                return None
            raise

        return self._inspection(network, running=False, image=None)

    def create_network(self, *, name: str, labels: Mapping[str, str]) -> None:
        self.client.networks.create(name=name, labels=dict(labels))

    def inspect_volume(self, name: str) -> DockerSdkResourceInspection | None:
        try:
            volume = self.client.volumes.get(name)
        except Exception as error:
            if self._is_not_found(error):
                return None
            raise

        return self._inspection(volume, running=False, image=None)

    def create_volume(self, *, name: str, labels: Mapping[str, str]) -> None:
        self.client.volumes.create(name=name, labels=dict(labels))

    def pull_image(self, image: str) -> None:
        self.client.images.pull(image)

    def inspect_container(self, name: str) -> DockerSdkResourceInspection | None:
        try:
            container = self.client.containers.get(name)
        except Exception as error:
            if self._is_not_found(error):
                return None
            raise

        return self._inspection(
            container,
            running=self._container_running(container),
            image=self._image_name(container),
        )

    def run_container(
        self,
        *,
        name: str,
        image: str,
        network: str,
        aliases: Sequence[str],
        environment: Mapping[str, str],
        labels: Mapping[str, str],
        volumes: Mapping[str, str],
        command: Sequence[str] = (),
        configuration_mounts: Sequence[DockerSdkConfigurationMount] = (),
        secret_mounts: Sequence[DockerSdkSecretMount] = (),
    ) -> None:
        mounts = {
            volume_name: {"bind": target_path, "mode": "rw"}
            for volume_name, target_path in volumes.items()
        }
        kwargs: dict[str, object] = {
            "detach": True,
            "name": name,
            "environment": dict(environment),
            "labels": dict(labels),
            "volumes": mounts,
            "mounts": [
                dict(mount.docker_mount())
                for mount in sorted(
                    configuration_mounts,
                    key=lambda value: value.artifact.artifact_id,
                )
            ]
            + [
                dict(mount.docker_mount())
                for mount in sorted(
                    secret_mounts,
                    key=lambda value: value.target_path,
                )
            ],
        }
        if command:
            kwargs["command"] = list(command)
        container = self.client.containers.create(image, **kwargs)
        self.client.networks.get(network).connect(container, aliases=list(aliases))
        container.start()

    def materialize_configuration_artifact(
        self,
        volume_name: str,
        artifact: ConfigurationArtifact,
    ) -> None:
        if not isinstance(artifact, ConfigurationArtifact):
            raise TypeError("configuration materialization requires an artifact")
        helper = self._create_configuration_helper(
            volume_name,
            readonly=False,
        )
        try:
            helper.start()
            helper.put_archive(
                "/artifact",
                _artifact_archive(artifact),
            )
            result = helper.exec_run(
                ["chmod", artifact.file_mode.value, "/artifact/content"]
            )
            exit_code = _exit_code(result)
            if exit_code != 0:
                raise RuntimeError("configuration helper chmod failed")
        finally:
            helper.remove(force=True)

    def configuration_artifact_digest(self, volume_name: str) -> str | None:
        helper = self._create_configuration_helper(
            volume_name,
            readonly=True,
        )
        try:
            helper.start()
            try:
                archive, _metadata = helper.get_archive("/artifact/content")
            except Exception as error:
                if self._is_not_found(error):
                    return None
                raise
            digest = _content_digest(archive)
        finally:
            helper.remove(force=True)
        return digest

    def materialize_secret_file(
        self,
        volume_name: str,
        value: SecretValue,
        file_mode: SecretFileMode,
    ) -> None:
        if not isinstance(value, SecretValue):
            raise TypeError("secret file materialization requires SecretValue")
        if not isinstance(file_mode, SecretFileMode):
            raise TypeError("secret file materialization requires SecretFileMode")
        helper = self._create_configuration_helper(
            volume_name,
            readonly=False,
        )
        try:
            helper.start()
            helper.put_archive(
                "/artifact",
                _secret_archive(value, file_mode),
            )
            result = helper.exec_run(
                ["chmod", file_mode.value, "/artifact/content"]
            )
            exit_code = _exit_code(result)
            if exit_code != 0:
                raise RuntimeError("secret helper chmod failed")
        finally:
            helper.remove(force=True)

    def secret_file_digest(self, volume_name: str) -> str | None:
        return self.configuration_artifact_digest(volume_name)

    def start_container(self, name: str) -> None:
        self.client.containers.get(name).start()

    def stop_container(self, name: str) -> None:
        self.client.containers.get(name).stop()

    def remove_container(self, name: str) -> None:
        self.client.containers.get(name).remove(force=True)

    def remove_network(self, name: str) -> None:
        self.client.networks.get(name).remove()

    def remove_volume(self, name: str) -> None:
        self.client.volumes.get(name).remove()

    def _create_configuration_helper(
        self,
        volume_name: str,
        *,
        readonly: bool,
    ) -> Any:
        return self.client.containers.create(
            self.configuration_helper_image,
            command=["sleep", "30"],
            detach=True,
            name=f"cpk-config-{uuid4().hex}",
            network_disabled=True,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            volumes={
                volume_name: {
                    "bind": "/artifact",
                    "mode": "ro" if readonly else "rw",
                }
            },
        )

    def _is_not_found(self, error: Exception) -> bool:
        docker_module = self.docker_module
        if docker_module is None:
            return False

        not_found = getattr(getattr(docker_module, "errors", None), "NotFound", None)
        return not_found is not None and isinstance(error, not_found)

    def _inspection(
        self,
        resource: Any,
        *,
        running: bool,
        image: str | None,
    ) -> DockerSdkResourceInspection:
        return DockerSdkResourceInspection(
            name=str(getattr(resource, "name", "")),
            running=running,
            image=image,
            labels=self._labels(resource),
        )

    def _labels(self, resource: Any) -> Mapping[str, str]:
        attrs = getattr(resource, "attrs", {})
        config = attrs.get("Config", {}) if isinstance(attrs, Mapping) else {}
        labels = attrs.get("Labels", {}) if isinstance(attrs, Mapping) else {}
        if not labels and isinstance(config, Mapping):
            labels = config.get("Labels", {})
        if not isinstance(labels, Mapping):
            return {}
        return {str(key): str(value) for key, value in labels.items()}

    def _container_running(self, container: Any) -> bool:
        attrs = getattr(container, "attrs", {})
        state = attrs.get("State", {}) if isinstance(attrs, Mapping) else {}
        if isinstance(state, Mapping) and isinstance(state.get("Running"), bool):
            return state["Running"]
        return getattr(container, "status", None) == "running"

    def _image_name(self, container: Any) -> str | None:
        image = getattr(container, "image", None)
        tags = getattr(image, "tags", None)
        if isinstance(tags, Sequence) and not isinstance(tags, str) and tags:
            return str(tags[0])
        short_id = getattr(image, "short_id", None)
        if short_id is not None:
            return str(short_id)
        return None


def _artifact_archive(artifact: ConfigurationArtifact) -> bytes:
    encoded = artifact.content.encode("utf-8")
    info = tarfile.TarInfo("content")
    info.size = len(encoded)
    info.mode = int(artifact.file_mode.value, 8)
    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        tar.addfile(info, BytesIO(encoded))
    return archive.getvalue()


def _secret_archive(value: SecretValue, file_mode: SecretFileMode) -> bytes:
    encoded = value.reveal().encode("utf-8")
    info = tarfile.TarInfo("content")
    info.size = len(encoded)
    info.mode = int(file_mode.value, 8)
    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        tar.addfile(info, BytesIO(encoded))
    return archive.getvalue()


def _content_digest(archive_chunks: Any) -> str:
    archive = BytesIO(b"".join(archive_chunks))
    with tarfile.open(fileobj=archive, mode="r") as tar:
        member = tar.extractfile("content")
        if member is None:
            raise RuntimeError("configuration digest archive has no content file")
        return hashlib.sha256(member.read()).hexdigest()


def _exit_code(result: Any) -> int:
    if isinstance(result, tuple) and result:
        return int(result[0])
    value = getattr(result, "exit_code", None)
    if value is None:
        raise RuntimeError("configuration helper returned malformed exec result")
    return int(value)
