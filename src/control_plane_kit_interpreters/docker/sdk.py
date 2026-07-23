from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class DockerSdkResourceInspection:
    name: str
    running: bool
    image: str | None
    labels: Mapping[str, str]


@dataclass
class DockerSdkClient:
    client: Any | None = None
    docker_module: Any | None = None

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
    ) -> None:
        mounts = {
            volume_name: {"bind": target_path, "mode": "rw"}
            for volume_name, target_path in volumes.items()
        }
        self.client.containers.run(
            image,
            detach=True,
            name=name,
            network=network,
            network_aliases=list(aliases),
            environment=dict(environment),
            labels=dict(labels),
            volumes=mounts,
        )

    def start_container(self, name: str) -> None:
        self.client.containers.get(name).start()

    def stop_container(self, name: str) -> None:
        self.client.containers.get(name).stop()

    def remove_container(self, name: str) -> None:
        self.client.containers.get(name).remove(force=True)

    def remove_network(self, name: str) -> None:
        self.client.networks.get(name).remove()

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
