from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from io import BytesIO
from importlib import import_module
from ipaddress import ip_address
from pathlib import Path
import tarfile
import tempfile
from typing import Any, Mapping, Sequence
from uuid import uuid4

from control_plane_kit_core.configuration import ConfigurationArtifact
from control_plane_kit_core.probe_intents import (
    EndpointContext,
    LiteralEndpointMaterial,
    RuntimeEndpointObservation,
)
from control_plane_kit_core.secrets import SecretFileMode, SecretValue
from control_plane_kit_core.types import Protocol, Transport


@dataclass(frozen=True, repr=False)
class DockerLocalAmbientClientConfig:
    """Explicit local Docker authority material using the process Docker context."""

    def __repr__(self) -> str:
        return "DockerLocalAmbientClientConfig()"


@dataclass(frozen=True, repr=False)
class DockerTlsClientConfig:
    """Ephemeral remote Docker TLS client material with redacted representation."""

    endpoint: str
    ca_certificate: SecretValue
    client_certificate: SecretValue
    client_key: SecretValue

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str) or not self.endpoint.startswith("tcp://"):
            raise ValueError("Docker TLS endpoint must be a tcp:// URL")
        for name, value in (
            ("ca_certificate", self.ca_certificate),
            ("client_certificate", self.client_certificate),
            ("client_key", self.client_key),
        ):
            if not isinstance(value, SecretValue):
                raise TypeError(f"Docker TLS {name} must be SecretValue")

    def __repr__(self) -> str:
        return "DockerTlsClientConfig(<redacted>)"


@dataclass(frozen=True, repr=False)
class DockerRegistryAuthConfig:
    """Bounded Docker SDK auth config with redacted representation."""

    username: str | None = None
    password: SecretValue | None = None
    identitytoken: SecretValue | None = None

    def __post_init__(self) -> None:
        if self.identitytoken is not None:
            if not isinstance(self.identitytoken, SecretValue):
                raise TypeError("Docker registry identity token must be SecretValue")
            if self.username is not None or self.password is not None:
                raise ValueError(
                    "Docker registry auth config must use either identity token or username/password"
                )
            return
        if not isinstance(self.username, str) or not self.username.strip():
            raise ValueError("Docker registry auth config username must not be empty")
        if not isinstance(self.password, SecretValue):
            raise TypeError("Docker registry auth config password must be SecretValue")

    def docker_auth_config(self) -> Mapping[str, str]:
        if self.identitytoken is not None:
            return {"identitytoken": self.identitytoken.reveal()}
        assert self.username is not None
        assert self.password is not None
        return {"username": self.username, "password": self.password.reveal()}

    def __repr__(self) -> str:
        return "DockerRegistryAuthConfig(<redacted>)"


@dataclass(frozen=True)
class DockerSdkResourceInspection:
    name: str
    running: bool
    image: str | None
    labels: Mapping[str, str]
    published_ports: tuple["DockerSdkPublishedPort", ...] = ()
    private_addresses: Mapping[str, str] = field(default_factory=dict)
    image_id: str | None = None
    network_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class DockerSdkImageInspection:
    image_id: str
    repo_digests: tuple[str, ...]


@dataclass(frozen=True, order=True)
class DockerSdkPublishedPort:
    container_port: int
    transport: Transport
    host_address: str
    host_port: int

    def __post_init__(self) -> None:
        _validate_port(self.container_port, "published container")
        _validate_port(self.host_port, "published host")
        if not isinstance(self.transport, Transport):
            raise TypeError("published port transport must be Transport")
        _validate_host_address(self.host_address)


@dataclass(frozen=True, order=True)
class DockerSdkPortBinding:
    socket_name: str
    protocol: Protocol
    container_port: int
    host_address: str
    host_port: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.socket_name, str) or not self.socket_name.strip():
            raise ValueError("Docker port binding socket name must not be empty")
        if not isinstance(self.protocol, Protocol):
            raise TypeError("Docker port binding protocol must be Protocol")
        _validate_port(self.container_port, "Docker container")
        _validate_host_address(self.host_address)
        if self.host_port is not None:
            _validate_port(self.host_port, "Docker host")

    def docker_port_key(self) -> str:
        return f"{self.container_port}/{self.protocol.transport.value}"

    def docker_port_value(self) -> tuple[str, int]:
        return (self.host_address, 0 if self.host_port is None else self.host_port)


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


@dataclass(frozen=True)
class DockerSdkBindMount:
    source_path: str
    target_path: str
    read_only: bool = False

    def __post_init__(self) -> None:
        _validate_absolute_path(self.source_path, "Docker bind mount source")
        _validate_absolute_path(self.target_path, "Docker bind mount target")

    def docker_mount(self) -> Mapping[str, object]:
        return {
            "Type": "bind",
            "Source": self.source_path,
            "Target": self.target_path,
            "ReadOnly": self.read_only,
        }


@dataclass(frozen=True)
class DockerSdkHttpProbeResult:
    status_code: int | None
    response_size: int
    exit_code: int

    @property
    def timed_out(self) -> bool:
        return self.exit_code == 124


@dataclass
class DockerSdkClient:
    client: Any | None = None
    docker_module: Any | None = None
    tls_config: DockerTlsClientConfig | None = field(default=None, repr=False)
    connect_on_init: bool = field(default=True, repr=False)
    _tls_directory: tempfile.TemporaryDirectory[str] | None = field(default=None, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)
    configuration_helper_image: str = (
        "python:3.14-slim@sha256:"
        "cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6"
    )

    def __post_init__(self) -> None:
        docker_module = self.docker_module
        if docker_module is None:
            docker_module = import_module("docker")

        self.docker_module = docker_module
        if self.client is not None or not self.connect_on_init:
            return

        self.client = self._connect()

    @classmethod
    def from_authority(
        cls,
        authority: DockerLocalAmbientClientConfig | DockerTlsClientConfig,
        *,
        docker_module: Any | None = None,
        connect_on_init: bool = True,
    ) -> "DockerSdkClient":
        if isinstance(authority, DockerLocalAmbientClientConfig):
            return cls(
                docker_module=docker_module,
                connect_on_init=connect_on_init,
            )
        if isinstance(authority, DockerTlsClientConfig):
            return cls(
                docker_module=docker_module,
                tls_config=authority,
                connect_on_init=connect_on_init,
            )
        raise TypeError("Docker SDK client authority is unsupported")

    def _connect(self) -> Any:
        if self._closed:
            raise RuntimeError("Docker SDK client is closed")
        docker_module = self.docker_module
        if docker_module is None:
            docker_module = import_module("docker")
            self.docker_module = docker_module
        if self.tls_config is None:
            return docker_module.from_env()
        return self._remote_tls_client(docker_module, self.tls_config)

    def _client(self) -> Any:
        if self._closed:
            raise RuntimeError("Docker SDK client is closed")
        if self.client is None:
            self.client = self._connect()
        return self.client

    def _remote_tls_client(
        self,
        docker_module: Any,
        tls_config: DockerTlsClientConfig,
    ) -> Any:
        directory = tempfile.TemporaryDirectory(prefix="cpk-docker-tls-")
        self._tls_directory = directory
        try:
            root = Path(directory.name)
            ca_path = _write_secret_file(root / "ca.pem", tls_config.ca_certificate)
            cert_path = _write_secret_file(root / "cert.pem", tls_config.client_certificate)
            key_path = _write_secret_file(root / "key.pem", tls_config.client_key)
            tls_factory = getattr(getattr(docker_module, "tls", None), "TLSConfig", None)
            if tls_factory is None:
                raise RuntimeError("Docker SDK TLSConfig is unavailable")
            tls = tls_factory(
                ca_cert=str(ca_path),
                client_cert=(str(cert_path), str(key_path)),
                verify=True,
            )
            return docker_module.DockerClient(
                base_url=tls_config.endpoint,
                tls=tls,
            )
        except Exception:
            self._tls_directory = None
            try:
                directory.cleanup()
            except Exception:
                pass
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        client = self.client
        directory = self._tls_directory
        self.client = None
        self.tls_config = None
        self._tls_directory = None

        client_error: Exception | None = None
        close = getattr(client, "close", None)
        if callable(close):
            try:
                close()
            except Exception as error:
                client_error = error
        try:
            if directory is not None:
                directory.cleanup()
        except Exception:
            if client_error is None:
                raise
        if client_error is not None:
            raise client_error

    def __del__(self) -> None:
        if getattr(self, "_tls_directory", None) is None:
            return
        try:
            self.close()
        except Exception:
            pass

    def inspect_network(self, name: str) -> DockerSdkResourceInspection | None:
        try:
            network = self._client().networks.get(name)
        except Exception as error:
            if self._is_not_found(error):
                return None
            raise

        return self._inspection(network, running=False, image=None)

    def create_network(self, *, name: str, labels: Mapping[str, str]) -> None:
        self._client().networks.create(name=name, labels=dict(labels))

    def inspect_volume(self, name: str) -> DockerSdkResourceInspection | None:
        try:
            volume = self._client().volumes.get(name)
        except Exception as error:
            if self._is_not_found(error):
                return None
            raise

        return self._inspection(volume, running=False, image=None)

    def create_volume(self, *, name: str, labels: Mapping[str, str]) -> None:
        self._client().volumes.create(name=name, labels=dict(labels))

    def pull_image(
        self,
        image: str,
        *,
        auth_config: DockerRegistryAuthConfig | None = None,
    ) -> None:
        if auth_config is None:
            self._client().images.pull(image)
            return
        self._client().images.pull(
            image,
            auth_config=dict(auth_config.docker_auth_config()),
        )

    def inspect_image(self, image: str) -> DockerSdkImageInspection | None:
        try:
            observed = self._client().images.get(image)
        except Exception as error:
            if self._is_not_found(error):
                return None
            raise

        image_id = getattr(observed, "id", None)
        attrs = getattr(observed, "attrs", {})
        repo_digests = attrs.get("RepoDigests", ()) if isinstance(attrs, Mapping) else ()
        if not isinstance(image_id, str) or not image_id.strip():
            raise RuntimeError("Docker image inspection was malformed")
        if repo_digests is None:
            repo_digests = ()
        if not isinstance(repo_digests, Sequence) or isinstance(repo_digests, (str, bytes)):
            raise RuntimeError("Docker image inspection was malformed")
        if not all(isinstance(value, str) and value.strip() for value in repo_digests):
            raise RuntimeError("Docker image inspection was malformed")
        return DockerSdkImageInspection(
            image_id=image_id,
            repo_digests=tuple(sorted(repo_digests)),
        )

    def inspect_container(self, name: str) -> DockerSdkResourceInspection | None:
        try:
            container = self._client().containers.get(name)
        except Exception as error:
            if self._is_not_found(error):
                return None
            raise

        return self._inspection(
            container,
            running=self._container_running(container),
            image=self._image_name(container),
            include_runtime_identity=True,
        )

    def create_container(
        self,
        *,
        name: str,
        image: str,
        environment: Mapping[str, str],
        labels: Mapping[str, str],
        volumes: Mapping[str, str],
        command: Sequence[str] = (),
        configuration_mounts: Sequence[DockerSdkConfigurationMount] = (),
        secret_mounts: Sequence[DockerSdkSecretMount] = (),
        bind_mounts: Sequence[DockerSdkBindMount] = (),
        supplementary_groups: Sequence[str] = (),
        port_bindings: Sequence[DockerSdkPortBinding] = (),
        network: str,
        aliases: Sequence[str],
    ) -> None:
        kwargs = self._container_create_kwargs(
            name=name,
            environment=environment,
            labels=labels,
            volumes=volumes,
            command=command,
            configuration_mounts=configuration_mounts,
            secret_mounts=secret_mounts,
            bind_mounts=bind_mounts,
            supplementary_groups=supplementary_groups,
            port_bindings=port_bindings,
        )
        endpoint_config = self._client().api.create_endpoint_config(
            aliases=list(aliases),
        )
        kwargs["network"] = network
        kwargs["networking_config"] = {network: endpoint_config}
        self._client().containers.create(image, **kwargs)

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
        bind_mounts: Sequence[DockerSdkBindMount] = (),
        supplementary_groups: Sequence[str] = (),
        port_bindings: Sequence[DockerSdkPortBinding] = (),
    ) -> None:
        kwargs = self._container_create_kwargs(
            name=name,
            environment=environment,
            labels=labels,
            volumes=volumes,
            command=command,
            configuration_mounts=configuration_mounts,
            secret_mounts=secret_mounts,
            bind_mounts=bind_mounts,
            supplementary_groups=supplementary_groups,
            port_bindings=port_bindings,
        )
        container = self._client().containers.create(image, **kwargs)
        self._client().networks.get(network).connect(container, aliases=list(aliases))
        container.start()

    def _container_create_kwargs(
        self,
        *,
        name: str,
        environment: Mapping[str, str],
        labels: Mapping[str, str],
        volumes: Mapping[str, str],
        command: Sequence[str],
        configuration_mounts: Sequence[DockerSdkConfigurationMount],
        secret_mounts: Sequence[DockerSdkSecretMount],
        bind_mounts: Sequence[DockerSdkBindMount],
        supplementary_groups: Sequence[str],
        port_bindings: Sequence[DockerSdkPortBinding],
    ) -> dict[str, object]:
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
            ]
            + [
                dict(mount.docker_mount())
                for mount in sorted(
                    bind_mounts,
                    key=lambda value: (value.target_path, value.source_path),
                )
            ],
            "ports": {
                binding.docker_port_key(): binding.docker_port_value()
                for binding in sorted(port_bindings)
            },
        }
        if command:
            kwargs["command"] = list(command)
        if supplementary_groups:
            kwargs["group_add"] = list(supplementary_groups)
        return kwargs

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
        self._client().containers.get(name).start()

    def stop_container(self, name: str) -> None:
        self._client().containers.get(name).stop()

    def remove_container(self, name: str) -> None:
        self._client().containers.get(name).remove(force=True)

    def remove_network(self, name: str) -> None:
        self._client().networks.get(name).remove()

    def remove_volume(self, name: str) -> None:
        self._client().volumes.get(name).remove()

    def run_http_probe(
        self,
        *,
        network: str,
        url: str,
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> DockerSdkHttpProbeResult:
        if not isinstance(network, str) or not network.strip():
            raise ValueError("HTTP probe network must not be empty")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError("HTTP probe URL must be absolute")
        timeout = max(1, min(int(timeout_seconds), 30))
        maximum_bytes = max(0, min(int(maximum_response_bytes), 65536))
        script = (
            "import sys,urllib.request\n"
            "url=sys.argv[1]\n"
            "limit=int(sys.argv[2])\n"
            "timeout=float(sys.argv[3])\n"
            "try:\n"
            "    with urllib.request.urlopen(url, timeout=timeout) as response:\n"
            "        data=response.read(limit + 1)\n"
            "        print(f'{response.status} {len(data)}')\n"
            "except TimeoutError:\n"
            "    sys.exit(124)\n"
            "except Exception:\n"
            "    sys.exit(1)\n"
        )
        helper = self._client().containers.create(
            self.configuration_helper_image,
            command=["python", "-c", script, url, str(maximum_bytes), str(timeout)],
            detach=True,
            name=f"cpk-http-probe-{uuid4().hex}",
            network=network,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
        )
        try:
            helper.start()
            wait_result = helper.wait(timeout=timeout + 2)
            exit_code = _wait_status_code(wait_result)
            output = _container_logs(helper, maximum_bytes=128).strip()
        finally:
            helper.remove(force=True)
        status_code = None
        response_size = 0
        if exit_code == 0 and output:
            parts = output.split(maxsplit=1)
            try:
                status_code = int(parts[0])
                response_size = int(parts[1]) if len(parts) > 1 else 0
            except ValueError:
                exit_code = 1
        return DockerSdkHttpProbeResult(status_code, response_size, exit_code)

    def _create_configuration_helper(
        self,
        volume_name: str,
        *,
        readonly: bool,
    ) -> Any:
        return self._client().containers.create(
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
        include_runtime_identity: bool = False,
    ) -> DockerSdkResourceInspection:
        return DockerSdkResourceInspection(
            name=str(getattr(resource, "name", "")),
            running=running,
            image=image,
            labels=self._labels(resource),
            published_ports=self._published_ports(resource),
            private_addresses=self._private_addresses(resource),
            image_id=self._image_id(resource) if include_runtime_identity else None,
            network_names=(
                self._network_names(resource) if include_runtime_identity else ()
            ),
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

    def _image_id(self, container: Any) -> str | None:
        image = getattr(container, "image", None)
        image_id = getattr(image, "id", None)
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            raise RuntimeError("Docker container image inspection was malformed")
        digest = image_id.removeprefix("sha256:")
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise RuntimeError("Docker container image inspection was malformed")
        return image_id

    def _network_names(self, container: Any) -> tuple[str, ...]:
        attrs = getattr(container, "attrs", {})
        settings = attrs.get("NetworkSettings", {}) if isinstance(attrs, Mapping) else {}
        networks = settings.get("Networks", {}) if isinstance(settings, Mapping) else {}
        if not isinstance(networks, Mapping):
            raise RuntimeError("Docker network membership inspection was malformed")
        if not all(isinstance(name, str) and name.strip() for name in networks):
            raise RuntimeError("Docker network membership inspection was malformed")
        return tuple(sorted(networks))

    def _published_ports(self, container: Any) -> tuple[DockerSdkPublishedPort, ...]:
        attrs = getattr(container, "attrs", {})
        settings = attrs.get("NetworkSettings", {}) if isinstance(attrs, Mapping) else {}
        ports = settings.get("Ports", {}) if isinstance(settings, Mapping) else {}
        if ports is None:
            return ()
        if not isinstance(ports, Mapping):
            raise RuntimeError("Docker published port inspection was malformed")
        values: list[DockerSdkPublishedPort] = []
        for key, bindings in ports.items():
            if not isinstance(key, str) or "/" not in key:
                raise RuntimeError("Docker published port inspection was malformed")
            port_value, transport_value = key.rsplit("/", 1)
            try:
                container_port = int(port_value)
                transport = Transport(transport_value)
            except ValueError as error:
                raise RuntimeError(
                    "Docker published port inspection was malformed"
                ) from error
            if bindings is None:
                continue
            if not isinstance(bindings, Sequence) or isinstance(bindings, (str, bytes)):
                raise RuntimeError("Docker published port inspection was malformed")
            for binding in bindings:
                if not isinstance(binding, Mapping):
                    raise RuntimeError("Docker published port inspection was malformed")
                host_address = binding.get("HostIp")
                host_port = binding.get("HostPort")
                if not isinstance(host_address, str) or not isinstance(host_port, str):
                    raise RuntimeError("Docker published port inspection was malformed")
                try:
                    values.append(
                        DockerSdkPublishedPort(
                            container_port,
                            transport,
                            host_address,
                            int(host_port),
                        )
                    )
                except ValueError as error:
                    raise RuntimeError(
                        "Docker published port inspection was malformed"
                    ) from error
        return tuple(sorted(values))

    def _private_addresses(self, container: Any) -> Mapping[str, str]:
        attrs = getattr(container, "attrs", {})
        settings = attrs.get("NetworkSettings", {}) if isinstance(attrs, Mapping) else {}
        networks = settings.get("Networks", {}) if isinstance(settings, Mapping) else {}
        if not isinstance(networks, Mapping):
            raise RuntimeError("Docker private address inspection was malformed")
        values: dict[str, str] = {}
        for name, details in networks.items():
            if not isinstance(name, str) or not isinstance(details, Mapping):
                raise RuntimeError("Docker private address inspection was malformed")
            address = details.get("IPAddress")
            if not isinstance(address, str) or not address:
                continue
            try:
                ip_address(address)
            except ValueError as error:
                raise RuntimeError(
                    "Docker private address inspection was malformed"
                ) from error
            values[name] = address
        return dict(sorted(values.items()))


def _write_secret_file(path: Path, value: SecretValue) -> Path:
    path.write_text(value.reveal(), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def runtime_endpoint_observations(
    *,
    subject_id: str,
    graph_id: str,
    private_host: str,
    provider_ports: Sequence[DockerSdkPortBinding],
    published_ports: Sequence[DockerSdkPublishedPort] = (),
) -> tuple[RuntimeEndpointObservation, ...]:
    observations: list[RuntimeEndpointObservation] = []
    for binding in sorted(provider_ports):
        observations.append(
            RuntimeEndpointObservation(
                subject_id,
                binding.socket_name,
                graph_id,
                binding.protocol,
                EndpointContext.RUNTIME_PRIVATE,
                LiteralEndpointMaterial(
                    _endpoint_url(
                        binding.protocol,
                        private_host,
                        binding.container_port,
                    )
                ),
            )
        )
        for published in sorted(published_ports):
            if (
                published.container_port == binding.container_port
                and published.transport is binding.protocol.transport
            ):
                observations.append(
                    RuntimeEndpointObservation(
                        subject_id,
                        binding.socket_name,
                        graph_id,
                        binding.protocol,
                        _host_endpoint_context(published.host_address),
                        LiteralEndpointMaterial(
                            _endpoint_url(
                                binding.protocol,
                                published.host_address,
                                published.host_port,
                            )
                        ),
                    )
                )
    return tuple(observations)


def verify_published_ports(
    requested: Sequence[DockerSdkPortBinding],
    published: Sequence[DockerSdkPublishedPort],
) -> tuple[DockerSdkPublishedPort, ...]:
    verified: list[DockerSdkPublishedPort] = []
    for binding in sorted(requested):
        matches = tuple(
            value
            for value in sorted(published)
            if value.container_port == binding.container_port
            and value.transport is binding.protocol.transport
            and value.host_address == binding.host_address
            and (
                binding.host_port is None
                or value.host_port == binding.host_port
            )
        )
        if not matches:
            raise RuntimeError(
                "Docker host publication postcondition was not observed"
            )
        verified.extend(matches)
    return tuple(verified)


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


def _endpoint_url(protocol: Protocol, host: str, port: int) -> str:
    scheme = sorted(protocol.endpoint_schemes())[0]
    return f"{scheme}://{_url_host(host)}:{port}"


def _url_host(host: str) -> str:
    try:
        parsed = ip_address(host)
    except ValueError:
        return host
    return f"[{host}]" if parsed.version == 6 else host


def _host_endpoint_context(host: str) -> EndpointContext:
    parsed = ip_address(host)
    return EndpointContext.PUBLIC if parsed.is_global else EndpointContext.HOST_LOCAL


def _validate_host_address(value: str) -> None:
    if not isinstance(value, str):
        raise TypeError("Docker host address must be text")
    try:
        ip_address(value)
    except ValueError as error:
        raise ValueError("Docker host address must be an IP address") from error


def _validate_absolute_path(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValueError(f"{label} must be an absolute path")
    if "://" in value:
        raise ValueError(f"{label} must not be a URL")


def _validate_port(value: int, label: str) -> None:
    if type(value) is not int or value < 1 or value > 65_535:
        raise ValueError(f"{label} port must be between 1 and 65535")


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


def _wait_status_code(result: Any) -> int:
    if isinstance(result, Mapping):
        status = result.get("StatusCode")
        if isinstance(status, int):
            return status
    if isinstance(result, int):
        return result
    raise RuntimeError("Docker wait result was malformed")


def _container_logs(container: Any, *, maximum_bytes: int) -> str:
    logs = container.logs(stdout=True, stderr=False, tail=1)
    if isinstance(logs, bytes):
        return logs[:maximum_bytes].decode("utf-8", errors="replace")
    if isinstance(logs, str):
        return logs[:maximum_bytes]
    raise RuntimeError("Docker logs result was malformed")
