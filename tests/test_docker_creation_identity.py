"""I177-B1: correlate creation with the returned provider object, never its name."""
import unittest
from unittest.mock import patch

import control_plane_kit_interpreters.docker.sdk as docker_sdk
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule, FakeResource


class DockerCreationIdentityTests(unittest.TestCase):
    def fixture(self):
        raw = FakeDockerClient()
        sdk = docker_sdk.DockerSdkClient(client=raw, docker_module=FakeDockerModule(raw))
        return raw, sdk

    def create(self, sdk):
        return sdk.create_container(
            name="logical-name", image="fixture@sha256:" + "b" * 64,
            environment={}, labels={}, volumes={}, network="owned-network",
            aliases=("node",),
        )

    def test_returns_exact_created_identity_without_name_lookup_or_start(self):
        raw, sdk = self.fixture()
        create = raw.containers.create

        def created(image, **kwargs):
            resource = create(image, **kwargs)
            resource.attrs["Id"] = "a" * 64
            resource.id = "c" * 64  # A second identity representation is not authority.
            other = FakeResource(resource.name)
            other.attrs["Id"] = "d" * 64
            raw.containers.resources[resource.name] = other
            return resource

        with patch.object(raw.containers, "create", side_effect=created) as creation, patch.object(
            raw.containers, "get", wraps=raw.containers.get,
        ) as lookup:
            identity = self.create(sdk)

        self.assertEqual(identity, "a" * 64)
        creation.assert_called_once()
        lookup.assert_not_called()
        resource = raw.containers.created_containers[0]
        self.assertFalse(resource.started or resource.removed)
        self.assertEqual(len(raw.containers.created_containers), 1)

    def test_successful_create_without_canonical_identity_remains_unknown(self):
        for value in (None, "", "logical-name", "a" * 12, "A" * 64, "z" * 64, 7):
            with self.subTest(identity=value):
                raw, sdk = self.fixture()
                create = raw.containers.create

                def created(image, **kwargs):
                    resource = create(image, **kwargs)
                    if value is not None:
                        resource.attrs["Id"] = value
                    resource.id = "f" * 64
                    return resource

                with patch.object(raw.containers, "create", side_effect=created) as creation, patch.object(
                    raw.containers, "get", wraps=raw.containers.get,
                ) as lookup:
                    self.assertIsNone(self.create(sdk))

                creation.assert_called_once()
                lookup.assert_not_called()
                self.assertEqual(len(raw.containers.created_containers), 1)
                resource = raw.containers.created_containers[0]
                self.assertFalse(resource.started or resource.removed)

    def test_provider_create_exception_is_classified_and_never_retried(self):
        raw, sdk = self.fixture()
        with patch.object(raw.containers, "create", side_effect=TimeoutError("provider detail")) as creation:
            with self.assertRaises(docker_sdk._DockerContainerCreateError) as caught:
                self.create(sdk)
        creation.assert_called_once()
        self.assertIs(caught.exception.suboperation, docker_sdk._ContainerCreateSuboperation.CREATE)
        self.assertIs(caught.exception.category, docker_sdk._DockerFailureCategory.TIMEOUT)
        self.assertNotIn("provider detail", str(caught.exception))
