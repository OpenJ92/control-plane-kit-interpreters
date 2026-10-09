"""Provider-only cleanup fixtures; Core owns request and outcome semantics."""
from dataclasses import replace
from types import SimpleNamespace

from docker.errors import APIError
from control_plane_kit_core.planning import CleanupConfigurationInstances
from control_plane_kit_interpreters.docker.configuration import configuration_volume_name, configuration_volume_labels
from configuration_replacement_fixtures import fixture, selected_request
from test_docker_sdk_client import FakeNotFound


def cleanup_request(count=1):
    selected = selected_request(count=count)
    return replace(selected, operation=CleanupConfigurationInstances(selected.configuration_instances.instances),
        products=(), configuration_instances=None)


def cleanup_fixture(count=1):
    raw, sdk, interpreter, events = fixture()
    sdk.docker_module.errors = SimpleNamespace(NotFound=FakeNotFound, APIError=APIError)
    request = cleanup_request(count)
    holders = []

    def containers(**kwargs):
        events.append(("use-query", kwargs))
        name = kwargs["filters"]["volume"]
        return [row for row in holders if any(mount.get("Name") == name
            for mount in row["Mounts"])][:kwargs["limit"]]

    raw.api.containers = containers
    resources = []
    for reference in request.operation.instances:
        name = configuration_volume_name(reference)
        labels = configuration_volume_labels(reference)
        resource = raw.volumes.create(name=name, labels=labels)
        resource.attrs = {"Name": name, "Labels": labels, "Driver": "local", "Scope": "local",
            "Options": None, "CreatedAt": "2026-10-09T00:00:00Z"}

        def remove(*, force=False, name=name):
            events.append(("remove-volume", name, force))
            del raw.volumes.resources[name]

        resource.remove = remove
        resources.append(resource)
    return raw, sdk, interpreter, request, resources, holders, events


def holder(name, state="running"):
    return {"Id": "a" * 64, "State": state,
        "Mounts": [{"Type": "volume", "Name": name, "Destination": "/selected"}]}


def conflict():
    return APIError("private provider detail", response=SimpleNamespace(status_code=409))
