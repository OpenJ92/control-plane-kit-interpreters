"""Exact provider cleanup; Core and Operations retain lifecycle ownership."""
from control_plane_kit_core.configuration_instances import (
    ConfigurationCleanupOutcome, ConfigurationCleanupOutcomeSet,
    ConfigurationCleanupReason as Reason, ConfigurationCleanupStatus as Status,
)
from control_plane_kit_core.runtime_effects import configuration_cleanup_result
from control_plane_kit_interpreters.docker.configuration import (
    ConfigurationMaterialConflict, configuration_volume_name, require_configuration_owner,
)
from control_plane_kit_interpreters.docker.sdk import DockerSdkConfigurationVolumeInUse


def refused_cleanup_authority(request):
    return configuration_cleanup_result(request, ConfigurationCleanupOutcomeSet(tuple(
        ConfigurationCleanupOutcome(ref, Status.REFUSED, Reason.AUTHORITY_REFUSED)
        for ref in request.operation.instances)))


def cleanup_configuration(client, request):
    rows = []
    unknown = False
    for reference in request.operation.instances:
        if unknown:
            status, reason = Status.UNKNOWN, Reason.NOT_ATTEMPTED
        else:
            try:
                status, reason = _cleanup_one(client, reference)
            except Exception:
                # Preserve earlier facts, stop later destructive calls and
                # never leak provider payloads or retry an ambiguous delete.
                status, reason = Status.UNKNOWN, Reason.PROVIDER_UNCERTAIN
            unknown = status is Status.UNKNOWN
        rows.append(ConfigurationCleanupOutcome(reference, status, reason))
    return configuration_cleanup_result(request, ConfigurationCleanupOutcomeSet(tuple(rows)))


def _cleanup_one(client, reference):
    name = configuration_volume_name(reference)
    observed = client.inspect_configuration_volume(name)
    if observed is None:
        return Status.ALREADY_ABSENT, None
    try:
        require_configuration_owner(observed, reference)
    except ConfigurationMaterialConflict:
        return Status.REFUSED, Reason.OWNERSHIP_MISMATCH
    if not observed.local_storage:
        return Status.REFUSED, Reason.PROVENANCE_UNPROVEN
    if client.configuration_volume_in_use(name):
        return Status.RETAINED_IN_USE, Reason.IN_USE
    try:
        # SDK rechecks the same name/incarnation snapshot immediately before
        # the non-forced call. Docker volumes do not have an immutable ID.
        client.remove_configuration_volume(observed)
    except DockerSdkConfigurationVolumeInUse:
        return Status.RETAINED_IN_USE, Reason.IN_USE
    if client.inspect_configuration_volume(name) is not None:
        return Status.UNKNOWN, Reason.PROVIDER_UNCERTAIN
    return Status.REMOVED, None
