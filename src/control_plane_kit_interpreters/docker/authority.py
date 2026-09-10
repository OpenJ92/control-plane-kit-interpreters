"""Resource conformance, not authority admission or physical-host attestation.

The Desktop rule is a provisional empirical compatibility contract. Callers must
already validate node delivery/admission and bind the appropriate provider client.
Raw SDK observations are never rewritten. A successful decision grants no powers.
"""

from enum import Enum

from .sdk import (
    DockerAuthorityProviderFacts,
    DockerSdkBindMount,
    DockerSdkClient,
    DockerSdkConfiguredBindMount,
    DockerSdkResourceInspection,
)


class DockerAuthorityConformance(Enum):
    CONFORMANT = "conformant"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


_SOCKET = "/var/run/docker.sock"
_CANONICAL = (DockerSdkBindMount(_SOCKET, _SOCKET, False),)
_DESKTOP_PROXY = "/run/host-services/docker.proxy.sock"
_DESKTOP_OBSERVED = (DockerSdkBindMount(_DESKTOP_PROXY, _SOCKET, False),)
_DESKTOP_PROVIDER = DockerAuthorityProviderFacts("Docker Desktop", "linux", "29.7.2", "1.55")


def docker_authority_conformance(
    inspection: DockerSdkResourceInspection,
    *,
    expected_mounts: tuple[DockerSdkBindMount, ...],
    expected_groups: tuple[str, ...],
    client: DockerSdkClient,
) -> DockerAuthorityConformance:
    """Compare exact facts, consulting Desktop metadata only for its fixed case.

    The Desktop relation requires canonical requested source, fixed proxy
    configured source and the same fixed proxy actual source. It does not retain
    the unqualified configured-canonical/actual-proxy permutation.
    Configured ReadOnly omission is interpreted as false only for the qualified
    API1.55 tuple. Explicit null stays unknown in the SDK projection. Actual RW
    never comes from configured intent. No facts survive between evaluations.
    """
    mounts = getattr(inspection, "bind_mounts", None)
    groups = getattr(inspection, "supplementary_groups", None)
    if type(mounts) is not tuple or type(groups) is not tuple:
        return DockerAuthorityConformance.UNKNOWN
    if mounts == expected_mounts and groups == expected_groups:
        return DockerAuthorityConformance.CONFORMANT
    if groups != expected_groups or expected_mounts != _CANONICAL or mounts != _DESKTOP_OBSERVED:
        return DockerAuthorityConformance.CONFLICT

    configured = getattr(inspection, "configured_bind_mounts", None)
    if type(configured) is not tuple:
        return DockerAuthorityConformance.UNKNOWN
    if len(configured) != 1:
        return DockerAuthorityConformance.CONFLICT
    mount = configured[0]
    if not isinstance(mount, DockerSdkConfiguredBindMount):
        return DockerAuthorityConformance.UNKNOWN
    if (mount.source_path != _DESKTOP_PROXY or mount.target_path != _SOCKET
            or not (mount.read_only is False or mount.read_only is None)):
        return DockerAuthorityConformance.CONFLICT
    try:
        if not client.uses_local_socket(_SOCKET):
            return DockerAuthorityConformance.CONFLICT
        facts = client.inspect_authority_provider_facts()
    except Exception:
        return DockerAuthorityConformance.UNKNOWN
    if not isinstance(facts, DockerAuthorityProviderFacts):
        return DockerAuthorityConformance.UNKNOWN
    return (DockerAuthorityConformance.CONFORMANT if facts == _DESKTOP_PROVIDER
            else DockerAuthorityConformance.CONFLICT)
