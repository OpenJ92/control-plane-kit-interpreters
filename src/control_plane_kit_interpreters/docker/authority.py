"""Resource conformance, not authority admission or physical-host attestation.

The Desktop rule is a provisional empirical compatibility contract. Callers must
already validate node delivery/admission and bind the appropriate provider client.
Raw SDK observations are never rewritten. A successful decision grants no powers.
"""

from collections.abc import Callable
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
_DESKTOP_PROVIDERS = (
    DockerAuthorityProviderFacts("Docker Desktop", "linux", "29.7.2", "1.55"),
    DockerAuthorityProviderFacts("Docker Desktop", "linux", "29.9.3", "1.56"),
)


def docker_authority_conformance(
    inspection: DockerSdkResourceInspection,
    *,
    expected_mounts: tuple[DockerSdkBindMount, ...],
    expected_groups: tuple[str, ...],
    client: DockerSdkClient,
    observe: Callable[[dict[str, object]], None] | None = None,
) -> DockerAuthorityConformance:
    """Compare exact facts, consulting Desktop metadata only for its fixed case.

    The Desktop relation requires canonical requested source, fixed proxy
    configured source and the same fixed proxy actual source. It does not retain
    the unqualified configured-canonical/actual-proxy permutation.
    Configured ReadOnly omission is interpreted as false only for the qualified
    provider/API tuples. Explicit null stays unknown in the SDK projection. Actual RW
    never comes from configured intent. No facts survive between evaluations.

    Optional observation reports only comparisons and reads consumed by this
    invocation. Ordinary sink failures cannot alter conformance; callers needing
    retained evidence must separately require successful capture and persistence.
    """
    group_state = transport_state = provider_state = "not-consulted"
    facts = None

    def finish(result: DockerAuthorityConformance) -> DockerAuthorityConformance:
        if observe is not None:
            try:
                provider = {"state": provider_state, "facts": None}
                if provider_state == "known":
                    values = {key: getattr(facts, key) for key in (
                        "operating_system", "os_type", "engine_version", "api_version")}
                    if all(type(value) is str and 0 < len(value) <= 128 for value in values.values()):
                        provider["facts"] = values
                    else:
                        provider["state"] = "unknown"
                observe({"schema": "cpk.docker.authority-decision.v1", "groups": group_state,
                         "local_transport": transport_state, "provider": provider,
                         "disposition": result.value})
            except Exception:
                # Diagnostics neither grant authority nor expose arbitrary errors.
                pass
        return result

    mounts = getattr(inspection, "bind_mounts", None)
    groups = getattr(inspection, "supplementary_groups", None)
    if type(mounts) is not tuple:
        return finish(DockerAuthorityConformance.UNKNOWN)
    if type(groups) is not tuple:
        group_state = "unknown"
        return finish(DockerAuthorityConformance.UNKNOWN)
    mounts_match = mounts == expected_mounts
    groups_match = groups == expected_groups
    group_state = "match" if groups_match else "mismatch"
    if mounts_match and groups_match:
        return finish(DockerAuthorityConformance.CONFORMANT)
    if not groups_match or expected_mounts != _CANONICAL or mounts != _DESKTOP_OBSERVED:
        return finish(DockerAuthorityConformance.CONFLICT)

    configured = getattr(inspection, "configured_bind_mounts", None)
    if type(configured) is not tuple:
        return finish(DockerAuthorityConformance.UNKNOWN)
    if len(configured) != 1:
        return finish(DockerAuthorityConformance.CONFLICT)
    mount = configured[0]
    if not isinstance(mount, DockerSdkConfiguredBindMount):
        return finish(DockerAuthorityConformance.UNKNOWN)
    if (mount.source_path != _DESKTOP_PROXY or mount.target_path != _SOCKET
            or not (mount.read_only is False or mount.read_only is None)):
        return finish(DockerAuthorityConformance.CONFLICT)
    try:
        transport_state = "unknown"
        if not client.uses_local_socket(_SOCKET):
            transport_state = "mismatch"
            return finish(DockerAuthorityConformance.CONFLICT)
        transport_state = "match"
        provider_state = "unknown"
        facts = client.inspect_authority_provider_facts()
    except Exception:
        return finish(DockerAuthorityConformance.UNKNOWN)
    if not isinstance(facts, DockerAuthorityProviderFacts):
        return finish(DockerAuthorityConformance.UNKNOWN)
    provider_state = "known"
    return finish(DockerAuthorityConformance.CONFORMANT if facts in _DESKTOP_PROVIDERS
                  else DockerAuthorityConformance.CONFLICT)
