"""Private bounded recipient-route evidence; never SQL or execution authority."""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace
import math
from urllib.parse import urlsplit

from control_plane_kit_core.receiver_management_routes import ReceiverManagementRouteBinding
from .sdk import DockerSdkResourceInspection


class PostgresRecipientUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("PostgreSQL recipient route is unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class PostgresRecipientRouteSnapshot:
    network_id: str
    gateway_id: str
    recipient_id: str
    route: ReceiverManagementRouteBinding
    members: tuple


def observe_postgres_recipient_route(client, *, network_name, network_id,
                                     gateway_id, recipient_id, route,
                                     deadline, clock):
    """No discovery, retry, mutation, grant or successful health observation."""
    try:
        if (type(route) is not ReceiverManagementRouteBinding
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not callable(clock) or gateway_id == recipient_id):
            raise ValueError
        route = replace(route)  # Revalidate Core's fixed-origin domain.
        hostname = urlsplit(route.origin).hostname
        # This observer supports the ordinary single-label node alias authored
        # by DockerRuntimeInterpreter, not literals, resolver numeric forms,
        # network-qualified names or the gateway's local host names.
        if (hostname != route.target.node_id.value or "." in hostname
                or not "a" <= hostname[0] <= "z"
                or hostname in {"localhost", "ip6-localhost", "ip6-loopback",
                    "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters"}):
            raise ValueError

        def check_window():
            now = clock()
            if (type(now) not in (int, float) or not math.isfinite(now)
                    or now >= deadline):
                raise ValueError

        def read(action):
            check_window()
            result = action()
            check_window()
            return result

        network = read(lambda: client.inspect_network(network_name))
        if (type(network) is not DockerSdkResourceInspection
                or network.network_id != network_id or network.name != network_name
                or type(network.network_container_ids) is not tuple
                or not 2 <= len(network.network_container_ids) <= 64
                or network.network_container_ids != tuple(sorted(set(network.network_container_ids)))
                or gateway_id not in network.network_container_ids
                or recipient_id not in network.network_container_ids):
            raise ValueError
        members, owners = [], []
        for identity in network.network_container_ids:
            member = read(lambda: client.inspect_container(identity))
            if (type(member) is not DockerSdkResourceInspection
                    or member.container_id != identity
                    or type(member.name) is not str or not 1 <= len(member.name) <= 255
                    or type(member.network_attachments) is not tuple):
                raise ValueError
            attachments = tuple(value for value in member.network_attachments
                if value.network_id == network_id)
            if len(attachments) != 1:
                raise ValueError
            attachment, = attachments
            dns_names = getattr(attachment, "dns_names", None)
            if (attachment.private_address is None or attachment.aliases is None
                    or type(dns_names) is not tuple):
                raise ValueError
            if identity in (gateway_id, recipient_id) and (
                    member.running is not True or member.started_at is None):
                raise ValueError
            if identity == recipient_id and hostname not in {
                    value.lower() for value in attachment.aliases}:
                raise ValueError
            # With multiple gateway networks, checking one network cannot
            # disambiguate the resolver's other potential destinations.
            if identity == gateway_id and len(member.network_attachments) != 1:
                raise ValueError
            # Docker reports container name, configured hostname, aliases and
            # short ID together. Aliases alone omit possible competing peers.
            if hostname in {value.lower() for value in dns_names}:
                owners.append(identity)
            # Do not compare SDK inspections: their ordinary equality excludes
            # StartedAt/aliases by design. Copy these private primitive facts.
            members.append((identity, member.name, member.running, member.started_at,
                member.image_id, attachment.private_address, attachment.aliases, dns_names))
        if owners != [recipient_id]:
            raise ValueError
        final_network = read(lambda: client.inspect_network(network_name))
        if (type(final_network) is not DockerSdkResourceInspection
                or final_network.network_id != network_id
                or final_network.name != network_name
                or final_network.network_container_ids != network.network_container_ids):
            raise ValueError
        return PostgresRecipientRouteSnapshot(network_id, gateway_id, recipient_id, route, tuple(members))
    except Exception:
        pass
    raise PostgresRecipientUnavailable() from None


def require_same_postgres_recipient_route(before, after):
    if (type(before) is not PostgresRecipientRouteSnapshot
            or type(after) is not PostgresRecipientRouteSnapshot or before != after):
        raise PostgresRecipientUnavailable()
