# Exact network inspection metadata (#194)

`DockerSdkClient.inspect_network` now retains the selected resource's immutable
Docker `Id` as `DockerSdkResourceInspection.network_id`. `inspect_container`
retains its existing `container_id` and adds `network_attachments`, a tuple of
public frozen `DockerSdkNetworkAttachment(network_id, private_address)` values.
The new identity/address fields come from the same already-fetched inspect
payload, never from a positional join of the existing name/address maps.

The optional values distinguish facts:

- `network_attachments is None`: membership identity is unavailable or was not
  requested. Missing NetworkSettings/Networks or an attachment lacking NetworkID
  cannot become an observed empty tuple or a partially qualified result.
- `network_attachments == ()`: the inspect payload contains an observed empty
  Networks mapping.
- `DockerSdkNetworkAttachment(network_id, None)`: that exact membership is known,
  but IPAddress is absent, null or empty; it cannot supply a gateway origin.

Missing network resource Id yields `network_id=None`; a present malformed Id
raises a fixed RuntimeError. Container identity retains its existing optional
semantics. Non-container reads leave membership evidence unrequested. Existing
name, network_names, private_addresses, labels, ports and runtime identity fields
remain available to current consumers.

IDs must be 64 lowercase hexadecimal characters. Membership count is capped at
64; each address is a canonical, unscoped numeric IP of at most 45 characters from
the existing IPAddress field. This does not add a new GlobalIPv6Address source or
alias inventory. Duplicate member IDs refuse; ordering is by immutable ID.
Each member is copied into a frozen value, so later provider metadata mutation
does not change the observed pair. Malformed metadata produces fixed bounded
errors; private addresses are omitted from the new member value's repr.

No provider lookup is added: each public inspection still performs one exact
SDK get. NotFound remains None; other provider exceptions retain their existing
behavior. Client creation, selected authority, ownership and close/TLS cleanup
are unchanged. No enumeration, network mutation, secret resolution, retry,
helper or persistent state is introduced.

The existing runtime observer recognizes the two new SDK parsers' exact code
origins and fixed malformed messages as unavailable provider observations.
Identical error text raised elsewhere still propagates as a programming error;
no broad RuntimeError normalization is added.

These are provider facts, not route authorization, reachability or readiness.
Servers #250 may use the accepted fields to correlate the exact selected
controller/gateway/network and derive a destination from the matched member IP
plus accepted readiness port. It must still supply explicit placement policy;
actual bounded signed HTTP proves health. I189 stays accepted; this addition
neither attaches a controller nor qualifies a production deployment.

The [target companion](tests/test_docker_network_inspection.py.md) records the
behavioral laws and red-to-green evidence boundary. Core/Operations and dependency
coordinates are unchanged. No live/provider mutation, image publication or
original tunnel/DNS/token changes are included.
