"""Opt-in passive native reader-v1 observation, without effect replay.

Construction is not admission. Operations owns current authority and folding.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import json
import re
from typing import Callable
from uuid import UUID

from control_plane_kit_core.planning import (
    ActivityPlan, ManagementBootstrapStage, ObserveManagementBootstrap,
    PlanGraphSide, resolve_management_observation, compile_graph_activity_plan,
    AllocatePublicIngress, StartNode, StartRuntime,
)
from control_plane_kit_core.products import ProductReference
from control_plane_kit_core.runtime_effects import RuntimeEffectRequest
from control_plane_kit_core.secrets import SecretFileDelivery, SecretFileMode, SecretUseIntent
from control_plane_kit_core.types import RuntimeKind
from control_plane_kit_interpreters.docker.runtime import (
    _container_name, _network_name, _node_correlation_labels, _node_labels, _secret_volume_name,
)
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient, DockerSdkSecretMount


class ConnectorConnectionOutcome(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNKNOWN = "unknown"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class ConnectorConnectionObservation:
    outcome: ConnectorConnectionOutcome
    effect_id: str | None = None
    activity_id: str | None = None
    container_id: str | None = None
    sample_start: str | None = None
    sample_end: str | None = None
    ready_connections: int | None = None
    connector_id: str | None = None


@dataclass(frozen=True, repr=False)
class DockerConnectorConnectionObserver:
    client: DockerSdkClient
    product_reference: ProductReference
    image_reference: str
    clock: Callable[[], datetime]

    def __post_init__(self):
        if (type(self.client) is not DockerSdkClient or type(self.product_reference) is not ProductReference
                or type(self.image_reference) is not str or not callable(self.clock)):
            raise TypeError("native connection observer configuration is invalid")

    def observe(self, request, *, plan, current, desired):
        try:
            if type(request) is not RuntimeEffectRequest or type(plan) is not ActivityPlan:
                raise ValueError
            request.__post_init__()
            operation = request.operation
            if (type(operation) is not ObserveManagementBootstrap
                    or operation.stage is not ManagementBootstrapStage.CONNECTOR_CONNECTED
                    or operation.target.graph_side is not PlanGraphSide.DESIRED_GRAPH
                    or request.runtime_kind is not RuntimeKind.DOCKER or request.authority_ref is None):
                raise ValueError
            resolved = resolve_management_observation(operation, current, desired,
                expected_operation=plan.activity(request.activity_id).operation)
            runtime_id = operation.target.runtime_id
            runtime = resolved.selected_graph.graph.runtimes[runtime_id]
            if (runtime.kind is not RuntimeKind.DOCKER or runtime.authority_ref != request.authority_ref
                    or runtime_id in current.graph.runtimes):
                raise ValueError
            node = resolved.connector_node
            gateway_id, ingress_id = resolved.gateway_node.node_id, resolved.ingress.ingress_id
            # Freshness belongs to the complete graph pair and real creation
            # obligations, not merely a new runtime ID or the observation pin.
            compiled = compile_graph_activity_plan(current, desired)
            operations = tuple(item.operation for item in compiled.activities)
            if (plan != compiled or not compiled.ready_for_execution
                    or gateway_id in current.graph.nodes or node.node_id in current.graph.nodes
                    or any(item.ingress_id == ingress_id for item in current.graph.public_ingresses)
                    or not any(type(item) is StartRuntime and item.target.runtime_id == runtime_id for item in operations)
                    or not all(any(type(item) is StartNode and item.target.node_id == identity for item in operations)
                        for identity in (gateway_id, node.node_id))
                    or not any(type(item) is AllocatePublicIngress and item.target.ingress_id == ingress_id for item in operations)):
                raise ValueError
            material, = request.products
            contract = material.product.runtime_contract
            if (material.node_id != node.node_id or material.runtime_id != runtime_id
                    or material.reference != self.product_reference
                    or material.product.image.execution_reference != self.image_reference
                    or node.metadata.get("product_identity") != material.reference.identity.key
                    or node.metadata.get("product_descriptor_digest") != material.reference.descriptor_sha256.value
                    or material.public_environment or material.socket_environment
                    or material.runtime_authority_deliveries or request.authority_deliveries
                    or contract.public_environment or contract.configuration_artifacts or contract.retained_data_mounts):
                raise ValueError
            delivery, = contract.secret_deliveries
            if (type(delivery) is not SecretFileDelivery
                    or delivery.intent is not SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN
                    or delivery.file_mode is not SecretFileMode.OWNER_READ_ONLY
                    or delivery.path_binding is None or delivery.path_binding.environment_name != "TUNNEL_TOKEN_FILE"):
                raise ValueError
            delivery.__post_init__()
            expected_name = _container_name(request, node.node_id)
            expected_labels = _node_correlation_labels(_node_labels(request, material))
            network = _network_name(request, runtime_id)
            mount = DockerSdkSecretMount(delivery.target_path, _secret_volume_name(request, node.node_id, delivery))
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return ConnectorConnectionObservation(ConnectorConnectionOutcome.REFUSED)

        correlation = dict(effect_id=request.effect_id, activity_id=request.activity_id.value)
        unknown = ConnectorConnectionObservation(ConnectorConnectionOutcome.UNKNOWN, **correlation)
        try:
            first = self.client.inspect_connector_container(expected_name)
            if (first.name != "/" + expected_name or first.network != network or first.secret_mount != mount
                    or _node_correlation_labels(dict(first.labels)) != expected_labels):
                return unknown
            _fresh(first, self.clock())
            image = self.client.inspect_connector_image(self.image_reference, token_path=delivery.target_path)
            _fresh(first, self.clock())
            if first.image_id != image.image_id or first.launch_digest != image.launch_digest:
                return unknown
            final = self.client.inspect_connector_container(first.container_id)
            _fresh(final, self.clock())
            # Equality includes latest sample, incarnation, effective program,
            # ownership and immutable ID; a new failed sample loses old success.
            if final != first:
                return unknown
            outcome, count, identity = _decode(final.sample)
            _fresh(final, self.clock())
            return ConnectorConnectionObservation(outcome, **correlation,
                container_id=final.container_id, sample_start=final.sample.start, sample_end=final.sample.end,
                ready_connections=count, connector_id=identity)
        except Exception:
            # Provider exceptions, candidate values and their hashes never cross
            # the observation boundary. No retries or fallback effects.
            return unknown


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_STAMP = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})\Z")


def _clock_ns(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    delta = value.astimezone(timezone.utc) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def _timestamp_ns(value):
    match = _STAMP.fullmatch(value)
    if match is None:
        raise ValueError
    whole, fraction, zone = match.groups()
    # fromisoformat normalizes offsets such as +00:60; reject malformed RFC3339
    # components before conversion so normalization cannot manufacture freshness.
    if zone != "Z" and (int(zone[1:3]) > 23 or int(zone[4:6]) > 59):
        raise ValueError
    parsed = datetime.fromisoformat(whole + ("+00:00" if zone == "Z" else zone))
    return _clock_ns(parsed) + int((fraction or "").ljust(9, "0"))


def _fresh(inspection, now):
    started = _timestamp_ns(inspection.started_at)
    start, end = _timestamp_ns(inspection.sample.start), _timestamp_ns(inspection.sample.end)
    current = _clock_ns(now)
    if not started <= start <= end <= current or current - end > 10_000_000_000:
        raise ValueError


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _decode(sample):
    value = json.loads(sample.output, object_pairs_hook=_unique)
    if type(value) is not dict or value.get("schema") != "cpk.cloudflared.connection/v1":
        raise ValueError
    outcome = ConnectorConnectionOutcome(value["outcome"])
    if outcome is ConnectorConnectionOutcome.UNKNOWN:
        if (set(value) != {"schema", "outcome", "reason"} or sample.exit_code != 1
                or value["reason"] not in {"invalid_response", "invalid_http", "response_too_large",
                    "timeout", "transport_unavailable", "invalid_invocation"}):
            raise ValueError
        return outcome, None, None
    if set(value) != {"schema", "outcome", "readyConnections", "connectorId"}:
        raise ValueError
    count, identity = value["readyConnections"], value["connectorId"]
    if type(count) is not int or not 0 <= count < 2**64 or type(identity) is not str:
        raise ValueError
    parsed = UUID(identity)
    if parsed.int == 0 or str(parsed) != identity:
        raise ValueError
    if (outcome is ConnectorConnectionOutcome.CONNECTED and count > 0 and sample.exit_code == 0
            or outcome is ConnectorConnectionOutcome.DISCONNECTED and count == 0 and sample.exit_code == 1):
        return outcome, count, identity
    raise ValueError
