"""Opt-in passive native connection observation with closed launch profiles.

Construction is not admission. Operations owns current authority and folding.
"""
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
import json
import re
from typing import Callable
from uuid import UUID

import control_plane_kit_core as core
from control_plane_kit_core.algebra import BlockSockets, ProviderSocket
from control_plane_kit_core.configuration import ConfigurationMediaType, ConfigurationFileMode, ConfigurationArtifactRequirement
from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
from control_plane_kit_core.planning import (
    ActivityId, ActivityPlan, ManagementBootstrapStage, ObserveManagementBootstrap,
    PlanGraphSide, resolve_management_observation, compile_graph_activity_plan,
    compile_managed_update_activity_plan, compile_retained_image_ingress_activity_plan,
    AllocatePublicIngress, ReconcileNode, StartNode, StartRuntime,
)
from control_plane_kit_core.products import ProductDescriptorCodec, ProductDescriptorDocument, ProductReference, ProviderRuntimePort
from control_plane_kit_core.receiver_configuration import (
    select_receiver_node_control_configuration_artifact, select_receiver_node_control_configuration_slot,
)
from control_plane_kit_core.runtime_authority import RuntimeAuthorityReference
from control_plane_kit_core.runtime_effects import RuntimeEffectKind, RuntimeEffectRequest, RuntimeProductMaterial
from control_plane_kit_core.secret_installation import (
    SecretInstallationReceipt, secret_installation_correlation_for_request,
    secret_material_selection_fingerprint,
)
from control_plane_kit_core.secret_selections import SecretVersionSelection
from control_plane_kit_core.secrets import SecretFileDelivery, SecretFileMode, SecretUseIntent
from control_plane_kit_core.topology.changes import FieldSubject, ModifiedChange, StructuralField
from control_plane_kit_core.topology.diff import diff_graphs
from control_plane_kit_core.topology.validation import NodeSubject
from control_plane_kit_core.types import RuntimeKind, Protocol
from control_plane_kit_interpreters.docker.configuration import (
    _container_incarnation_fingerprint, configuration_volume_name, require_configuration_file,
)
from control_plane_kit_interpreters.docker.runtime import (
    _container_name, _network_name, _node_correlation_labels, _node_labels, _secret_volume_name,
)
from control_plane_kit_interpreters.docker.sdk import (
    ConnectorConnectionProfile, DockerSdkClient, DockerSdkSecretMount, DockerSdkConfigurationMount,
    _MANAGED_CONNECTOR_CONFIGURATION_PATH,
)


class ConnectorConnectionOutcome(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNKNOWN = "unknown"
    REFUSED = "refused"


class ConnectorConnectionQualification(StrEnum):
    FRESH = "fresh"
    RETAINED_CONTENT_UPDATE = "retained_content_update"
    RETAINED_IMAGE_INGRESS_UPDATE = "retained_image_ingress_update"


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
class DockerConnectorConnectionQualifier:
    """Pure closed-profile capability selection without client or clock custody."""

    product_reference: ProductReference
    image_reference: str
    profile: ConnectorConnectionProfile = ConnectorConnectionProfile.NATIVE_READER_V1

    def __post_init__(self):
        if (type(self.product_reference) is not ProductReference
                or type(self.image_reference) is not str
                or type(self.profile) is not ConnectorConnectionProfile):
            raise TypeError("native connection qualifier configuration is invalid")

    def qualify(self, *, activity_id, plan, current, desired, material,
                authority_ref) -> ConnectorConnectionQualification | None:
        """Pure capability selection, without installation proof or execution authority."""
        try:
            mode, _, _ = self._qualify(activity_id=activity_id, plan=plan, current=current,
                desired=desired, material=material, authority_ref=authority_ref)
            return mode
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return None

    def qualify_shape(self, *, activity_id, plan, current, desired,
                      product_document, authority_ref) -> ConnectorConnectionQualification | None:
        """Query declared capability without resolving material or granting authority."""
        try:
            if type(product_document) is not ProductDescriptorDocument:
                raise ValueError
            document = ProductDescriptorCodec().decode_document(product_document.content)
            if document != product_document:
                raise ValueError
            mode, resolved = self._qualify_plan(activity_id=activity_id, plan=plan,
                current=current, desired=desired, authority_ref=authority_ref)
            node = resolved.connector_node
            reference = ProductReference.from_document(document)
            contract = document.product.runtime_contract
            if (reference != self.product_reference
                    or document.product.image.execution_reference != self.image_reference
                    or node.metadata.get("product_identity") != reference.identity.key
                    or node.metadata.get("product_descriptor_digest") != reference.descriptor_sha256.value
                    or node.socket_environment or node.runtime_authority_deliveries
                    or contract.retained_data_mounts):
                raise ValueError
            if self.profile is ConnectorConnectionProfile.MANAGED_WRAPPER_V1:
                _managed_slot(contract, node)
            elif (node.public_environment or node.configuration_artifacts
                    or contract.public_environment or contract.configuration_artifacts):
                raise ValueError
            # The graph declares the producer/consumer relation. Operations alone
            # later creates the delivery and selected version from durable facts.
            ingresses = tuple(value for value in resolved.selected_graph.graph.public_ingresses
                if value.connector_node_id == node.node_id)
            if ingresses != (resolved.ingress,):
                raise ValueError
            if not node.secret_deliveries:
                if contract.secret_deliveries:
                    # Do not infer descriptor-only material projection here.
                    raise ValueError
            else:
                delivery, = node.secret_deliveries
                slot = _reader_token_slot(delivery)
                if contract.secret_deliveries:
                    declared, = contract.secret_deliveries
                    if _reader_token_slot(declared) != slot:
                        raise ValueError
            return mode
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return None

    def _qualify_plan(self, *, activity_id, plan, current, desired, authority_ref):
        """Core owns validity/order; this predicate bounds the reader's capability."""
        if (type(activity_id) is not ActivityId or type(plan) is not ActivityPlan
                or type(authority_ref) is not RuntimeAuthorityReference):
            raise ValueError
        operation = plan.activity(activity_id).operation
        if (type(operation) is not ObserveManagementBootstrap
                or operation.stage is not ManagementBootstrapStage.CONNECTOR_CONNECTED
                or operation.target.graph_side is not PlanGraphSide.DESIRED_GRAPH):
            raise ValueError
        resolved = resolve_management_observation(operation, current, desired, expected_operation=operation)
        runtime_id = operation.target.runtime_id
        runtime = resolved.selected_graph.graph.runtimes[runtime_id]
        if runtime.kind is not RuntimeKind.DOCKER or runtime.authority_ref != authority_ref:
            raise ValueError
        node = resolved.connector_node
        gateway_id, ingress_id = resolved.gateway_node.node_id, resolved.ingress.ingress_id
        if runtime_id not in current.graph.runtimes:
            # Freshness requires actual creation obligations in the complete pair.
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
            mode = ConnectorConnectionQualification.FRESH
        else:
            if (current.graph.runtimes[runtime_id] != runtime
                    or current.graph.nodes.get(gateway_id) != resolved.gateway_node
                    or current.graph.nodes.get(node.node_id) != node
                    or resolved.ingress not in current.graph.public_ingresses):
                raise ValueError
            image_plan = compile_retained_image_ingress_activity_plan(current, desired)
            if plan == image_plan and image_plan.ready_for_execution and image_plan.activities:
                # Core owns the image relation and ordering. Bound this reader to
                # the retained management path of the one affected workload.
                replacement, = (value.operation for value in image_plan.activities
                    if type(value.operation) is ReconcileNode)
                affected = desired.graph.nodes[replacement.target.node_id]
                if affected.runtime_id != runtime_id or affected.node_id in (gateway_id, node.node_id):
                    raise ValueError
                mode = ConnectorConnectionQualification.RETAINED_IMAGE_INGRESS_UPDATE
            else:
                compiled = compile_managed_update_activity_plan(current, desired)
                if (plan != compiled or not compiled.ready_for_execution
                        or not _retained_content_change(current, desired, runtime_id, gateway_id, node.node_id)):
                    raise ValueError
                mode = ConnectorConnectionQualification.RETAINED_CONTENT_UPDATE
        return mode, resolved

    def _qualify(self, *, activity_id, plan, current, desired, material, authority_ref):
        if type(material) is not RuntimeProductMaterial:
            raise ValueError
        mode, resolved = self._qualify_plan(activity_id=activity_id, plan=plan,
            current=current, desired=desired, authority_ref=authority_ref)
        node = resolved.connector_node
        runtime_id = plan.activity(activity_id).operation.target.runtime_id
        # Round-trip a detached value rather than normalize caller-owned material.
        if RuntimeProductMaterial.from_descriptor(material.descriptor()) != material:
            raise ValueError
        contract = material.product.runtime_contract
        if (material.node_id != node.node_id or material.runtime_id != runtime_id
                or material.reference != self.product_reference
                or material.product.image.execution_reference != self.image_reference
                or node.metadata.get("product_identity") != material.reference.identity.key
                or node.metadata.get("product_descriptor_digest") != material.reference.descriptor_sha256.value
                or material.socket_environment
                or material.runtime_authority_deliveries
                or contract.retained_data_mounts):
            raise ValueError
        if self.profile is ConnectorConnectionProfile.MANAGED_WRAPPER_V1:
            _managed_configuration(material, node)
        elif material.public_environment or contract.public_environment or contract.configuration_artifacts:
            raise ValueError
        delivery, = contract.secret_deliveries
        _reader_token_slot(delivery)
        selections = tuple(selection for selection in material.secret_selections
            if selection.reference == delivery.reference and selection.intent == delivery.intent)
        if len(selections) != 1 or type(selections[0]) is not SecretVersionSelection:
            raise ValueError
        return mode, resolved, delivery


@dataclass(frozen=True, repr=False)
class DockerConnectorConnectionObserver:
    client: DockerSdkClient
    product_reference: ProductReference
    image_reference: str
    clock: Callable[[], datetime]
    profile: ConnectorConnectionProfile = ConnectorConnectionProfile.NATIVE_READER_V1
    _qualification: DockerConnectorConnectionQualifier = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if type(self.client) is not DockerSdkClient or not callable(self.clock):
            raise TypeError("native connection observer configuration is invalid")
        try:
            qualification = DockerConnectorConnectionQualifier(
                self.product_reference, self.image_reference, self.profile,
            )
        except TypeError:
            raise TypeError("native connection observer configuration is invalid") from None
        object.__setattr__(self, "_qualification", qualification)

    def qualify(self, *, activity_id, plan, current, desired, material,
                authority_ref) -> ConnectorConnectionQualification | None:
        """Compatibility entrance to the same pure capability selection."""
        return self._qualification.qualify(activity_id=activity_id, plan=plan,
            current=current, desired=desired, material=material, authority_ref=authority_ref)

    def qualify_shape(self, *, activity_id, plan, current, desired,
                      product_document, authority_ref) -> ConnectorConnectionQualification | None:
        """Compatibility entrance to the same declared capability query."""
        return self._qualification.qualify_shape(activity_id=activity_id, plan=plan,
            current=current, desired=desired, product_document=product_document,
            authority_ref=authority_ref)

    def observe(self, request, *, plan, current, desired,
                installation_request: RuntimeEffectRequest | None = None,
                installation_receipt: SecretInstallationReceipt | None = None):
        try:
            if type(request) is not RuntimeEffectRequest or type(plan) is not ActivityPlan:
                raise ValueError
            request.__post_init__()
            if (request.runtime_kind is not RuntimeKind.DOCKER or request.authority_deliveries
                    or request.operation != plan.activity(request.activity_id).operation):
                raise ValueError
            material, = request.products
            mode, resolved, delivery = self._qualification._qualify(activity_id=request.activity_id, plan=plan,
                current=current, desired=desired, material=material, authority_ref=request.authority_ref)
            node = resolved.connector_node
            origin, incarnation = request, None
            if mode is ConnectorConnectionQualification.FRESH:
                if installation_request is not None or installation_receipt is not None:
                    raise ValueError
            else:
                origin = _installation_origin(request, installation_request, installation_receipt)
                incarnation = installation_receipt.current_realization_fingerprint
            artifact, configuration_volume = None, None
            if self.profile is ConnectorConnectionProfile.MANAGED_WRAPPER_V1:
                artifact = _managed_configuration(material, node, workspace_id=request.source.workspace_id)
                if mode in (ConnectorConnectionQualification.RETAINED_CONTENT_UPDATE,
                            ConnectorConnectionQualification.RETAINED_IMAGE_INGRESS_UPDATE):
                    # Invalid retained proof must never acquire fresh candidate semantics.
                    if origin.kind is not RuntimeEffectKind.CONFIGURATION_ACTIVITY_V1 or origin.configuration_instances is None:
                        raise ValueError
                    reference, = origin.configuration_instances.instances
                    if (reference.workspace_id, reference.runtime_id, reference.node_id,
                            reference.artifact_id, reference.target_path, reference.media_type,
                            reference.file_mode, reference.content_digest) != (
                            request.source.workspace_id, material.runtime_id, material.node_id,
                            artifact.artifact_id, artifact.target_path, artifact.media_type,
                            artifact.file_mode, artifact.content_digest):
                        raise ValueError
                    configuration_volume = configuration_volume_name(reference)
            expected_name = _container_name(origin, node.node_id)
            expected_labels = _node_correlation_labels(_node_labels(origin, material))
            network = _network_name(origin, material.runtime_id)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return ConnectorConnectionObservation(ConnectorConnectionOutcome.REFUSED)

        correlation = dict(effect_id=request.effect_id, activity_id=request.activity_id.value)
        unknown = ConnectorConnectionObservation(ConnectorConnectionOutcome.UNKNOWN, **correlation)
        try:
            first = self.client.inspect_connector_container(expected_name, profile=self.profile)
            if (first.name != "/" + expected_name or first.network != network
                    or _node_correlation_labels(dict(first.labels)) != expected_labels):
                return unknown
            if incarnation is not None and _container_incarnation_fingerprint(first.container_id) != incarnation:
                return unknown
            _fresh(first, self.clock())
            image = self.client.inspect_connector_image(self.image_reference, token_path=delivery.target_path,
                profile=self.profile)
            mount = DockerSdkSecretMount(delivery.target_path,
                _secret_volume_name(origin, node.node_id, delivery, owner_uid=image.owner_uid))
            _fresh(first, self.clock())
            if (first.image_id != image.image_id or first.launch_digest != image.launch_digest
                    or first.secret_mount != mount):
                return unknown
            if artifact is not None:
                selected = first.configuration_mount
                if (selected is None or selected.target_path != artifact.target_path
                        or (configuration_volume is not None and selected.volume_name != configuration_volume)):
                    return unknown
                # Fresh volume is an observed candidate, not an allocated reference.
                mounted = DockerSdkConfigurationMount(artifact, selected.volume_name)
                content = self.client.inspect_configuration_mount(first.container_id, mounted)
                _fresh(first, self.clock())
                if (content is None or content.container_id != first.container_id
                        or content.volume_name != selected.volume_name or content.target_path != artifact.target_path
                        or content.subpath != "content" or content.read_only is not True):
                    return unknown
                require_configuration_file(content.file, artifact)
            final = self.client.inspect_connector_container(first.container_id, profile=self.profile)
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


_MANAGED_REQUIREMENT = ConfigurationArtifactRequirement("cloudflared-control",
    _MANAGED_CONNECTOR_CONFIGURATION_PATH, ConfigurationMediaType.JSON, ConfigurationFileMode.READ_ONLY)
_MANAGED_ENVIRONMENT = (PublicStaticEnvironmentBinding(
    "CPK_WRAPPER_CONFIGURATION_FILE", _MANAGED_CONNECTOR_CONFIGURATION_PATH),)
_MANAGED_DECLARATION = core.WorkloadNodeControlSurfaceDeclaration(
    core.WorkloadNodeControlSurfaceDescriptor(
        core.NodeControlGraphReference(core.NodeControlGraphReferenceRole.PROVIDER_SOCKET, "control"),
        (), (core.NodeHealthReadKind.LIVENESS, core.NodeHealthReadKind.READINESS)),
    profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2)


def _slot_fields(value):
    return value.artifact_id, value.target_path, value.media_type, value.file_mode


def _managed_slot(contract, node):
    """Pure structural capability; declared requirements do not resolve material."""
    surfaces = (_MANAGED_DECLARATION.surface,)
    if (contract.public_environment != _MANAGED_ENVIRONMENT
            or node.public_environment != _MANAGED_ENVIRONMENT or node.socket_environment
            or node.runtime_authority_deliveries or contract.control_surfaces != surfaces
            or node.block_spec.control_surfaces != surfaces
            or contract.sockets != BlockSockets(providers=(ProviderSocket("control", Protocol.HTTP),))
            or node.sockets != contract.sockets
            or contract.provider_ports != (ProviderRuntimePort("control", 8000),)
            or len(contract.configuration_artifacts) + len(contract.configuration_requirements) != 1
            or len(node.configuration_artifacts) != 1):
        raise ValueError
    declared = select_receiver_node_control_configuration_slot(
        artifacts=contract.configuration_artifacts, requirements=contract.configuration_requirements,
        environment=contract.public_environment, control_surfaces=surfaces)
    authored = select_receiver_node_control_configuration_slot(artifacts=node.configuration_artifacts,
        environment=node.public_environment, control_surfaces=surfaces)
    if _slot_fields(declared) != _slot_fields(_MANAGED_REQUIREMENT) or _slot_fields(authored) != _slot_fields(declared):
        raise ValueError
    if contract.configuration_artifacts and contract.configuration_artifacts != node.configuration_artifacts:
        raise ValueError
    return authored


def _managed_configuration(material, node, *, workspace_id=None):
    contract = material.product.runtime_contract
    _managed_slot(contract, node)
    if (contract.configuration_requirements or material.public_environment != _MANAGED_ENVIRONMENT
            or contract.configuration_artifacts != node.configuration_artifacts):
        raise ValueError
    artifact = select_receiver_node_control_configuration_artifact(
        artifacts=contract.configuration_artifacts, environment=material.public_environment,
        control_surfaces=contract.control_surfaces)
    value = core.ReceiverNodeControlConfigurationCodec().decode_bytes(artifact.content.encode("utf-8"))
    if (value.declaration != _MANAGED_DECLARATION or value.target.runtime_id.value != material.runtime_id
            or value.target.node_id.value != material.node_id
            or (workspace_id is not None and value.target.workspace_id.value != workspace_id)):
        raise ValueError
    return artifact


def _reader_token_slot(delivery):
    """Validate the existing file profile without constructing or resolving it."""
    if (type(delivery) is not SecretFileDelivery
            or delivery.intent is not SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN
            or delivery.file_mode is not SecretFileMode.OWNER_READ_ONLY
            or delivery.path_binding is None or delivery.path_binding.environment_name != "TUNNEL_TOKEN_FILE"):
        raise ValueError
    delivery.__post_init__()
    return delivery.target_path, delivery.intent, delivery.file_mode, delivery.path_binding


def _retained_content_change(current, desired, runtime_id, gateway_id, connector_id):
    """Narrow reader capability over Core's separately validated managed plan."""
    changes = diff_graphs(current, desired).changes
    if len(changes) != 1:
        return False
    change, = changes
    if (type(change) is not ModifiedChange or type(change.subject) is not FieldSubject
            or change.subject.field is not StructuralField.CONFIGURATION_ARTIFACTS
            or type(change.subject.owner) is not NodeSubject):
        return False
    node_id = change.subject.owner.node_id
    before, after = current.graph.nodes[node_id], desired.graph.nodes[node_id]
    if (node_id in (gateway_id, connector_id) or after.runtime_id != runtime_id
            or desired.graph.update_node(replace(after, configuration_artifacts=before.configuration_artifacts)) != current.graph):
        return False
    old = {value.artifact_id: value for value in before.configuration_artifacts}
    new = {value.artifact_id: value for value in after.configuration_artifacts}
    if old.keys() != new.keys():
        return False
    changed = tuple(key for key in old if old[key] != new[key])
    if len(changed) != 1:
        return False
    wrapper = select_receiver_node_control_configuration_artifact(artifacts=before.configuration_artifacts,
        environment=before.public_environment + before.socket_environment,
        control_surfaces=before.block_spec.control_surfaces)
    if changed[0] == wrapper.artifact_id:
        return False
    original, successor = old[changed[0]], new[changed[0]]
    return (original.media_type is ConfigurationMediaType.JSON and original.content != successor.content
        and replace(successor, content=original.content, source_digest=original.source_digest) == original)


def _installation_origin(request, original, receipt):
    """Check supplied provenance correlation; durable proof belongs to the caller."""
    if (type(original) is not RuntimeEffectRequest or type(receipt) is not SecretInstallationReceipt
            or original.runtime_kind is not RuntimeKind.DOCKER
            or original.secret_resolution_grants != () or original.authority_deliveries != ()):
        raise ValueError
    context = secret_installation_correlation_for_request(original)
    SecretInstallationReceipt.__post_init__(receipt)
    material, = request.products
    if (original.products != request.products
            or (context.source.workspace_id, context.runtime_id, context.node_id) != (
                request.source.workspace_id, material.runtime_id, material.node_id)
            or not context.secret_selections
            or receipt.request_fingerprint != context.request_fingerprint
            or receipt.selection_fingerprint != secret_material_selection_fingerprint(original)):
        raise ValueError
    return original


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
