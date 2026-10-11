"""I186 finite hosted witness: actual configured runtime and receipt production."""
from contextlib import ExitStack
import json
from uuid import uuid4
from unittest.mock import patch

from docker.errors import NotFound
from control_plane_kit_core.algebra import BlockSockets
from control_plane_kit_core.configuration import ConfigurationArtifact, ConfigurationFileMode, ConfigurationMediaType
from control_plane_kit_core.configuration_installation import configuration_installation_receipt_for_result
from control_plane_kit_core.configuration_instances import ConfigurationInstanceRef, ConfigurationInstanceSelection
from control_plane_kit_core.configuration_invocation import configuration_invocation_correlation_for_request
from control_plane_kit_core.operations import RunId
from control_plane_kit_core.planning import ActivityId, NodeTarget, ReconcileNode, StartNode
from control_plane_kit_core.products import (
    ContainerServerProduct, OciImageReference, ProductDescriptorCodec, ProductDescriptorDigest,
    ProductIdentity, ProductReference, ProductRuntimeContract,
)
from control_plane_kit_core.runtime_effects import (
    EffectResultKind, RuntimeEffectKind, RuntimeEffectRequest, RuntimeEffectSource, RuntimeProductMaterial,
)
from control_plane_kit_core.types import RuntimeKind
from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter, DockerSdkConfigurationMount
from control_plane_kit_interpreters.docker.configuration import configuration_volume_name
from control_plane_kit_interpreters.docker.runtime import _container_name, _network_name
from live_docker_configuration import ConfigurationFixtureResources
from test_docker_installation_receipts import expected_identity


_LIMITS = {"network": 1, "volume": 4, "reader": 2, "helper": 14}
_PHASES = frozenset({"preflight", "authority-preflight", "network", "configuration-staging",
    "container-preparation", "container-remove", "container-create", "container-start", "installed-verification"})
_FAILURE_CODES = frozenset({
    "docker.configuration-effect-uncertain", "docker.configuration-material-conflict",
    "docker.configuration-evidence-invalid", "docker.configuration-result-capacity",
    "docker.runtime-request-invalid", "docker.unsupported-effect-kind", "docker.unsupported-runtime-kind",
    "docker.unsupported-activity-operation", "docker.runtime-authority-change-unsupported",
    "docker.product-material-required", "docker.image-reference-conflict", "docker.effect-uncertain",
    "docker.container-ownership-conflict", "docker.network-ownership-conflict",
    "docker.container-material-evidence-unsupported", "docker.container-network-conflict",
    "docker.container-image-conflict", "docker.container-not-running", "docker.container-authority-conflict",
    "docker.runtime-authority-delivery-conflict", "docker.runtime-authority-delivery-unsupported",
    "docker.environment-binding-conflict",
})


def _bounded_counts(counts):
    values = counts if type(counts) is dict else {}
    return {key: (values[key] if 0 <= values[key] <= limit else
                  "limit-exceeded" if values[key] > limit else "unavailable")
            if type(values.get(key)) is int else "unavailable" for key, limit in _LIMITS.items()}


def _runtime_diagnostic(step, result, counts):
    evidence = result.evidence if type(result.evidence) is dict else {}
    attempt = evidence.get("configuration_attempt")
    attempt = attempt if type(attempt) is dict else {}
    code = None if result.failure is None else result.failure.code
    phase = attempt.get("phase")
    def indices(key):
        value = attempt.get(key)
        return list(value) if type(value) in (list, tuple) and len(value) <= 32 and all(
            type(item) is int and 0 <= item < 32 for item in value) else "unavailable"
    return {"installation_runtime": "observed",
        "step": step if type(step) is str and step in ("created", "reused", "replaced") else "unavailable",
        "kind": result.kind.value if type(result.kind) is EffectResultKind else "unavailable",
        "failure_code": code if type(code) is str and code in _FAILURE_CODES else "unavailable",
        "phase": phase if type(phase) is str and phase in _PHASES else "unavailable",
        "attempted_indices": indices("attempted_indices"), "staged_indices": indices("staged_indices"),
        "old_removed": attempt.get("old_removed") if type(attempt.get("old_removed")) is bool else None,
        "unknown_created_resource": attempt.get("unknown_created_resource")
            if type(attempt.get("unknown_created_resource")) is bool else None,
        "receipt_present": "configuration_installation_receipt" in evidence,
        "completion_present": "configuration_invocation_completion" in evidence,
        "attempted_calls": _bounded_counts(counts)}


def _cleanup_diagnostic(state, resources):
    counts = {key: 0 for key in _LIMITS}
    for kind, _, _, _ in resources.entries:
        if kind in counts:
            counts[kind] += 1
    unresolved = len(resources.uncertain)
    return {"installation_cleanup": state if state in ("started", "passed", "HOLD") else "unavailable",
        "scope": "existing-acknowledged-resource-predicate",
        "recorded_candidates": _bounded_counts(counts),
        "unresolved_creates": unresolved if 0 <= unresolved <= sum(_LIMITS.values()) else "unavailable"}


def _write_diagnostic(project, *arguments):
    try:
        print(json.dumps(project(*arguments), sort_keys=True))
    except Exception:
        # Formatting or failed output cannot prevent exact fixture cleanup.
        return False
    return True


def _hardened_workload_kwargs(builder, arguments):
    # Preserve the runtime's exact reserved labels; add only fixture hardening.
    return {**builder(**arguments),
        "command": ["python", "-B", "-c", "import time; time.sleep(120)"],
        "user": "10006:10008", "read_only": True, "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"]}


def _requests(workspace, image_reference):
    def request(generation, suffix, reconcile):
        artifacts = tuple(ConfigurationArtifact(f"config-{index}", f"/etc/cpk-fixture/{index}.json",
            ConfigurationMediaType.JSON, json.dumps({"value": generation if index == 0 else "fixed"}),
            ConfigurationFileMode.READ_ONLY) for index in range(2))
        product = ContainerServerProduct(ProductIdentity("control-plane-kit-test", "installation-receipt", 1),
            OciImageReference("docker.io", "library/python", image_reference.split("@", 1)[1]),
            ProductRuntimeContract(sockets=BlockSockets(), configuration_artifacts=artifacts))
        descriptor = ProductDescriptorCodec().encode_document(product)
        material = RuntimeProductMaterial(node_id="receiver", runtime_id="docker",
            reference=ProductReference(product.identity, ProductDescriptorDigest(descriptor.content_digest)), product=product)
        instances = ConfigurationInstanceSelection(tuple(ConfigurationInstanceRef(
            f"{generation}-{index}", workspace, "docker", "receiver", artifact.artifact_id,
            artifact.target_path, artifact.media_type, artifact.file_mode, artifact.content_digest)
            for index, artifact in enumerate(artifacts)))
        effect = "effect-" + suffix
        return RuntimeEffectRequest(effect, RuntimeEffectKind.CONFIGURATION_ACTIVITY_V1, RuntimeKind.DOCKER,
            RuntimeEffectSource(workspace, "request-" + suffix, RunId("run-" + suffix), "plan-" + suffix,
                "base-" + suffix, "desired-" + suffix, effect), ActivityId("activity-" + suffix),
            ReconcileNode(NodeTarget("receiver")) if reconcile else StartNode(NodeTarget("receiver")),
            products=(material,), configuration_instances=instances)
    return request("a", "created", False), request("a", "reused", True), request("b", "replaced", True)


def run_installation_witness(client, sdk, image_reference, helper_image):
    workspace = "cpk186-" + uuid4().hex
    requests = _requests(workspace, image_reference)
    image = sdk.inspect_image(image_reference)
    if image is None or client.images.get(image_reference).id != image.image_id:
        raise RuntimeError("installation fixture image provenance unavailable")
    if sdk.configuration_helper_image != helper_image or client.images.get(helper_image).id != helper_image:
        raise RuntimeError("installation fixture helper provenance unavailable")
    # Production image admission verifies RepoDigests again, with pull forbidden.
    resources = ConfigurationFixtureResources(client, workspace, image.image_id, helper_image,
        ownership_label="org.openj92.cpk.workspace")
    name, network = _container_name(requests[0], "receiver"), _network_name(requests[0], "docker")
    volumes = {configuration_volume_name(ref) for request in (requests[0], requests[2])
               for ref in request.configuration_instances.instances}
    for manager, coordinate in ((client.containers, name), (client.networks, network),
                                *((client.volumes, volume) for volume in sorted(volumes))):
        try:
            manager.get(coordinate)
        except NotFound:
            continue
        raise RuntimeError("installation fixture coordinate already exists")

    original_create = sdk.create_container
    original_helper = sdk._create_configuration_helper
    original_kwargs = sdk._container_create_kwargs
    network_type, volume_type = type(client.networks), type(client.volumes)
    original_network, original_volume = network_type.create, volume_type.create
    counts = dict(network=0, volume=0, reader=0, helper=0)

    def admit(kind, limit):
        counts[kind] += 1
        if counts[kind] > limit:
            raise RuntimeError("installation fixture resource ceiling exceeded")

    def create_network(manager, *args, **kwargs):
        if manager.client is not client or args or kwargs.get("name") != network:
            raise RuntimeError("installation fixture network out of scope")
        admit("network", 1)
        labels = dict(kwargs["labels"])
        return resources.create("network", network,
            lambda: original_network(manager, **{**kwargs, "labels": labels, "internal": True}), labels=labels)

    def create_volume(manager, *args, **kwargs):
        if manager.client is not client or args or kwargs.get("name") not in volumes:
            raise RuntimeError("installation fixture volume out of scope")
        admit("volume", 4)
        labels = dict(kwargs["labels"])
        return resources.create("volume", kwargs["name"],
            lambda: original_volume(manager, **{**kwargs, "labels": labels}), labels=labels)

    def create_workload(**kwargs):
        if kwargs.get("name") != name or kwargs.get("image") != image_reference:
            raise RuntimeError("installation fixture workload out of scope")
        admit("reader", 2)
        return resources.create("reader", name, lambda: original_create(**kwargs),
            labels=kwargs["labels"])

    def create_helper(volume_name, *, readonly):
        if volume_name not in volumes:
            raise RuntimeError("installation fixture helper out of scope")
        admit("helper", 14)
        return resources.create("helper", volume_name,
            lambda: original_helper(volume_name, readonly=readonly), volume=volume_name, readonly=readonly)

    def hardened_kwargs(**kwargs):
        return _hardened_workload_kwargs(original_kwargs, kwargs)

    def refuse_pull(*args, **kwargs):
        raise RuntimeError("installation fixture image pull prohibited")

    print(json.dumps({"installation_receipts": "planned", "workspace": workspace,
        "network": network, "workload": name, "volumes": sorted(volumes)}, sort_keys=True))
    identities, receipts = [], []
    diagnostics_available = True
    def emit(project, *arguments):
        nonlocal diagnostics_available
        diagnostics_available = _write_diagnostic(project, *arguments) and diagnostics_available
    try:
        with ExitStack() as stack:
            for owner, method, replacement in (
                (network_type, "create", create_network), (volume_type, "create", create_volume),
                (sdk, "create_container", create_workload), (sdk, "_create_configuration_helper", create_helper),
                (sdk, "_container_create_kwargs", hardened_kwargs), (sdk, "pull_image", refuse_pull),
            ):
                stack.enter_context(patch.object(owner, method, replacement))
            interpreter = DockerRuntimeInterpreter(sdk)
            for request, disposition in zip(requests, ("created", "reused", "replaced"), strict=True):
                result = interpreter.execute(request)
                emit(_runtime_diagnostic, disposition, result, counts)
                if result.kind is not EffectResultKind.SUCCEEDED:
                    raise RuntimeError("installation fixture runtime did not succeed")
                receipt = configuration_installation_receipt_for_result(
                    configuration_invocation_correlation_for_request(request), result)
                assert receipt is not None and receipt.disposition.value == disposition
                identity = result.evidence["configuration_attempt"]["container_id"]
                assert any(kind == "reader" and captured == identity for kind, captured, _, _ in resources.entries)
                assert receipt.current_realization_fingerprint == expected_identity(identity)
                observed = sdk.inspect_container(identity)
                assert observed is not None and observed.container_id == identity and observed.running
                assert observed.image_id == image.image_id
                resource = client.containers.get(identity)
                resource.reload()
                assert resource.id == identity and resource.attrs["Config"]["User"] == "10006:10008"
                assert resource.attrs["HostConfig"]["ReadonlyRootfs"] is True
                assert resource.attrs["HostConfig"]["CapDrop"] == ["ALL"]
                assert "no-new-privileges" in resource.attrs["HostConfig"]["SecurityOpt"]
                assert not resource.attrs["HostConfig"]["PortBindings"]
                assert set(resource.attrs["NetworkSettings"]["Networks"]) == {network}
                artifacts = {artifact.artifact_id: artifact for artifact in request.products[0].product.runtime_contract.configuration_artifacts}
                assert len(resource.attrs["Mounts"]) == 2
                for ref in request.configuration_instances.instances:
                    mount = DockerSdkConfigurationMount(artifacts[ref.artifact_id], configuration_volume_name(ref))
                    actual = sdk.inspect_configuration_mount(identity, mount)
                    assert actual is not None and actual.container_id == identity
                    assert (actual.volume_name, actual.target_path, actual.subpath, actual.read_only) == (
                        mount.volume_name, mount.artifact.target_path, "content", True)
                    assert actual.file.regular_file and actual.file.mode == 0o444
                    assert actual.file.content_digest == mount.artifact.content_digest
                if disposition == "created":
                    assert receipt.prior_realization_fingerprint is None
                elif disposition == "reused":
                    assert identity == identities[0]
                    assert receipt.prior_realization_fingerprint == receipts[0].current_realization_fingerprint
                    assert receipt.request_fingerprint != receipts[0].request_fingerprint
                    assert counts == dict(network=1, volume=2, reader=1, helper=8)
                else:
                    assert identity != identities[0]
                    assert receipt.prior_realization_fingerprint == receipts[0].current_realization_fingerprint
                    assert receipt.current_realization_fingerprint != receipt.prior_realization_fingerprint
                    assert sdk.inspect_container(identities[0]) is None
                identities.append(identity)
                receipts.append(receipt)
            assert counts == dict(network=1, volume=4, reader=2, helper=14)
            network_ids = [identity for kind, identity, _, _ in resources.entries if kind == "network"]
            assert len(network_ids) == 1
            assert client.networks.get(network_ids[0]).attrs["Internal"] is True
    finally:
        emit(_cleanup_diagnostic, "started", resources)
        try:
            resources.cleanup()
        except Exception:
            emit(_cleanup_diagnostic, "HOLD", resources)
            raise
        else:
            emit(_cleanup_diagnostic, "passed", resources)
    if not diagnostics_available:
        raise RuntimeError("installation fixture diagnostics unavailable")
    print(json.dumps({"installation_receipts": "passed", "sequence": [r.disposition.value for r in receipts],
        "stable_reuse_identity": True, "distinct_replacement_identity": True,
        "prior_absence_verified": True, "all_selected_material_verified": True,
        "resources": counts, "residue": "absent"}, sort_keys=True))
