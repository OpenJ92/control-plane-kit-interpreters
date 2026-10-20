"""Managed Core values and recording Docker facts; no admission emulator."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import control_plane_kit_core as core
from control_plane_kit_core.algebra import BlockSockets, ProviderSocket
from control_plane_kit_core.capabilities import CapabilityName
from control_plane_kit_core.configuration import ConfigurationArtifactRequirement, ConfigurationFileMode, ConfigurationMediaType
from control_plane_kit_core.configuration_instances import ConfigurationInstanceRef, ConfigurationInstanceSelection
from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
from control_plane_kit_core.products import ProductDescriptorCodec, ProductReference, ProviderRuntimePort
from control_plane_kit_core.runtime_effects import RuntimeEffectKind
from control_plane_kit_core.topology import validate_graph
from control_plane_kit_core.topology.graph import Endpoint, LiteralAddress
from control_plane_kit_core.types import Protocol
from control_plane_kit_interpreters.docker import connector_connection as module
from control_plane_kit_interpreters.docker.configuration import configuration_volume_name
from control_plane_kit_interpreters.docker.runtime import _node_labels
from docker_connector_fixtures import World, RetainedWorld, CONTAINER_ID
from receiver_configuration_fixtures import receiver_configuration, receiver_artifact
from health_signing_fixtures import key
from test_docker_configuration_readback import archive_bytes

TARGET = "/etc/cpk/cloudflared/control.json"
ENVIRONMENT = (PublicStaticEnvironmentBinding("CPK_WRAPPER_CONFIGURATION_FILE", TARGET),)


def managed_world(*, retained=False, lazy=False):
    world = RetainedWorld(lazy=lazy) if retained else World(lazy=lazy)
    surface = core.WorkloadNodeControlSurfaceDescriptor(
        core.NodeControlGraphReference(core.NodeControlGraphReferenceRole.PROVIDER_SOCKET, "control"),
        (), (core.NodeHealthReadKind.LIVENESS, core.NodeHealthReadKind.READINESS))
    declaration = core.WorkloadNodeControlSurfaceDeclaration(surface,
        profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2)
    roles = core.NodeControlGraphReferenceRole
    target = core.NodeControlReceiverTarget(*(
        core.NodeControlGraphReference(role, value) for role, value in (
            (roles.WORKSPACE, "workspace"), (roles.RUNTIME, "docker"),
            (roles.NODE, "connector"), (roles.PROVIDER_SOCKET, "control"))), "b" * 32)
    world.receiver = receiver_configuration(target, declaration, key("managed-native")[1])
    world.artifact = receiver_artifact(world.receiver, "cloudflared-control", TARGET)
    contract = replace(world.material.product.runtime_contract,
        sockets=BlockSockets(providers=(ProviderSocket("control", Protocol.HTTP),)),
        provider_ports=(ProviderRuntimePort("control", 8000),),
        capabilities=(CapabilityName.HEALTH_CHECKABLE, CapabilityName.NODE_CONTROLLABLE),
        control_surfaces=(surface,), public_environment=ENVIRONMENT,
        configuration_requirements=(ConfigurationArtifactRequirement(
            "cloudflared-control", TARGET, ConfigurationMediaType.JSON, ConfigurationFileMode.READ_ONLY),),
        secret_deliveries=())
    product = replace(world.material.product, runtime_contract=contract)
    world.document = ProductDescriptorCodec().encode_document(product)
    world.reference = ProductReference.from_document(world.document)
    actual = replace(contract, configuration_requirements=(), configuration_artifacts=(world.artifact,),
                     secret_deliveries=(world.file,))
    world.material = replace(world.material, reference=world.reference,
        product=replace(product, runtime_contract=actual), public_environment=ENVIRONMENT)
    for side in ("current", "desired"):
        graph = getattr(world, side).graph
        if "connector" not in graph.nodes:
            continue
        node = graph.nodes["connector"]
        node = replace(node, block_spec=replace(node.block_spec,
            capabilities=contract.capabilities, control_surfaces=(surface,)),
            sockets=contract.sockets, public_environment=ENVIRONMENT,
            endpoints={"control": Endpoint(LiteralAddress("http://connector:8000"), Protocol.HTTP)},
            configuration_artifacts=(world.artifact,),
            metadata={"product_identity": world.reference.identity.key,
                      "product_descriptor_digest": world.reference.descriptor_sha256.value})
        setattr(world, side, validate_graph(graph.update_node(node)))
    world.request = replace(world.request, products=(world.material,))
    if retained:
        ref = ConfigurationInstanceRef("managed-allocation", "workspace", "docker", "connector",
            world.artifact.artifact_id, TARGET, world.artifact.media_type,
            world.artifact.file_mode, world.artifact.content_digest)
        world.installation_request = replace(world.installation_request,
            kind=RuntimeEffectKind.CONFIGURATION_ACTIVITY_V1, products=(world.material,),
            configuration_instances=ConfigurationInstanceSelection((ref,)))
        world.install_receipt()
        world.configuration_volume = configuration_volume_name(ref)
        world.recompile_retained()
    else:
        world.configuration_volume = "observed-candidate-without-allocation-claim"
        world.recompile()
    for config in [world.image["Config"], *(value["Config"] for value in world.containers)]:
        config.update(Entrypoint=["python", "-m", "control_plane_kit_servers_cloudflared_connector.entrypoint"],
                      Cmd=[], WorkingDir="/app")
        config["Env"].append("CPK_WRAPPER_CONFIGURATION_FILE=" + TARGET)
    origin = world.installation_request if retained else world.request
    for container in world.containers:
        container["Config"]["Labels"] = _node_labels(origin, world.material)
        container.update(Path="python", Args=container["Config"]["Entrypoint"][1:])
        container["HostConfig"]["Mounts"].append({"Type": "volume", "Source": world.configuration_volume,
            "Target": TARGET, "ReadOnly": True, "VolumeOptions": {"Subpath": "content"}})
        container["Mounts"].append({"Type": "volume", "Name": world.configuration_volume,
            "Destination": TARGET, "RW": False})
    world.archive = archive_bytes(name="control.json", body=world.artifact.content.encode())
    world.archive_error = None
    world.archive_calls = []
    world.archive_after_read = None
    def get(identity):
        world.archive_calls.append(("get", identity))
        if identity != CONTAINER_ID:
            raise AssertionError("only captured ID may be read")
        resource = SimpleNamespace(attrs=deepcopy(world.containers[0]), id=CONTAINER_ID)
        def reload():
            resource.attrs = deepcopy(world.containers[0])
        def read(path):
            world.archive_calls.append(("archive", path))
            if world.archive_error:
                raise world.archive_error
            if world.archive_after_read:
                world.archive_after_read()
                resource.attrs = deepcopy(world.containers[0])
            return [world.archive], {}
        resource.reload, resource.get_archive = reload, read
        return resource
    old_connect = world.client.docker_module.from_env
    def connect():
        raw = old_connect()
        raw.containers = SimpleNamespace(get=get)
        return raw
    world.client.docker_module.from_env = connect
    if world.client.client is not None:
        world.client.client.containers = SimpleNamespace(get=get)
    return world


def observer(world, *, managed=True, clock=None):
    options = dict(client=world.client, product_reference=world.reference,
        image_reference=world.material.product.image.execution_reference,
        clock=clock or (lambda: world.now))
    if managed:
        options["profile"] = module.ConnectorConnectionProfile.MANAGED_WRAPPER_V1
    return module.DockerConnectorConnectionObserver(**options)


def observe(world, **changes):
    options = dict(request=world.request, plan=world.plan, current=world.current, desired=world.desired)
    if isinstance(world, RetainedWorld):
        options.update(installation_request=world.installation_request,
                       installation_receipt=world.installation_receipt)
    options.update(changes)
    return observer(world).observe(**options)
