"""Pure compiled graph plus recording SDK; no authority or workflow emulator."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from types import SimpleNamespace

import control_plane_kit_core as core
from control_plane_kit_core.algebra import BlockSockets, BlockSpec, ProviderSocket
from control_plane_kit_core.capabilities import CapabilityName
from control_plane_kit_core.operations.run_identity import RunId
from control_plane_kit_core.products import (
    ContainerServerProduct, OciImageReference, ProductIdentity, ProductReference,
    ProductDescriptorDigest, ProductRuntimeContract,
)
from control_plane_kit_core.public_ingress import NamedPublicIngress, IngressAuthorityReference, PublicIngressTarget
from control_plane_kit_core.runtime_effects import RuntimeEffectRequest, RuntimeEffectKind, RuntimeEffectSource, RuntimeProductMaterial
from control_plane_kit_core.runtime_authority import RuntimeAuthorityReference
from control_plane_kit_core.secrets import SecretFileDelivery, SecretFilePathBinding, SecretReference, SecretUseIntent
from control_plane_kit_core.secret_selections import SecretVersionSelection
from control_plane_kit_core.topology import DeploymentGraph, Node, RuntimeRecord, validate_graph
from control_plane_kit_core.topology.graph import Endpoint, LiteralAddress
from control_plane_kit_core.types import BlockFamily, Protocol, RuntimeKind
from control_plane_kit_interpreters.docker.runtime import _container_name, _network_name, _node_labels, _secret_volume_name
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient


CONTAINER_ID = "c" * 64
IMAGE_ID = "sha256:" + "d" * 64
NATIVE_ID = "ae232234-79c8-48fe-9b67-123456789abc"
HEALTHCHECK = {"Test": ["CMD", "python", "-m", "control_plane_kit_servers_cloudflared_connector.readiness"],
               "Interval": 5_000_000_000, "Timeout": 3_000_000_000, "Retries": 1}


def sample(outcome="connected", *, start="2026-09-24T12:00:00.000000001Z", end="2026-09-24T12:00:01.000000001Z"):
    value = {"schema": "cpk.cloudflared.connection/v1", "outcome": outcome}
    if outcome == "unknown":
        value["reason"] = "timeout"
    else:
        value.update(readyConnections=4 if outcome == "connected" else 0, connectorId=NATIVE_ID)
    return {"Start": start, "End": end, "ExitCode": 0 if outcome == "connected" else 1,
            "Output": json.dumps(value, separators=(",", ":")) + "\n"}


class RecordingApi:
    def __init__(self, world):
        self.world, self.timeout, self.calls = world, 60, []

    def inspect_container(self, identity):
        self.calls.append(("container", identity))
        if self.world.error:
            raise self.world.error
        index = sum(kind == "container" for kind, _ in self.calls) - 1
        value = deepcopy(self.world.containers[min(index, 1)])
        if self.world.after_read:
            self.world.after_read(len(self.calls))
        return value

    def inspect_image(self, identity):
        self.calls.append(("image", identity))
        value = deepcopy(self.world.image)
        if self.world.after_read:
            self.world.after_read(len(self.calls))
        return value


class World:
    def __init__(self, *, lazy=False):
        self.now = datetime(2026, 9, 24, 12, 0, 2, tzinfo=timezone.utc)
        self.file = SecretFileDelivery("/run/secrets/tunnel", SecretReference("secret://fixture/tunnel"),
            SecretUseIntent.CLOUDFLARE_TUNNEL_TOKEN, path_binding=SecretFilePathBinding("TUNNEL_TOKEN_FILE"))
        product = ContainerServerProduct(ProductIdentity("fixture", "native-reader", 1),
            OciImageReference("ghcr.io", "fixture/reader", "sha256:" + "a" * 64),
            ProductRuntimeContract(secret_deliveries=(self.file,)))
        self.reference = ProductReference(product.identity, ProductDescriptorDigest("b" * 64))
        self.material = RuntimeProductMaterial("connector", "docker", self.reference, product,
            secret_selections=(SecretVersionSelection(self.file.reference, self.file.intent, "fixture-version"),))
        control = core.WorkloadNodeControlSurfaceDescriptor(
            core.NodeControlGraphReference(core.NodeControlGraphReferenceRole.PROVIDER_SOCKET, "control"),
            (), (core.NodeHealthReadKind.READINESS,))
        gateway = Node("gateway", BlockFamily.APPLICATION,
            BlockSpec("gateway", capabilities=(CapabilityName.NODE_CONTROLLABLE, CapabilityName.HEALTH_CHECKABLE),
                control_surfaces=(control,), gateway_transit=core.GatewayTransitDeclaration("transit", core.GatewayTransitProtocol.RECEIVER_HEALTH_READ_V2)),
            "container-server", "docker", BlockSockets(providers=(ProviderSocket("control", Protocol.HTTP), ProviderSocket("transit", Protocol.HTTP))),
            endpoints={name: Endpoint(LiteralAddress("http://gateway:8000"), Protocol.HTTP) for name in ("control", "transit")})
        connector = Node("connector", BlockFamily.APPLICATION, BlockSpec("connector"), "container-server", "docker", BlockSockets(),
            metadata={"product_identity": self.reference.identity.key, "product_descriptor_digest": self.reference.descriptor_sha256.value})
        self.ingress = NamedPublicIngress("management", IngressAuthorityReference("ingress-authority"),
            PublicIngressTarget("gateway", "transit"), "connector", "fixture.example.invalid")
        self.current = validate_graph(DeploymentGraph("native"))
        self.desired = validate_graph(DeploymentGraph("native", nodes={"gateway": gateway, "connector": connector},
            runtimes={"docker": RuntimeRecord("docker", RuntimeKind.DOCKER, ("gateway", "connector"),
                authority_ref=RuntimeAuthorityReference("docker-authority"),
                management=core.RuntimeManagement("gateway", "management"))}, public_ingresses=(self.ingress,)))
        self.current.require_valid()
        self.desired.require_valid()
        self.plan = core.compile_graph_activity_plan(self.current, self.desired)
        if not self.plan.ready_for_execution:
            raise AssertionError("pure native graph must compile")
        activity, = (item for item in self.plan.activities if type(item.operation) is core.ObserveManagementBootstrap
                     and item.operation.stage is core.ManagementBootstrapStage.CONNECTOR_CONNECTED)
        self.request = RuntimeEffectRequest("event-native", RuntimeEffectKind.REALIZE_ACTIVITY, RuntimeKind.DOCKER,
            RuntimeEffectSource("workspace", "request", RunId("run-native"), "plan-native", "base", "desired", "event-native"),
            activity.activity_id, activity.operation, RuntimeAuthorityReference("docker-authority"), products=(self.material,))
        self.name = _container_name(self.request, "connector")
        self.network = _network_name(self.request, "docker")
        self.volume = _secret_volume_name(self.request, "connector", self.file, owner_uid=65532)
        config = {"Entrypoint": ["cloudflared", "--no-autoupdate", "--metrics", "127.0.0.1:20241"],
            "Cmd": ["tunnel", "run"], "User": "65532:65532", "WorkingDir": "", "StopSignal": "SIGTERM",
            "Healthcheck": deepcopy(HEALTHCHECK), "Env": ["PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONPATH=/app/products/cloudflared_connector/src"], "Shell": None, "Volumes": None}
        self.image = {"Id": IMAGE_ID, "RepoDigests": [product.image.execution_reference], "Config": deepcopy(config)}
        config["Env"].append("TUNNEL_TOKEN_FILE=" + self.file.target_path)
        config["Labels"] = _node_labels(self.request, self.material)
        container = {"Id": CONTAINER_ID, "Name": "/" + self.name, "Image": IMAGE_ID, "Config": config,
            "Path": "cloudflared", "Args": config["Entrypoint"][1:] + config["Cmd"],
            "State": {"Running": True, "Paused": False, "Restarting": False,
                "StartedAt": "2026-09-24T11:59:00Z", "Health": {"Status": "unhealthy", "Log": [sample()]}},
            "HostConfig": {"NetworkMode": self.network, "Binds": None, "Tmpfs": None, "VolumesFrom": None,
                "Mounts": [{"Type": "volume", "Source": self.volume, "Target": self.file.target_path,
                    "ReadOnly": True, "VolumeOptions": {"Subpath": "content"}}]},
            "NetworkSettings": {"Networks": {self.network: {}}},
            "Mounts": [{"Type": "volume", "Name": self.volume, "Destination": self.file.target_path, "RW": False}]}
        self.containers = [container, deepcopy(container)]
        self.api, self.error, self.after_read = RecordingApi(self), None, None
        self.initializations = []
        def connect():
            self.initializations.append("factory/version-negotiation")
            return SimpleNamespace(api=self.api)
        self.client = DockerSdkClient(client=None if lazy else SimpleNamespace(api=self.api),
            docker_module=SimpleNamespace(from_env=connect), connect_on_init=False)

    def observe(self, module, **changes):
        options = dict(request=self.request, plan=self.plan, current=self.current, desired=self.desired)
        options.update(changes)
        return module.DockerConnectorConnectionObserver(self.client, self.reference,
            self.material.product.image.execution_reference, lambda: self.now).observe(**options)

    def mutate(self, section, key, value, *, final_only=False):
        for container in self.containers[1:] if final_only else self.containers:
            container[section][key] = deepcopy(value)

    def recompile(self):
        self.current.require_valid()
        self.desired.require_valid()
        self.plan = core.compile_graph_activity_plan(self.current, self.desired)
        activity, = (item for item in self.plan.activities if type(item.operation) is core.ObserveManagementBootstrap
                     and item.operation.stage is core.ManagementBootstrapStage.CONNECTOR_CONNECTED)
        self.request = replace(self.request, operation=activity.operation, activity_id=activity.activity_id)


class RetainedWorld(World):
    """Actual public-content update and typed installation, not a ledger emulator."""

    def __init__(self, *, lazy=False, reconcile=False):
        super().__init__(lazy=lazy)
        from control_plane_kit_core.configuration import ConfigurationArtifact, ConfigurationMediaType
        from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
        from control_plane_kit_core.wrapper_configuration import WORKLOAD_NODE_CONTROL_CONFIGURATION_ENVIRONMENT
        from receiver_configuration_fixtures import receiver_configuration, receiver_artifact
        from health_signing_fixtures import key

        activity, = (item for item in self.plan.activities
            if type(item.operation) is core.StartNode and item.operation.target.node_id == "connector")
        self.installation_request = replace(self.request,
            effect_id="event-installation", source=replace(self.request.source,
                intent_event_id="event-installation", plan_id="plan-installation",
                desired_graph_id="graph-installation"),
            activity_id=activity.activity_id, operation=activity.operation)
        if reconcile:
            self.installation_request = replace(self.installation_request,
                operation=core.ReconcileNode(activity.operation.target))
        self.install_receipt()
        for container in self.containers:
            container["Config"]["Labels"] = _node_labels(self.installation_request, self.material)

        control = self.desired.graph.nodes["gateway"].block_spec.control_surfaces[0]
        roles = core.NodeControlGraphReferenceRole
        target = core.NodeControlReceiverTarget(*(
            core.NodeControlGraphReference(role, value) for role, value in (
                (roles.WORKSPACE, "workspace"), (roles.RUNTIME, "docker"),
                (roles.NODE, "workload"), (roles.PROVIDER_SOCKET, "control"))), "a" * 32)
        declaration = core.WorkloadNodeControlSurfaceDeclaration(control,
            profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2)
        self.receiver = receiver_configuration(target, declaration, key("native-health")[1])
        wrapper = receiver_artifact(self.receiver)
        application = ConfigurationArtifact("application", "/etc/application/settings.json",
            ConfigurationMediaType.JSON, '{"mode":"blue"}')
        workload = Node("workload", BlockFamily.APPLICATION,
            BlockSpec("workload", capabilities=(CapabilityName.NODE_CONTROLLABLE, CapabilityName.HEALTH_CHECKABLE),
                control_surfaces=(control,)), "container-server", "docker",
            BlockSockets(providers=(ProviderSocket("control", Protocol.HTTP),)),
            endpoints={"control": Endpoint(LiteralAddress("http://workload:8000"), Protocol.HTTP)},
            configuration_artifacts=(wrapper, application),
            public_environment=(PublicStaticEnvironmentBinding(
                WORKLOAD_NODE_CONTROL_CONFIGURATION_ENVIRONMENT, wrapper.target_path),))
        graph = self.desired.graph
        self.current = validate_graph(replace(graph, nodes={**graph.nodes, "workload": workload},
            runtimes={"docker": replace(graph.runtimes["docker"], children=("gateway", "connector", "workload"))}))
        self.desired = validate_graph(self.current.graph.update_node(replace(workload,
            configuration_artifacts=(wrapper, replace(application, content='{"mode":"green"}', source_digest=None)))))
        self.recompile_retained()
        self.request = replace(self.request, effect_id="event-observe-b", source=replace(self.request.source,
            intent_event_id="event-observe-b", request_id="request-b", run_id=RunId("run-b"),
            plan_id="plan-b", base_graph_id="graph-before-b", desired_graph_id="graph-b"))

    def install_receipt(self, *, disposition=None, container_id=CONTAINER_ID):
        from control_plane_kit_core.secret_installation import (
            SecretInstallationDisposition, SecretInstallationReceipt,
            secret_installation_correlation_for_request, secret_material_selection_fingerprint,
        )
        from control_plane_kit_interpreters.docker.configuration import _container_incarnation_fingerprint
        disposition = SecretInstallationDisposition.CREATED if disposition is None else disposition
        current = _container_incarnation_fingerprint(container_id)
        prior = (current if disposition is SecretInstallationDisposition.REUSED else
            _container_incarnation_fingerprint("e" * 64) if disposition is SecretInstallationDisposition.REPLACED else None)
        self.installation_receipt = SecretInstallationReceipt(
            secret_installation_correlation_for_request(self.installation_request).request_fingerprint,
            secret_material_selection_fingerprint(self.installation_request), disposition, prior, current)

    def recompile_retained(self, *, require_ready=True):
        self.current.require_valid()
        self.desired.require_valid()
        self.plan = core.compile_managed_update_activity_plan(self.current, self.desired)
        if require_ready and not self.plan.ready_for_execution:
            raise AssertionError("retained native fixture must compile")
        activities = tuple(item for item in self.plan.activities
            if type(item.operation) is core.ObserveManagementBootstrap
            and item.operation.stage is core.ManagementBootstrapStage.CONNECTOR_CONNECTED)
        if activities:
            activity, = activities
            self.request = replace(self.request, operation=activity.operation, activity_id=activity.activity_id)

    def observe(self, module, **changes):
        options = dict(installation_request=self.installation_request,
            installation_receipt=self.installation_receipt)
        options.update(changes)
        return super().observe(module, **options)
