"""Source-only Core#2089/SKD/signing units, never actual operation history.

The explicit test.sh local-core phase supplies Core's own immutable supplied-
binding fixture; no Core/Operations state machine or persistent row is emulated.
Docker/HTTP transport fixtures are external doubles. They do not prove SQL.
"""
from dataclasses import replace
from io import BytesIO
import json
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx
import control_plane_kit_core as core
from control_plane_kit_core.configuration_instances import ConfigurationInstanceSelection
from control_plane_kit_core.products import ProductDescriptorCodec, ProductIdentity, ProductReference, ProductRuntimeContract, ProviderRuntimePort
from control_plane_kit_core.algebra import BlockSockets, ProviderSocket
from control_plane_kit_core.configuration import ConfigurationArtifact, ConfigurationMediaType, ConfigurationFileMode
from control_plane_kit_core.types import Protocol, RuntimeKind
from control_plane_kit_core.receiver_health_read_results import ReceiverHealthReadResult
from control_plane_kit_core.secret_installation import secret_installation_correlation_for_request, secret_material_selection_fingerprint
from control_plane_kit_core.secret_version_grants import SecretVersionResolutionGrant
from control_plane_kit_core.secrets import SecretResolved, SecretValue, SecretProviderEndpointReference, SecretReference
from control_plane_kit_core.runtime_authority import RuntimeAuthorityReference
from control_plane_kit_core.runtime_management import GatewayTransitProtocol, GatewayTransitDeclaration
from control_plane_kit_interpreters.docker.configuration import _container_incarnation_fingerprint, configuration_volume_name
from control_plane_kit_interpreters.docker.runtime import (
    DockerRuntimeInterpreter, _container_name, _network_name, _node_labels, _runtime_labels, _secret_volume_name,
)
from control_plane_kit_interpreters.invocations import InvocationPortError
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient
from control_plane_kit_interpreters.secrets import SecretFileRuntimeMaterial
from control_plane_kit_interpreters.probes.health_signing import (
    HealthSigningContext, HealthSigningKey, Ed25519HealthCredentialPairSigner,
)
from control_plane_kit_interpreters.probes.health_transport import SignedGatewayHealthClient, SelectedManagementGateway
from control_plane_kit_interpreters.probes.postgres_readiness_check import (
    PostgresReadinessCheckInput, PostgresReadinessRouteInput, PostgresReadinessCheckExecutor, PostgresReadinessCheckUnavailable,
)
from control_plane_kit_servers_cpk_local_gateway.health_relay_configuration import (
    ARTIFACT_ID as ROUTE_ARTIFACT_ID, CONFIGURATION_PATH as ROUTE_PATH,
)
from control_plane_kit_servers_cpk_local_gateway.health_transit_configuration import (
    GatewayHealthTransitConfiguration, gateway_health_transit_configuration_artifact,
)
from tests.test_postgres_readiness import supplied_binding
from health_signing_fixtures import world, private_pem
from health_transport_fixtures import Resolver
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule, FakeResource, FakeImage
from test_health_invocations import RecordingPort


NETWORK, GATEWAY, POSTGRES = (marker * 64 for marker in "abc")


class ReadbackResource(FakeResource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.files = {}

    def reload(self):
        pass

    def get_archive(self, path):
        raw, mode, uid = self.files[path]
        stream = BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            member = tarfile.TarInfo(path.rsplit("/", 1)[-1])
            member.size, member.mode, member.uid, member.gid = len(raw), mode, uid, uid
            archive.addfile(member, BytesIO(raw))
        return [stream.getvalue()], {}


def mounted(resource, path, volume, raw, mode, uid=0):
    resource.attrs["Mounts"].append(dict(Type="volume", Name=volume, Destination=path, RW=False))
    resource.attrs["HostConfig"].setdefault("Mounts", []).append(dict(Type="volume", Source=volume,
        Target=path, ReadOnly=True, VolumeOptions={"Subpath": "content"}))
    resource.files[path] = (raw, mode, uid)


class NativePostgresReadinessSourceTests(unittest.TestCase):
    def setUp(self):
        self.now_ms, self.ticks = 100_010, 0.0
        self.events, self.resolved, self.posts = [], [], []
        signing = world()
        base = supplied_binding()
        receiver = replace(base.receiver, verifiers=tuple(replace(value,
            issuer="workload-issuer", public_keys=(signing.publics[1],))
            if value.purpose is core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ else value
            for value in base.receiver.verifiers))
        material = base.installation.products[0]
        artifact = replace(material.product.runtime_contract.configuration_artifacts[0],
            content=core.ReceiverNodeControlConfigurationCodec().encode_bytes(receiver).decode())
        product = replace(material.product, runtime_contract=replace(material.product.runtime_contract,
            configuration_artifacts=(artifact,)))
        material = replace(material, product=product,
            reference=ProductReference.from_document(ProductDescriptorCodec().encode_document(product)))
        allocation, = base.installation.configuration_instances.instances
        install = replace(base.installation, products=(material,), authority_ref=RuntimeAuthorityReference("local-docker"), configuration_instances=
            ConfigurationInstanceSelection((replace(allocation, content_digest=artifact.content_digest),)))
        receipt = replace(base.receipt,
            request_fingerprint=secret_installation_correlation_for_request(install).request_fingerprint,
            selection_fingerprint=secret_material_selection_fingerprint(install),
            current_realization_fingerprint=_container_incarnation_fingerprint(POSTGRES))
        self.binding = binding = replace(base, wait=replace(base.wait, products=(material,), authority_ref=install.authority_ref),
            installation=install, receipt=receipt, receiver=receiver,
            observer=replace(base.observer, product=material.reference))
        request = binding.request()
        gateway = replace(receiver.target, node_id=replace(receiver.target.node_id, value="gateway-a"), receiver_id="b" * 32)
        common = dict(target=receiver.target, authority_context=request.authority_context, kind=request.kind,
            declaration_identity=request.declaration_identity, request_id=request.request_id,
            request_digest=request.canonical_digest(), issued_at=100, not_before=100, expires_at=105)
        transit = replace(signing.transit, gateway_target=gateway, **common)
        workload = replace(signing.workload, audience=core.receiver_node_control_audience(receiver.target), **common)
        resolutions = tuple(replace(value, workspace_id=binding.wait.source.workspace_id,
            run_id=binding.wait.source.run_id.value, activity_id=binding.wait.activity_id.value)
            for value in signing.resolutions)
        password = SecretVersionResolutionGrant("suse_" + "c" * 64, binding.wait.source.workspace_id,
            "sref_" + "c" * 64, "sprov_" + "c" * 64,
            SecretProviderEndpointReference("local"), SecretReference("secret://bootstrap/provider-token"),
            material.secret_selections[0], "actor-a", "password-correlation", "c" * 64,
            binding.wait.source.request_id, binding.wait.source.run_id.value, binding.wait.activity_id.value,
            binding.wait.effect_id, binding.descriptor()["request_fingerprint"], receipt.selection_fingerprint, "session-a")
        ingress = core.NamedPublicIngress("management", core.IngressAuthorityReference("fixture-zone"),
            core.PublicIngressTarget("gateway-a", "control"), "connector-a", "gateway.example.invalid")
        control_port, = (port.container_port for port in product.runtime_contract.provider_ports
            if port.provider_socket == receiver.target.provider_socket_name.value)
        route = core.ReceiverManagementRouteBinding("pg-management", receiver.target, receiver.declaration,
            f"http://{receiver.target.node_id.value}:{control_port}")
        route_artifact = ConfigurationArtifact(ROUTE_ARTIFACT_ID, ROUTE_PATH, ConfigurationMediaType.JSON,
            core.ReceiverManagementRoutesCodec().encode_bytes(core.ReceiverManagementRoutes(gateway, (route,))).decode(),
            ConfigurationFileMode.READ_ONLY)
        transit_artifact = gateway_health_transit_configuration_artifact(GatewayHealthTransitConfiguration(
            gateway, transit.issuer, transit.purpose, (signing.publics[0],)))
        gateway_product = ProductDescriptorCodec().encode_document(replace(product,
            identity=ProductIdentity("synthetic", "gateway", 1),
            image=replace(product.image, repository="gateway"),
            runtime_contract=ProductRuntimeContract(
                sockets=BlockSockets(providers=(ProviderSocket("control", Protocol.HTTP),)),
                provider_ports=(ProviderRuntimePort("control", 8000),),
                configuration_artifacts=(transit_artifact, route_artifact),
                gateway_transit=GatewayTransitDeclaration("control", GatewayTransitProtocol.RECEIVER_HEALTH_READ_V2))))
        self.prepared = PostgresReadinessCheckInput(binding, password,
            HealthSigningContext(request, transit.attempt_id, gateway, receiver.declaration, transit.issuer, workload.issuer),
            HealthSigningKey(signing.publics[0], resolutions[0]), HealthSigningKey(signing.publics[1], resolutions[1]),
            transit, workload, SelectedManagementGateway(ingress, gateway.node_id, "control", gateway.runtime_id,
                route.target_id, GatewayTransitProtocol.RECEIVER_HEALTH_READ_V2), route, gateway_product,
            route_artifact, transit_artifact)
        password_value = SecretValue("synthetic-source-password")
        values = {password.selection.reference: password_value,
            **{value.reference: SecretValue(private_pem(key)) for value, key in zip(resolutions, signing.privates)}}
        def resolve(grant):
            self.resolved.append(grant.authorization_id)
            reference = grant.selection.reference if type(grant) is SecretVersionResolutionGrant else grant.reference
            return SecretResolved(reference, values[reference])
        self.resolver = SimpleNamespace(resolve=resolve)
        async def response(http_request):
            self.posts.append(json.loads(await http_request.aread())["request"]["request_id"])
            if self.after_response:
                self.after_response()
            return httpx.Response(200, json=ReceiverHealthReadResult(
                request, receiver.declaration, core.NodeHealthReadOutcome.HEALTHY).descriptor())
        self.after_response = None
        self.executor = PostgresReadinessCheckExecutor(self.resolver,
            Ed25519HealthCredentialPairSigner(self.resolver, lambda:self.now_ms // 1000),
            SignedGatewayHealthClient(lambda:self.now_ms // 1000, Resolver(), httpx.MockTransport(response)),
            lambda:self.now_ms, object(), lambda:self.ticks)
        self.child = RecordingPort(self.events)
        self.child.prepare_postgres_readiness = lambda:self.prepared
        self.raw = FakeDockerClient()
        self.docker = DockerSdkClient(docker_module=FakeDockerModule(self.raw))
        self.net = FakeResource(_network_name(binding.wait, material.runtime_id), labels=_runtime_labels(binding.wait, material.runtime_id))
        self.net.attrs.update(Id=NETWORK, Containers={GATEWAY: {}, POSTGRES: {}})
        self.raw.networks.resources[self.net.name] = self.net
        def member(identity, node, selected_product, labels):
            image_id = "sha256:" + ("1" if identity == POSTGRES else "2") * 64
            ref = selected_product.image.execution_reference
            image = FakeImage([ref], image_id=image_id)
            image.attrs.update(RepoDigests=[ref], Config={"User":"70:70"})
            self.raw.images.resources[ref] = image
            resource = ReadbackResource(_container_name(binding.wait, node), labels=labels, image=ref, image_id=image_id, running=True)
            resource.attrs.update(Id=identity, Image=image_id)
            resource.attrs["Config"].update(User="70:70", Env=[])
            resource.attrs["State"]["StartedAt"] = "2026-11-08T16:00:00Z"
            resource.attrs["NetworkSettings"]["Networks"] = {self.net.name: {"NetworkID":NETWORK,
                "IPAddress":"10.0.0.3" if identity == POSTGRES else "10.0.0.2", "Aliases":[node],
                "DNSNames":[node, identity[:12]]}}
            self.raw.containers.resources[resource.name] = self.raw.containers.resources[identity] = resource
            return resource
        self.pg = member(POSTGRES, material.node_id, product, _node_labels(install, material))
        gateway_material = replace(material, node_id=gateway.node_id.value, product=gateway_product.product,
            reference=ProductReference.from_document(gateway_product), secret_selections=())
        self.gateway = member(GATEWAY, gateway.node_id.value, gateway_product.product, _node_labels(binding.wait, gateway_material))
        delivery, = product.runtime_contract.secret_deliveries
        secret = SecretFileRuntimeMaterial(delivery.reference, delivery.target_path, password_value,
            delivery.file_mode, delivery.path_binding.environment_name, material.secret_selections[0])
        self.pg.attrs["Config"]["Env"] = [f"{value.name}={value.value}" for value in material.public_environment] + [
            f"{delivery.path_binding.environment_name}={delivery.target_path}"]
        mounted(self.pg, delivery.target_path, _secret_volume_name(install, material.node_id, secret, owner_uid=70),
            password_value.reveal().encode(), int(delivery.file_mode.value, 8), 70)
        mounted(self.pg, artifact.target_path, configuration_volume_name(install.configuration_instances.instances[0]),
            artifact.content.encode(), int(artifact.file_mode.value, 8))
        for value in (route_artifact, transit_artifact):
            mounted(self.gateway, value.target_path, "gateway-" + value.artifact_id, value.content.encode(), int(value.file_mode.value, 8))

    def execute(self):
        return self.executor.execute(self.binding.wait,
            self.binding.wait.products[0].product.runtime_contract.verification.checks[0], self.child, docker=self.docker,
            acquired=self.acquired())

    def acquired(self):
        value = self.prepared
        return PostgresReadinessRouteInput(self.binding.request().authority_context, self.binding.receiver,
            value.destination, value.route, value.gateway_product, value.gateway_route_artifact, value.gateway_transit_artifact)

    def test_registered_gateway_declared_slots_accept_exact_selected_mount_bytes(self):
        from control_plane_kit_core.configuration import ConfigurationArtifactRequirement
        document = self.prepared.gateway_product
        contract = document.product.runtime_contract
        declared = replace(contract, configuration_artifacts=(), configuration_requirements=tuple(
            ConfigurationArtifactRequirement(value.artifact_id, value.target_path, value.media_type, value.file_mode)
            for value in contract.configuration_artifacts))
        document = ProductDescriptorCodec().encode_document(replace(document.product, runtime_contract=declared))
        self.prepared = replace(self.prepared, gateway_product=document)
        # Physical labels name the selected registered descriptor, not the
        # previous source-concrete descriptor with bytes embedded.
        reference = ProductReference.from_document(document)
        self.gateway.attrs["Config"]["Labels"].update({
            "org.openj92.cpk.descriptor": reference.descriptor_sha256.value})
        self.assertEqual(self.execute()["check_id"], self.binding.check_id)

    def runtime(self):
        support = SimpleNamespace(http_samples=None)
        executor = replace(self.executor, managed_verification_support=support)
        parent = RecordingPort(self.events)
        parent.managed_verification_support = support
        parent.for_check = lambda check_id:self.child
        parent.acquire_managed_verification_route = self.acquired
        adapter = DockerRuntimeInterpreter(client=self.docker, postgres_readiness_executor=executor,
            require_invocations=True)
        authority = SimpleNamespace(runtime_kind=RuntimeKind.DOCKER, authority_kind="local-docker-socket")
        return adapter, parent, authority

    def test_registered_runtime_arm_returns_sql_evidence_without_http_observations_or_private_probe(self):
        adapter, parent, authority = self.runtime()
        with patch.object(DockerRuntimeInterpreter, "_runtime_private_endpoint_observations") as private, \
                patch.object(DockerRuntimeInterpreter, "_execute_postgres_health_check") as sql:
            result = adapter.execute_with_authority(self.binding.wait, authority, invocations=parent)
        private.assert_not_called()
        sql.assert_not_called()
        self.assertEqual(result.kind.value, "succeeded")
        self.assertEqual(result.observations, ())
        self.assertEqual(result.evidence["postgres_readiness_checks"][0]["check_id"], self.binding.check_id)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual([value[1] for value in self.events if value[0] == "admit"],
            ["ordinary-verification-acquisition"] + ["secret-resolution"] * 3 + ["ordinary-verification-check"])

    def test_changed_runtime_support_refuses_before_resolution_or_dispatch(self):
        adapter, parent, authority = self.runtime()
        parent.managed_verification_support = object()
        with self.assertRaises(InvocationPortError):
            adapter.execute_with_authority(self.binding.wait, authority, invocations=parent)
        self.assertEqual(self.resolved, [])
        self.assertEqual(self.posts, [])

    def test_remote_authority_and_ambient_execution_never_fall_through_to_sql(self):
        adapter, parent, authority = self.runtime()
        authority.authority_kind = "remote-docker-tls"
        result = adapter.execute_with_authority(self.binding.wait, authority, invocations=parent)
        self.assertEqual(result.kind.value, "unsupported")
        result = adapter.execute(self.binding.wait, invocations=parent)
        self.assertEqual(result.kind.value, "unsupported")
        self.assertEqual(self.resolved, [])
        self.assertEqual(self.posts, [])

    def test_managed_profile_keeps_existing_all_http_sampling_arm(self):
        from test_native_http_sample import NativeHttpSampleTests
        case = NativeHttpSampleTests()
        case.setUp()
        support = SimpleNamespace(http_samples=case.support)
        case.interpreter = replace(case.interpreter,
            postgres_readiness_executor=replace(self.executor, managed_verification_support=support))
        case.parent.managed_verification_support = support
        result = case.execute()
        self.assertEqual(result.kind.value, "succeeded")
        self.assertEqual(len(case.posts), 2)
        self.assertNotIn("postgres_readiness_checks", result.evidence)

    def test_passive_connection_qualifier_requires_actual_sql_observer_for_complete_mixed_plan(self):
        from tests.test_managed_verification_planning import mixed_graph
        from tests.test_management_bootstrap_planning import empty
        from test_native_http_sample import NativeHttpSampleTests
        from docker_connector_fixtures import World
        from control_plane_kit_core.topology import validate_graph
        from control_plane_kit_interpreters.docker.connector_connection import (
            DockerConnectorConnectionQualifier, ConnectorConnectionQualification,
        )
        world = World()
        document = ProductDescriptorCodec().encode_document(replace(world.material.product,
            runtime_contract=replace(world.material.product.runtime_contract, secret_deliveries=())))
        reference = ProductReference.from_document(document)
        graph = mixed_graph()
        connector = graph.node("connector")
        graph = graph.update_node(replace(connector, metadata={"product_identity": reference.identity.key,
            "product_descriptor_digest": reference.descriptor_sha256.value}))
        postgres = graph.node("postgres")
        observer = self.binding.observer
        graph = graph.update_node(replace(postgres, metadata={"product_identity": observer.product.identity.key,
            "product_descriptor_digest": observer.product.descriptor_sha256.value}))
        runtime = graph.runtimes[postgres.runtime_id]
        authority = RuntimeAuthorityReference("fixture-local-docker")
        graph = replace(graph, runtimes={**graph.runtimes,
            runtime.runtime_id:replace(runtime, authority_ref=authority)})
        current, desired = validate_graph(empty()), validate_graph(graph)
        current.require_valid()
        desired.require_valid()
        plan = core.compile_managed_verification_bootstrap_activity_plan(current, desired)
        self.assertTrue(plan.ready_for_execution)
        activity, = (item for item in plan.activities if type(item.operation) is core.ObserveManagementBootstrap
            and item.operation.stage is core.ManagementBootstrapStage.CONNECTOR_CONNECTED)
        case = NativeHttpSampleTests()
        case.setUp()
        support = SimpleNamespace(http_samples=case.support, postgres_observers=(observer,))
        qualifier = DockerConnectorConnectionQualifier(reference, document.product.image.execution_reference,
            http_sample_executor=case.executor,
            postgres_readiness_executor=replace(self.executor, managed_verification_support=support))
        inputs = dict(activity_id=activity.activity_id, plan=plan, current=current, desired=desired,
            product_document=document, authority_ref=authority)
        self.assertIs(qualifier.qualify_shape(**inputs), ConnectorConnectionQualification.FRESH)
        wrong = replace(observer, product=replace(observer.product,
            descriptor_sha256=replace(observer.product.descriptor_sha256, value="9" * 64)))
        changed = replace(qualifier, postgres_readiness_executor=replace(self.executor,
            managed_verification_support=SimpleNamespace(http_samples=case.support, postgres_observers=(wrong,))))
        self.assertIsNone(changed.qualify_shape(**inputs))
        self.assertEqual(self.posts, [])
        self.assertEqual(self.resolved, [])

    def test_one_check_emits_only_original_bounded_sql_evidence_after_real_sdk_and_signing(self):
        item = self.execute()
        self.assertEqual(set(item), {"profile", "check_id", "result", "observed_at_epoch_ms"})
        self.assertEqual(item["profile"], "cpk.original-postgres-readiness.v1")
        self.assertEqual(item["check_id"], self.binding.check_id)
        self.assertEqual(item["observed_at_epoch_ms"], self.now_ms)
        self.assertEqual(len(self.posts), 1)
        expected = [self.prepared.password_grant.authorization_id,
            self.prepared.transit_key.resolution_grant.authorization_id,
            self.prepared.workload_key.resolution_grant.authorization_id]
        self.assertEqual(self.resolved, expected)
        self.assertEqual([event[1] for event in self.events if event[0] == "admit"],
            ["secret-resolution"] * 3 + ["ordinary-verification-check"])

    def test_wrong_password_bytes_never_send(self):
        path = self.binding.observer.password_path
        _, mode, uid = self.pg.files[path]
        self.pg.files[path] = (b"different-password", mode, uid)
        with self.assertRaises(PostgresReadinessCheckUnavailable):
            self.execute()
        self.assertEqual(self.posts, [])

    def test_same_container_restart_after_response_never_returns_success_evidence(self):
        self.after_response = lambda:self.pg.attrs["State"].update(StartedAt="2026-11-08T16:00:01Z")
        with self.assertRaises(PostgresReadinessCheckUnavailable):
            self.execute()
        self.assertEqual(len(self.posts), 1)

    def test_expired_original_window_refuses_before_roles_or_send(self):
        self.now_ms = self.binding.deadline_epoch_ms
        with self.assertRaises(PostgresReadinessCheckUnavailable):
            self.execute()
        self.assertEqual(self.posts, [])
        self.assertEqual(self.resolved, [])

    def test_crossed_selected_version_grant_refuses_before_resolution(self):
        self.prepared = replace(self.prepared, password_grant=replace(self.prepared.password_grant,
            selection=replace(self.prepared.password_grant.selection, version_id="different-version")))
        with self.assertRaises(PostgresReadinessCheckUnavailable):
            self.execute()
        self.assertEqual(self.resolved, [])
        self.assertEqual(self.posts, [])

    def test_unknown_network_dns_names_never_send(self):
        self.pg.attrs["NetworkSettings"]["Networks"][self.net.name].pop("DNSNames")
        with self.assertRaises(PostgresReadinessCheckUnavailable):
            self.execute()
        self.assertEqual(self.posts, [])

    def test_password_change_after_response_never_returns_success_evidence(self):
        def change():
            path = self.binding.observer.password_path
            _, mode, uid = self.pg.files[path]
            self.pg.files[path] = (b"different-password", mode, uid)
        self.after_response = change
        with self.assertRaises(PostgresReadinessCheckUnavailable):
            self.execute()
        self.assertEqual(len(self.posts), 1)

    def test_late_actual_response_never_returns_success_evidence(self):
        self.after_response = lambda:setattr(self, "now_ms", self.binding.deadline_epoch_ms)
        with self.assertRaises(PostgresReadinessCheckUnavailable):
            self.execute()
        self.assertEqual(len(self.posts), 1)
