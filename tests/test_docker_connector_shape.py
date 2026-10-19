"""#148 new-law query targets over Core values, without an Operations emulator."""
from dataclasses import replace
import unittest

import control_plane_kit_core as core
from control_plane_kit_core.configuration import ConfigurationArtifact, ConfigurationMediaType
from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
from control_plane_kit_core.lifecycle import ResourceLifecycle
from control_plane_kit_core.planning import ActivityId, ActivityPlan
from control_plane_kit_core.products import ProductDescriptorCodec, ProductReference, RetainedDataMount
from control_plane_kit_core.runtime_authority import RuntimeAuthorityAccessDelivery, RuntimeAuthorityAccessDeliveryKind
from control_plane_kit_core.secrets import SecretEnvironmentDelivery, SecretFilePathBinding, SecretReference, SecretUseIntent
from control_plane_kit_core.secret_selections import SecretVersionSelection, UnselectedSecretUse, author_secret_selections
from control_plane_kit_core.topology import validate_graph
from control_plane_kit_interpreters.docker.connector_connection import (
    ConnectorConnectionQualification, DockerConnectorConnectionObserver,
)
from docker_connector_fixtures import World, RetainedWorld


def bind_document(world, *, declared=(), authored=(), product=None):
    """Bind real canonical bytes to the existing pure graph; never resolve a secret."""
    product = product or replace(world.material.product,
        runtime_contract=replace(world.material.product.runtime_contract, secret_deliveries=declared))
    document = ProductDescriptorCodec().encode_document(product)
    world.reference = ProductReference.from_document(document)
    for side in ("current", "desired"):
        graph = getattr(world, side).graph
        if "connector" in graph.nodes:
            node = replace(graph.nodes["connector"], secret_deliveries=authored,
                secret_selections=author_secret_selections(authored, previous=world.material.secret_selections),
                metadata={"product_identity": world.reference.identity.key,
                    "product_descriptor_digest": document.content_digest})
            setattr(world, side, validate_graph(graph.update_node(node)))
    world.material = replace(world.material, reference=world.reference,
        product=replace(product, runtime_contract=replace(product.runtime_contract,
            secret_deliveries=(world.file,))))
    world.request = replace(world.request, products=(world.material,))
    if isinstance(world, RetainedWorld):
        world.recompile_retained()
    else:
        world.recompile()
    return document


def shape_world(world_type=World):
    world = world_type(lazy=True)
    world.file = replace(world.file, target_path="/run/secrets/cloudflare-tunnel-token")
    world.material = replace(world.material, secret_selections=(
        SecretVersionSelection(world.file.reference, world.file.intent, "fixture-version"),))
    return world, bind_document(world)


class ConnectorShapeQualificationTests(unittest.TestCase):
    def observer(self, world, **changes):
        def no_clock():
            raise AssertionError("shape qualification must not read time")
        options = dict(client=world.client, product_reference=world.reference,
            image_reference=world.material.product.image.execution_reference, clock=no_clock)
        options.update(changes)
        return DockerConnectorConnectionObserver(**options)

    def shape(self, world, document, **changes):
        options = dict(activity_id=world.request.activity_id, plan=world.plan,
            current=world.current, desired=world.desired, product_document=document,
            authority_ref=world.request.authority_ref)
        options.update(changes)
        result = self.observer(world).qualify_shape(**options)
        self.assertEqual(world.initializations + world.api.calls, [])
        return result

    def full(self, world, **changes):
        options = dict(activity_id=world.request.activity_id, plan=world.plan,
            current=world.current, desired=world.desired, material=world.material,
            authority_ref=world.request.authority_ref)
        options.update(changes)
        return self.observer(world).qualify(**options)

    def test_generated_fresh_and_retained_shapes_are_pure_without_token_values(self):
        for world_type, expected in ((World, ConnectorConnectionQualification.FRESH),
                (RetainedWorld, ConnectorConnectionQualification.RETAINED_CONTENT_UPDATE)):
            with self.subTest(mode=expected):
                world, document = shape_world(world_type)
                self.assertEqual(document.product.runtime_contract.secret_deliveries, ())
                node = world.desired.graph.nodes["connector"]
                self.assertEqual(node.secret_deliveries, ())
                self.assertEqual(node.secret_selections, ())
                before = (world.current, world.desired, world.plan, document)
                self.assertIs(self.shape(world, document), expected)
                self.assertIs(self.shape(world, document), expected)
                self.assertEqual((world.current, world.desired, world.plan, document), before)

    def test_canonical_document_content_and_product_must_agree(self):
        for case in ("type", "noncanonical", "malformed", "oversized", "foreign-product"):
            with self.subTest(case=case):
                world, document = shape_world()
                if case == "type": document = document.product
                elif case == "noncanonical": document = replace(document, content=document.content + b"\n")
                elif case == "malformed": document = replace(document, content=b"PRIVATE-CANDIDATE")
                elif case == "oversized": document = replace(document, content=b" " * (1024 * 1024 + 1))
                else: document = replace(document, product=replace(document.product, display_name="foreign"))
                self.assertIsNone(self.shape(world, document))

    def test_trusted_reference_image_and_graph_metadata_are_independent(self):
        for case in ("reference", "image", "metadata"):
            with self.subTest(case=case):
                world, document = shape_world()
                if case == "reference":
                    world.reference = replace(world.reference,
                        descriptor_sha256=replace(world.reference.descriptor_sha256, value="e" * 64))
                elif case == "image":
                    other = replace(document.product, image=replace(document.product.image, digest="sha256:" + "f" * 64))
                    document = bind_document(world, product=other)
                    world.material = replace(world.material, product=replace(world.material.product,
                        image=replace(other.image, digest="sha256:" + "a" * 64)))
                else:
                    node = replace(world.desired.graph.nodes["connector"], metadata={})
                    world.desired = validate_graph(world.desired.graph.update_node(node))
                    world.recompile()
                self.assertIsNone(self.shape(world, document))

    def test_actual_plan_graph_side_and_authority_are_required(self):
        for world_type in (World, RetainedWorld):
            for case in ("activity", "plan", "authority", "graph", "base-side"):
                with self.subTest(world=world_type.__name__, case=case):
                    world, document = shape_world(world_type)
                    changes = {}
                    if case == "activity": changes["activity_id"] = ActivityId("missing")
                    elif case == "plan": changes["plan"] = ActivityPlan(())
                    elif case == "authority": changes["authority_ref"] = replace(world.request.authority_ref, reference_id="foreign")
                    elif case == "graph": changes["desired"] = world.current
                    else:
                        activity = world.plan.activity(world.request.activity_id)
                        operation = replace(activity.operation, target=replace(activity.operation.target,
                            graph_side=core.PlanGraphSide.BASE_GRAPH))
                        changes["plan"] = replace(world.plan, activities=tuple(
                            replace(item, operation=operation) if item == activity else item
                            for item in world.plan.activities))
                    self.assertIsNone(self.shape(world, document, **changes))

    def test_missing_foreign_or_ambiguous_ingress_is_not_generated_support(self):
        for case in ("missing", "foreign", "ambiguous"):
            with self.subTest(case=case):
                world, document = shape_world()
                ingress = world.ingress
                ingresses = (() if case == "missing" else
                    (replace(ingress, connector_node_id="gateway"),) if case == "foreign" else
                    (ingress, replace(ingress, ingress_id="second", hostname="second.example.invalid")))
                desired = validate_graph(replace(world.desired.graph, public_ingresses=ingresses))
                self.assertIsNone(self.shape(world, document, desired=desired))

    def test_explicit_authored_file_with_empty_or_matching_declared_slot(self):
        for world_type in (World, RetainedWorld):
            for declared_slot in (False, True):
                with self.subTest(world=world_type.__name__, declared=declared_slot):
                    world, _ = shape_world(world_type)
                    declared = ((replace(world.file, reference=SecretReference("secret://declaration/token")),)
                        if declared_slot else ())
                    document = bind_document(world, declared=declared, authored=(world.file,))
                    mode = self.full(world)
                    self.assertIsNotNone(mode)
                    self.assertIs(self.shape(world, document), mode)

    def test_present_unsupported_or_extra_file_is_not_treated_as_absent(self):
        for case in ("environment", "intent", "binding", "binding-name", "extra"):
            with self.subTest(case=case):
                world, _ = shape_world()
                file = world.file
                if case == "environment": deliveries = (SecretEnvironmentDelivery("TUNNEL_TOKEN", file.reference, file.intent),)
                elif case == "intent": deliveries = (replace(file, intent=SecretUseIntent.APPLICATION_CONTROL_TOKEN),)
                elif case == "binding": deliveries = (replace(file, path_binding=None),)
                elif case == "binding-name": deliveries = (replace(file, path_binding=SecretFilePathBinding("OTHER_TOKEN_FILE")),)
                else: deliveries = (file, replace(file, target_path="/run/secrets/extra", path_binding=None))
                document = bind_document(world, authored=deliveries)
                self.assertIsNone(self.shape(world, document))

    def test_descriptor_slot_must_match_actual_authored_slot(self):
        for case in ("path", "intent", "binding", "extra"):
            with self.subTest(case=case):
                world, _ = shape_world()
                file = world.file
                if case == "path": declared = (replace(file, target_path="/run/secrets/other"),)
                elif case == "intent": declared = (replace(file, intent=SecretUseIntent.APPLICATION_CONTROL_TOKEN),)
                elif case == "binding": declared = (replace(file, path_binding=None),)
                else: declared = (file, replace(file, target_path="/run/secrets/extra", path_binding=None))
                document = bind_document(world, declared=declared, authored=(file,))
                self.assertIsNone(self.shape(world, document))

    def test_descriptor_only_slot_is_conservatively_narrower_than_full_material(self):
        world, _ = shape_world()
        document = bind_document(world, declared=(world.file,))
        self.assertIs(self.full(world), ConnectorConnectionQualification.FRESH)
        self.assertIsNone(self.shape(world, document))

    def test_authored_or_declared_configuration_and_environment_refuse_managed_shape(self):
        artifact = ConfigurationArtifact("control", "/etc/cpk/control.json", ConfigurationMediaType.JSON, "{}")
        environment = (PublicStaticEnvironmentBinding("CPK_WRAPPER_CONFIGURATION_FILE", artifact.target_path),)
        for owner in ("document", "node"):
            for case in ("artifact", "environment"):
                with self.subTest(owner=owner, case=case):
                    world, document = shape_world()
                    fields = ({"configuration_artifacts": (artifact,)} if case == "artifact" else {"public_environment": environment})
                    if owner == "document":
                        product = replace(document.product, runtime_contract=replace(document.product.runtime_contract, **fields))
                        document = bind_document(world, product=product)
                    else:
                        world.desired = validate_graph(world.desired.graph.update_node(
                            replace(world.desired.graph.nodes["connector"], **fields)))
                        world.recompile()
                    self.assertIsNone(self.shape(world, document))

    def test_supported_shape_does_not_supply_exact_material_or_installation_proof(self):
        for world_type in (World, RetainedWorld):
            with self.subTest(world=world_type.__name__):
                world, document = shape_world(world_type)
                mode = self.shape(world, document)
                self.assertIsNotNone(mode)
                self.assertIs(self.full(world), mode)
                missing = replace(world.material, secret_selections=(), product=replace(
                    world.material.product, runtime_contract=replace(
                        world.material.product.runtime_contract, secret_deliveries=())))
                unselected = replace(world.material, secret_selections=(
                    UnselectedSecretUse(world.file.reference, world.file.intent),))
                for material in (missing, unselected):
                    self.assertIsNone(self.full(world, material=material))
                    result = self.observer(world).observe(replace(world.request, products=(material,)),
                        plan=world.plan, current=world.current, desired=world.desired)
                    self.assertEqual(result.outcome.value, "refused")
                if world_type is RetainedWorld:
                    result = self.observer(world).observe(world.request,
                        plan=world.plan, current=world.current, desired=world.desired)
                    self.assertEqual(result.outcome.value, "refused")
                self.assertEqual(world.initializations + world.api.calls, [])

    def test_retained_mounts_and_authored_authority_delivery_are_not_native_shape(self):
        for case in ("retained-mount", "authority-delivery"):
            with self.subTest(case=case):
                world, document = shape_world()
                if case == "retained-mount":
                    product = replace(document.product, runtime_contract=replace(document.product.runtime_contract,
                        retained_data_mounts=(RetainedDataMount("data", "/var/lib/connector"),),
                        lifecycle=ResourceLifecycle.owned_with_retained_data("data")))
                    document = bind_document(world, product=product)
                else:
                    delivery = RuntimeAuthorityAccessDelivery(world.request.authority_ref,
                        RuntimeAuthorityAccessDeliveryKind.LOCAL_DOCKER_SOCKET_MOUNT)
                    world.desired = validate_graph(world.desired.graph.update_node(replace(
                        world.desired.graph.nodes["connector"], runtime_authority_deliveries=(delivery,))))
                    world.recompile()
                self.assertIsNone(self.shape(world, document))
