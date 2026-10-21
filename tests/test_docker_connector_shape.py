"""#148 new-law query targets over Core values, without an Operations emulator."""
from dataclasses import replace
import json
import unittest

import control_plane_kit_core as core
from control_plane_kit_core.configuration import ConfigurationArtifact, ConfigurationMediaType
from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
from control_plane_kit_core.lifecycle import ResourceLifecycle
from control_plane_kit_core.planning import ActivityId, ActivityPlan, ActivityPlanDescriptorCodec
from control_plane_kit_core.products import ProductDescriptorCodec, ProductReference, RetainedDataMount
from control_plane_kit_core.runtime_authority import RuntimeAuthorityAccessDelivery, RuntimeAuthorityAccessDeliveryKind
from control_plane_kit_core.secrets import SecretEnvironmentDelivery, SecretFilePathBinding, SecretReference, SecretUseIntent
from control_plane_kit_core.secret_selections import SecretVersionSelection, UnselectedSecretUse, author_secret_selections
from control_plane_kit_core.topology import DEFAULT_GRAPH_CODEC, validate_graph
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


def declared_snapshot(world, document):
    return (json.dumps(DEFAULT_GRAPH_CODEC.encode(world.current.graph), sort_keys=True),
        json.dumps(DEFAULT_GRAPH_CODEC.encode(world.desired.graph), sort_keys=True),
        json.dumps(ActivityPlanDescriptorCodec().encode(world.plan), sort_keys=True),
        ProductDescriptorCodec().encode_document(document.product).content, document.content)


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
                before = declared_snapshot(world, document)
                self.assertIs(self.shape(world, document), expected)
                self.assertIs(self.shape(world, document), expected)
                self.assertEqual(declared_snapshot(world, document), before)

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


class ClientFreeConnectorQualificationTests(unittest.TestCase):
    """#218: one pure capability owner with compatible observer entrances."""

    def qualifier_type(self):
        from control_plane_kit_interpreters.docker import connector_connection as module
        qualifier = getattr(module, "DockerConnectorConnectionQualifier", None)
        self.assertIsNotNone(qualifier, "I218 missing client-free connection qualifier")
        return qualifier

    def world(self, *, managed=False, mode="fresh", reverse=False):
        from managed_connector_fixtures import managed_world
        from test_docker_retained_image_connector import image_transition
        if managed:
            world = managed_world(retained=mode != "fresh", lazy=True)
            document = world.document
        else:
            world, document = shape_world(World if mode == "fresh" else RetainedWorld)
        if mode == "retained_image_ingress_update":
            image_transition(world, reverse=reverse)
        return world, document

    def profile(self, managed):
        from control_plane_kit_interpreters.docker.sdk import ConnectorConnectionProfile
        return (ConnectorConnectionProfile.MANAGED_WRAPPER_V1 if managed
                else ConnectorConnectionProfile.NATIVE_READER_V1)

    def options(self, world):
        return dict(activity_id=world.request.activity_id, plan=world.plan,
                    current=world.current, desired=world.desired,
                    authority_ref=world.request.authority_ref)

    def snapshot(self, world, document):
        return declared_snapshot(world, document) + (
            json.dumps(world.material.descriptor(), sort_keys=True),)

    def query_pair(self, world, document, *, managed=False, shape_changes=None, full_changes=None,
                   image_reference=None):
        qualifier_type = self.qualifier_type()
        image = image_reference if image_reference is not None else world.material.product.image.execution_reference
        profile = self.profile(managed)

        def no_clock():
            raise AssertionError("pure qualifier read time")

        observer = DockerConnectorConnectionObserver(world.client, world.reference, image, no_clock, profile)
        pure = qualifier_type(world.reference, image, profile)
        shape = dict(self.options(world), product_document=document)
        full = dict(self.options(world), material=world.material)
        shape.update(shape_changes or {})
        full.update(full_changes or {})
        before = self.snapshot(world, document)
        mode = pure.qualify(**full)
        shape_mode = pure.qualify_shape(**shape)
        self.assertIs(observer.qualify(**full), mode)
        self.assertIs(observer.qualify_shape(**shape), shape_mode)
        self.assertEqual(self.snapshot(world, document), before)
        self.assertEqual(world.initializations + world.api.calls + getattr(world, "archive_calls", []), [])
        return mode, shape_mode

    def test_standalone_construction_and_queries_need_no_client_clock_or_io(self):
        from dataclasses import FrozenInstanceError
        from unittest.mock import patch
        from control_plane_kit_interpreters.docker import sdk
        qualifier_type = self.qualifier_type()
        world, document = self.world()
        options = self.options(world)
        before = self.snapshot(world, document)
        with patch.object(sdk.DockerSdkClient, "__init__", side_effect=AssertionError("SDK construction")), \
                patch.object(sdk, "import_module", side_effect=AssertionError("SDK import")), \
                patch("builtins.open", side_effect=AssertionError("filesystem")), \
                patch("os.stat", side_effect=AssertionError("stat")), \
                patch("os.getenv", side_effect=AssertionError("environment")):
            pure = qualifier_type(world.reference, world.material.product.image.execution_reference)
            self.assertIs(pure.qualify(**options, material=world.material), ConnectorConnectionQualification.FRESH)
            self.assertIs(pure.qualify_shape(**options, product_document=document), ConnectorConnectionQualification.FRESH)
        self.assertNotIn(world.material.product.image.execution_reference, repr(pure))
        with self.assertRaises(FrozenInstanceError):
            pure.image_reference = "changed"
        self.assertEqual(self.snapshot(world, document), before)
        self.assertEqual(world.initializations + world.api.calls, [])
        with self.assertRaises(TypeError):
            qualifier_type(world.reference, world.material.product.image.execution_reference, client=world.client)
        with self.assertRaises(TypeError):
            qualifier_type(world.reference, world.material.product.image.execution_reference, clock=lambda: world.now)

    def test_constructor_types_and_observer_fixed_error_surface_are_preserved(self):
        qualifier_type = self.qualifier_type()
        world, _ = self.world()
        reference, image, profile = world.reference, world.material.product.image.execution_reference, self.profile(False)
        for field, value in (("product_reference", object()), ("image_reference", object()),
                             ("profile", "native-reader-v1")):
            with self.subTest(field=field):
                options = dict(product_reference=reference, image_reference=image, profile=profile)
                options[field] = value
                with self.assertRaises(TypeError):
                    qualifier_type(**options)
                with self.assertRaisesRegex(TypeError, "^native connection observer configuration is invalid$"):
                    DockerConnectorConnectionObserver(world.client, clock=lambda: world.now, **options)
        for client, clock in ((object(), lambda: world.now), (world.client, None)):
            with self.assertRaisesRegex(TypeError, "^native connection observer configuration is invalid$"):
                DockerConnectorConnectionObserver(client, reference, image, clock, profile)
        # Preserve existing exact-str acceptance; extraction adds no image grammar.
        qualifier_type(reference, "", profile)
        first = DockerConnectorConnectionObserver(world.client, reference, image, lambda: world.now)
        second = replace(first)
        self.assertEqual(first, second)

    def test_all_modes_and_profiles_are_pure_and_match_both_observer_queries(self):
        self.qualifier_type()
        for managed in (False, True):
            for mode in ("fresh", "retained_content_update", "retained_image_ingress_update"):
                for reverse in ((False, True) if mode == "retained_image_ingress_update" else (False,)):
                    with self.subTest(managed=managed, mode=mode, reverse=reverse):
                        world, document = self.world(managed=managed, mode=mode, reverse=reverse)
                        for _ in range(2):
                            full, shape = self.query_pair(world, document, managed=managed)
                            self.assertEqual(full.value, mode)
                            self.assertIs(shape, full)

    def test_standalone_refuses_foreign_document_plan_authority_and_image(self):
        self.qualifier_type()
        for case in ("malformed", "noncanonical", "foreign-product", "activity", "plan", "authority", "image"):
            with self.subTest(case=case):
                world, document = self.world()
                shape_changes, full_changes = {}, {}
                image = None
                if case == "malformed":
                    document = replace(document, content=b"PRIVATE-CANDIDATE")
                elif case == "noncanonical":
                    document = replace(document, content=document.content + b"\n")
                elif case == "foreign-product":
                    document = replace(document, product=replace(document.product, display_name="foreign"))
                elif case == "activity":
                    shape_changes = full_changes = {"activity_id": ActivityId("missing")}
                elif case == "plan":
                    shape_changes = full_changes = {"plan": ActivityPlan(())}
                elif case == "authority":
                    shape_changes = full_changes = {"authority_ref": replace(world.request.authority_ref, reference_id="foreign")}
                else:
                    image = "ghcr.io/fixture/other@sha256:" + "f" * 64
                full, shape = self.query_pair(world, document, shape_changes=shape_changes,
                    full_changes=full_changes, image_reference=image)
                self.assertIsNone(shape)
                if case not in ("malformed", "noncanonical", "foreign-product"):
                    self.assertIsNone(full)

    def test_standalone_preserves_authored_slot_and_descriptor_only_asymmetry(self):
        self.qualifier_type()
        for case in ("generated", "authored", "matching", "mismatch", "descriptor-only"):
            with self.subTest(case=case):
                world, document = self.world()
                if case == "authored":
                    document = bind_document(world, authored=(world.file,))
                elif case == "matching":
                    document = bind_document(world, declared=(world.file,), authored=(world.file,))
                elif case == "mismatch":
                    document = bind_document(world, declared=(replace(world.file, target_path="/run/secrets/other"),),
                                             authored=(world.file,))
                elif case == "descriptor-only":
                    document = bind_document(world, declared=(world.file,))
                full, shape = self.query_pair(world, document)
                self.assertIs(full, ConnectorConnectionQualification.FRESH)
                self.assertIs(shape, None if case in ("mismatch", "descriptor-only") else full)

    def test_standalone_full_query_keeps_exact_material_and_selected_token_requirements(self):
        self.qualifier_type()
        for managed in (False, True):
            for case in ("node", "token", "image"):
                with self.subTest(managed=managed, case=case):
                    world, document = self.world(managed=managed)
                    material = world.material
                    if case == "node":
                        material = replace(material, node_id="foreign")
                    elif case == "token":
                        material = replace(material, secret_selections=(
                            UnselectedSecretUse(world.file.reference, world.file.intent),))
                    else:
                        material = replace(material, product=replace(material.product,
                            image=replace(material.product.image, digest="sha256:" + "f" * 64)))
                    full, shape = self.query_pair(world, document, managed=managed, full_changes={"material": material})
                    self.assertIsNone(full)
                    self.assertIs(shape, ConnectorConnectionQualification.FRESH)

    def test_standalone_image_query_requires_whole_canonical_plan(self):
        from control_plane_kit_core.planning import ReconcileNode
        self.qualifier_type()
        for case in ("old-v1", "filtered", "dependencies"):
            with self.subTest(case=case):
                world, document = self.world(managed=True, mode="retained_image_ingress_update")
                if case == "old-v1":
                    plan = core.compile_managed_update_activity_plan(world.current, world.desired)
                elif case == "filtered":
                    plan = ActivityPlan(tuple(value for value in world.plan.activities
                                              if value.activity_id == world.request.activity_id))
                else:
                    plan = ActivityPlan(tuple(replace(value, dependencies=())
                        if type(value.operation) is ReconcileNode else value for value in world.plan.activities))
                full, shape = self.query_pair(world, document, managed=True,
                    shape_changes={"plan": plan}, full_changes={"plan": plan})
                self.assertIsNone(full)
                self.assertIsNone(shape)

    def test_qualification_does_not_supply_retained_installation_proof(self):
        self.qualifier_type()
        for managed in (False, True):
            for mode in ("retained_content_update", "retained_image_ingress_update"):
                with self.subTest(managed=managed, mode=mode):
                    world, document = self.world(managed=managed, mode=mode)
                    full, shape = self.query_pair(world, document, managed=managed)
                    self.assertEqual(full.value, mode)
                    self.assertIs(shape, full)
                    observer = DockerConnectorConnectionObserver(world.client, world.reference,
                        world.material.product.image.execution_reference, lambda: world.now, self.profile(managed))
                    result = observer.observe(world.request, plan=world.plan, current=world.current, desired=world.desired)
                    self.assertEqual(result.outcome.value, "refused")
                    self.assertIsNone(result.effect_id)
                    self.assertIsNone(result.activity_id)
                    self.assertEqual(world.initializations + world.api.calls + getattr(world, "archive_calls", []), [])
