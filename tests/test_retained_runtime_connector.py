"""A new managed connector needs evidence from the run that added it."""
from dataclasses import replace
import unittest

import control_plane_kit_core as core
from control_plane_kit_core.planning import AllocatePublicIngress, StartNode
from control_plane_kit_core.public_ingress import IngressAuthorityReference, PublicIngressTarget
from control_plane_kit_core.secret_installation import SecretInstallationDisposition
from control_plane_kit_core.topology import validate_graph
from control_plane_kit_interpreters.docker import connector_connection as reader
from control_plane_kit_interpreters.docker.runtime import _node_labels
from managed_connector_fixtures import managed_world, observe, SELECTION_LABEL


def new_connector_world():
    world = managed_world(retained=True, lazy=True)
    graph = world.desired.graph
    runtime = graph.runtimes["docker"]
    application = replace(world.ingress, ingress_id="public",
        authority_ref=IngressAuthorityReference("public-authority"),
        target=PublicIngressTarget("workload", "control"),
        hostname="public.example.invalid", connector_node_id="application-connector")
    sibling = replace(graph.nodes["connector"], node_id=application.connector_node_id, block_spec=replace(graph.nodes["connector"].block_spec, role_id=application.connector_node_id))
    world.desired = validate_graph(replace(graph, nodes={**graph.nodes, sibling.node_id: sibling},
        runtimes={"docker": replace(runtime, children=(*runtime.children, sibling.node_id))},
        public_ingresses=(world.ingress, application)))
    world.current = validate_graph(replace(graph, nodes={"workload": graph.nodes["workload"]},
        runtimes={"docker": replace(runtime, children=("workload",), management=None)}, public_ingresses=()))
    world.current.require_valid()
    assert world.desired.valid, world.desired.errors
    world.plan = core.compile_existing_runtime_bootstrap_activity_plan(world.current, world.desired)
    assert world.plan.ready_for_execution
    native, = (v for v in world.plan.activities if getattr(v.operation, "stage", None)
        is core.ManagementBootstrapStage.CONNECTOR_CONNECTED)
    start, = (v for v in world.plan.activities if isinstance(v.operation, StartNode)
        and v.operation.target.node_id == "connector")
    allocation, = (v for v in world.plan.activities if isinstance(v.operation, AllocatePublicIngress)
        and v.operation.target.ingress_id == world.ingress.ingress_id)
    world.allocation = allocation.activity_id
    world.request = replace(world.request, activity_id=native.activity_id, operation=native.operation)
    world.installation_request = replace(world.installation_request, activity_id=start.activity_id,
        operation=start.operation, source=replace(world.request.source, intent_event_id=world.installation_request.effect_id))
    world.install_receipt()
    for item in world.containers:
        labels = item["Config"]["Labels"]
        item["Config"]["Labels"] = {**_node_labels(world.installation_request, world.material),
            SELECTION_LABEL: labels[SELECTION_LABEL]}
    return world


class NewConnectorOnRetainedRuntimeTests(unittest.TestCase):
    def test_selected_container_matches_original_start(self):
        world = new_connector_world()
        result = observe(world, allocation_activity_id=world.allocation)
        self.assertEqual(result.outcome, reader.ConnectorConnectionOutcome.CONNECTED, result)

    def test_missing_or_foreign_evidence_refuses_before_docker(self):
        for change in ("allocation", "run", "receipt", "disposition", "authority", "sibling"):
            with self.subTest(change=change):
                world = new_connector_world()
                args = dict(allocation_activity_id=world.allocation)
                if change == "allocation":
                    args.clear()
                if change == "run":
                    origin = world.installation_request
                    world.installation_request = replace(origin, source=replace(origin.source, request_id="other"))
                    world.install_receipt()
                if change == "receipt":
                    args["installation_receipt"] = None
                if change == "disposition":
                    world.install_receipt(disposition=SecretInstallationDisposition.REUSED)
                if change == "authority":
                    args["request"] = replace(world.request, authority_ref=None)
                if change == "sibling":
                    args["allocation_activity_id"], = (v.activity_id for v in world.plan.activities
                        if isinstance(v.operation, AllocatePublicIngress) and v.activity_id != world.allocation)
                self.assertEqual(observe(world, **args).outcome, reader.ConnectorConnectionOutcome.REFUSED)
                self.assertFalse(world.initializations)

    def test_same_name_other_container_is_unknown(self):
        world = new_connector_world()
        world.install_receipt(container_id="e" * 64)
        result = observe(world, allocation_activity_id=world.allocation)
        self.assertEqual(result.diagnostic, reader.ConnectorConnectionDiagnostic.BINDING_MISMATCH)
        self.assertFalse(world.archive_calls)
