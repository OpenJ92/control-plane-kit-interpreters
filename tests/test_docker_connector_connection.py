"""#167 new-law tests: actual SDK projection and compiled graph selection."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json
import unittest

import control_plane_kit_core as core
from control_plane_kit_core.planning import ActivityId, ActivityPlan, PlannedActivity, StartRuntime
from control_plane_kit_core.lifecycle import ResourceLifecycle
from control_plane_kit_core.secrets import SecretEnvironmentDelivery, SecretUseIntent
from control_plane_kit_core.secret_selections import SecretVersionSelection
from control_plane_kit_core.topology import validate_graph
from control_plane_kit_core.types import RuntimeKind
from control_plane_kit_interpreters.docker import connector_connection as module
from docker_connector_fixtures import World, RetainedWorld, sample, CONTAINER_ID, NATIVE_ID, IMAGE_ID


class DockerConnectorConnectionTests(unittest.TestCase):
    def assert_outcome(self, world, expected, **changes):
        result = world.observe(module, **changes)
        self.assertEqual(result.outcome.value, expected)
        for candidate in ("PRIVATE-CANDIDATE", "secret://fixture", "fixture.example.invalid", "TUNNEL_TOKEN"):
            self.assertNotIn(candidate, repr(result))
        return result

    def test_connected_disconnected_and_unknown_use_newest_sample_not_aggregate(self):
        for outcome in ("connected", "disconnected", "unknown"):
            with self.subTest(outcome=outcome):
                world = World()
                world.mutate("State", "Health", {"Status": "healthy", "Log": [sample(), sample(outcome)]})
                result = self.assert_outcome(world, outcome)
                self.assertEqual(result.effect_id, world.request.effect_id)
                self.assertEqual(result.activity_id, world.request.activity_id.value)
                self.assertEqual(world.api.calls, [("container", world.name),
                    ("image", world.material.product.image.execution_reference), ("container", CONTAINER_ID)])
                if outcome != "unknown":
                    self.assertEqual(result.connector_id, NATIVE_ID)
                    self.assertEqual(result.ready_connections, 4 if outcome == "connected" else 0)
                    self.assertEqual(result.container_id, CONTAINER_ID)
                    self.assertEqual(result.sample_end, "2026-09-24T12:00:01.000000001Z")

    def test_original_selection_mismatches_refuse_before_lazy_initialization(self):
        for case in ("stage", "runtime", "graph", "relation", "plan", "activity", "authority", "other-authority", "product", "image", "metadata", "stale-metadata-pin", "ingress", "retained", "base"):
            with self.subTest(case=case):
                world, changes = World(lazy=True), {}
                request, op = world.request, world.request.operation
                if case == "stage": request = replace(request, operation=replace(op, stage=core.ManagementBootstrapStage.GATEWAY_INGRESS_READY))
                elif case == "runtime": request = replace(request, runtime_kind=RuntimeKind.KUBERNETES)
                elif case in ("graph", "relation"):
                    request = replace(request, operation=replace(op, target=replace(op.target, **{case + "_digest": "e" * 64})))
                elif case == "plan": changes["plan"] = ActivityPlan((PlannedActivity(request.activity_id, replace(op, stage=core.ManagementBootstrapStage.GATEWAY_INGRESS_READY)),))
                elif case == "activity": request = replace(request, activity_id=ActivityId("other"))
                elif case == "authority": request = replace(request, authority_ref=None)
                elif case == "other-authority": request = replace(request, authority_ref=replace(request.authority_ref, reference_id="other"))
                elif case == "product": request = replace(request, products=())
                elif case == "image":
                    material = replace(world.material, product=replace(world.material.product,
                        image=replace(world.material.product.image, digest="sha256:" + "f" * 64)))
                    request = replace(request, products=(material,))
                elif case in ("metadata", "stale-metadata-pin"):
                    node = replace(world.desired.graph.nodes["connector"], metadata={})
                    changes["desired"] = validate_graph(replace(world.desired.graph, nodes={**world.desired.graph.nodes, "connector": node}))
                    if case == "metadata":
                        coherent = core.compile_graph_activity_plan(world.current, changes["desired"])
                        activity, = (item for item in coherent.activities if type(item.operation) is core.ObserveManagementBootstrap
                            and item.operation.stage is core.ManagementBootstrapStage.CONNECTOR_CONNECTED)
                        changes["plan"] = coherent
                        request = replace(request, operation=activity.operation, activity_id=activity.activity_id)
                elif case == "ingress": changes["desired"] = validate_graph(replace(world.desired.graph,
                    public_ingresses=(replace(world.ingress, hostname="other.example.invalid"),)))
                elif case == "retained": changes["current"] = world.desired
                elif case == "base":
                    operation = replace(op, target=replace(op.target, graph_side=core.PlanGraphSide.BASE_GRAPH))
                    request = replace(request, operation=operation)
                    changes.update(current=world.desired, plan=ActivityPlan((PlannedActivity(request.activity_id, operation),)))
                self.assert_outcome(world, "refused", request=request, **changes)
                self.assertEqual(world.initializations, [])
                self.assertEqual(world.api.calls, [])

    def test_file_only_contract_and_no_extra_environment_or_material_before_io(self):
        for case in ("environment", "missing", "wrong-intent", "wrong-binding", "extra-file", "public-env"):
            with self.subTest(case=case):
                world = World(lazy=True)
                delivery = world.file
                deliveries = (delivery,)
                if case == "environment": deliveries = (SecretEnvironmentDelivery("TUNNEL_TOKEN", delivery.reference, delivery.intent),)
                elif case == "missing": deliveries = ()
                elif case == "wrong-intent": deliveries = (replace(delivery, intent=SecretUseIntent.APPLICATION_CONTROL_TOKEN),)
                elif case == "wrong-binding": deliveries = (replace(delivery, path_binding=None),)
                elif case == "extra-file": deliveries += (replace(delivery, target_path="/run/secrets/extra", path_binding=None),)
                contract = replace(world.material.product.runtime_contract, secret_deliveries=deliveries)
                selections = tuple(SecretVersionSelection(reference, intent, "fixture-version")
                    for reference, intent in dict.fromkeys((item.reference, item.intent) for item in deliveries))
                material = replace(world.material, product=replace(world.material.product, runtime_contract=contract),
                    secret_selections=selections)
                if case == "public-env":
                    from control_plane_kit_core.products import PublicStaticEnvironmentBinding
                    material = replace(material, public_environment=(PublicStaticEnvironmentBinding("PYTHONPATH", "/tmp/PRIVATE-CANDIDATE"),))
                self.assert_outcome(world, "refused", request=replace(world.request, products=(material,)))
                self.assertEqual(world.initializations + world.api.calls, [])

    def test_actual_nonfresh_creation_plans_refuse_before_lazy_io(self):
        for lifecycle in (ResourceLifecycle.attached(), ResourceLifecycle.external()):
            with self.subTest(lifecycle=lifecycle):
                world = World(lazy=True)
                graph = world.desired.graph
                world.desired = validate_graph(replace(graph,
                    runtimes={"docker":replace(graph.runtimes["docker"], lifecycle=lifecycle)}))
                world.recompile()
                self.assertFalse(any(type(item.operation) is StartRuntime and item.operation.target.runtime_id == "docker"
                    for item in world.plan.activities))
                # Coherent operation pins and otherwise working SDK evidence.
                self.assert_outcome(world, "refused")
                self.assertEqual(world.initializations + world.api.calls, [])

    def test_retained_node_identity_in_actual_graph_pair_refuses_before_io(self):
        from control_plane_kit_core.topology import DeploymentGraph, RuntimeRecord
        for subject in ("gateway", "connector"):
            with self.subTest(subject=subject):
                world = World(lazy=True)
                retained = replace(world.desired.graph.nodes[subject], runtime_id="old-runtime")
                world.current = validate_graph(DeploymentGraph("native", nodes={subject:retained},
                    runtimes={"old-runtime":RuntimeRecord("old-runtime", RuntimeKind.DOCKER, (subject,))}))
                world.recompile()
                self.assert_outcome(world, "refused")
                self.assertEqual(world.initializations + world.api.calls, [])

    def test_sdk_timeout_conformance_injected_eager_and_lazy(self):
        for timeout in (None, False, 0, -1, float("nan"), float("inf"), 60.001, "60"):
            with self.subTest(timeout=timeout):
                world = World()
                world.api.timeout = timeout
                self.assert_outcome(world, "unknown")
                self.assertEqual(world.api.calls, [])
        world = World()
        del world.api.timeout
        self.assert_outcome(world, "unknown")
        self.assertEqual(world.api.calls, [])
        for lazy in (False, True):
            world = World(lazy=lazy)
            world.api.timeout = 0.5
            self.assert_outcome(world, "connected")
            self.assertEqual(len(world.initializations), int(lazy))
            self.assertEqual(world.api.timeout, 0.5)
        world = World(lazy=True)
        world.client.connect_on_init = True
        world.client.__post_init__()
        self.assertEqual(len(world.initializations), 1)
        self.assert_outcome(world, "connected")
        self.assertEqual(len(world.initializations), 1)

    def test_ownership_image_identity_and_network_must_match(self):
        for case in ("id", "name", "ownership", "foreign-plan", "image-id", "repo", "network", "network-mode"):
            with self.subTest(case=case):
                world = World()
                if case == "id": world.containers[0]["Id"] = "malformed"
                elif case == "name": world.containers[0]["Name"] = "/foreign"
                elif case in ("ownership", "foreign-plan"):
                    world.containers[0]["Config"]["Labels"]["org.openj92.cpk." + ("node" if case == "ownership" else "plan")] = "foreign"
                elif case == "image-id": world.image["Id"] = "sha256:" + "f" * 64
                elif case == "repo": world.image["RepoDigests"] = ["ghcr.io/other/image@sha256:" + "a" * 64]
                elif case == "network": world.containers[0]["NetworkSettings"]["Networks"] = {"foreign": {}}
                else: world.containers[0]["HostConfig"]["NetworkMode"] = "host"
                self.assert_outcome(world, "unknown")

    def test_effective_launch_overrides_and_malformed_prehash_values_cannot_attest(self):
        candidates = [("Entrypoint", ["PRIVATE-CANDIDATE"]), ("Cmd", ["run", "tunnel"]),
            ("User", "0"), ("WorkingDir", "/tmp"), ("StopSignal", "SIGKILL"),
            ("Shell", ["PRIVATE-CANDIDATE"]), ("Volumes", {"/app": {}}),
            ("Entrypoint", "cloudflared"), ("Cmd", [True]), ("User", 65532),
            ("Env", ["PATH=a", "PATH=b"]), ("Env", ["MALFORMED"]),
            ("Env", ["X=" + "x" * 8193]), ("Env", ["X=1"] * 129),
            ("Healthcheck", {"Test": ["NONE"]}), ("Healthcheck", {"Test": ["CMD", "python"], "Retries": True})]
        for key, value in candidates:
            with self.subTest(key=key, value=str(value)[:100]):
                world = World()
                world.mutate("Config", key, value)
                self.assert_outcome(world, "unknown")
        for key in ("PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "LD_PRELOAD", "TUNNEL_TOKEN"):
            world = World()
            env = [item for item in world.containers[0]["Config"]["Env"] if not item.startswith(key + "=")]
            world.mutate("Config", "Env", env + [key + "=PRIVATE-CANDIDATE"])
            self.assert_outcome(world, "unknown")
        for key, value in (("Path", "sh"), ("Args", ["PRIVATE-CANDIDATE"])):
            world = World()
            world.containers[0][key] = value
            self.assert_outcome(world, "unknown")

    def test_environment_order_is_irrelevant_but_image_baseline_must_be_reader_v1(self):
        world = World()
        for container in world.containers:
            container["Config"]["Env"].reverse()
        self.assert_outcome(world, "connected")
        world = World()
        for container in world.containers:
            # Same lawful key/value: a dict conversion would otherwise hide it.
            container["Config"]["Env"].append(container["Config"]["Env"][0])
        self.assert_outcome(world, "unknown")
        for key, value in (("Healthcheck", {"Test": ["CMD", "true"]}), ("Entrypoint", ["sh"])):
            world = World()
            world.image["Config"][key] = value
            world.mutate("Config", key, value)
            self.assert_outcome(world, "unknown")

    def test_mount_must_be_exact_declared_readonly_content_subpath_without_shadowing(self):
        for case in ("rw", "subpath", "volume", "extra", "binds", "tmpfs", "volumes-from"):
            with self.subTest(case=case):
                world = World()
                for container in world.containers:
                    if case == "rw": container["Mounts"][0]["RW"] = True
                    elif case == "subpath": container["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] = "other"
                    elif case == "volume": container["Mounts"][0]["Name"] = "foreign"
                    elif case == "extra": container["Mounts"].append({"Type": "bind", "Destination": "/app", "RW": False})
                    else: container["HostConfig"][{"binds":"Binds", "tmpfs":"Tmpfs", "volumes-from":"VolumesFrom"}[case]] = ["PRIVATE-CANDIDATE"]
                self.assert_outcome(world, "unknown")

    def test_nonrunning_paused_restarting_and_missing_newest_sample_are_unknown(self):
        for key, value in (("Running", False), ("Running", 1), ("Paused", True), ("Restarting", True),
                           ("Health", {"Status":"healthy", "Log":[]}), ("Health", {"Status":"healthy"})):
            world = World()
            world.mutate("State", key, value)
            self.assert_outcome(world, "unknown")

    def test_strict_wire_schema_exit_count_uuid_and_limits(self):
        valid = json.loads(sample()["Output"])
        bodies = ["PRIVATE-CANDIDATE", "[1]", "x" * 257,
            json.dumps({**valid, "extra":"PRIVATE-CANDIDATE"}),
            json.dumps({**valid, "schema":"future"}),
            json.dumps({**valid, "readyConnections":True}), json.dumps({**valid, "readyConnections":0}),
            json.dumps({**valid, "readyConnections":2**64}),
            json.dumps({**valid, "connectorId":"00000000-0000-0000-0000-000000000000"}),
            json.dumps({**valid, "connectorId":NATIVE_ID.upper()}),
            sample()["Output"].rstrip()[:-1] + ',"outcome":"connected"}',
            '{"schema":"cpk.cloudflared.connection/v1","outcome":"unknown","reason":"PRIVATE-CANDIDATE"}']
        for output in bodies:
            world = World()
            current = sample()
            current["Output"] = output
            world.mutate("State", "Health", {"Status":"healthy", "Log":[current]})
            self.assert_outcome(world, "unknown")
        for exit_code in (1, True, "0"):
            world = World()
            current = sample()
            current["ExitCode"] = exit_code
            world.mutate("State", "Health", {"Log":[current]})
            self.assert_outcome(world, "unknown")
        world = World()
        current = sample()
        current["Output"] = current["Output"].rstrip().ljust(256)
        world.mutate("State", "Health", {"Log":[current]})
        self.assert_outcome(world, "connected")
        current["Output"] += " "
        world.mutate("State", "Health", {"Log":[current]})
        self.assert_outcome(world, "unknown")

    def test_precise_incarnation_freshness_and_nonfuture_boundaries(self):
        cases = [("2026-09-24T11:59:51Z", "2026-09-24T11:59:52Z", "connected"),
                 ("2026-09-24T11:59:51Z", "2026-09-24T11:59:51.999999999Z", "unknown"),
                 ("2026-09-24T12:00:01Z", "2026-09-24T12:00:02Z", "connected"),
                 ("2026-09-24T12:00:01Z", "2026-09-24T12:00:02.000000001Z", "unknown"),
                 ("2026-09-24T11:58:59.999999999Z", "2026-09-24T12:00:01Z", "unknown"),
                 ("2026-09-24T12:00:01.000000002Z", "2026-09-24T12:00:01.000000001Z", "unknown"),
                 ("malformed", "2026-09-24T12:00:01Z", "unknown")]
        for start, end, outcome in cases:
            with self.subTest(start=start, end=end):
                world = World()
                world.mutate("State", "Health", {"Log":[sample(start=start, end=end)]})
                self.assert_outcome(world, outcome)

    def test_time_rechecked_after_every_semantic_lookup(self):
        for slow_read in (1, 2, 3):
            world = World()
            def advance(count):
                if count == slow_read:
                    world.now += timedelta(seconds=11)
            world.after_read = advance
            self.assert_outcome(world, "unknown")
            self.assertEqual(len(world.api.calls), slow_read)

    def test_invalid_offset_is_not_normalized_into_fresh_evidence(self):
        for zone, outcome in (("+00:60", "unknown"), ("+01:00", "connected")):
            with self.subTest(zone=zone):
                world = World()
                world.mutate("State", "Health", {"Log":[sample(
                    start="2026-09-24T13:00:00.000000001" + zone,
                    end="2026-09-24T13:00:01.000000001" + zone)]})
                self.assert_outcome(world, outcome)

    def test_final_id_incarnation_ownership_launch_and_newest_sample_must_be_unchanged(self):
        for case in ("id", "started", "dead", "labels", "env", "new-failure", "new-success"):
            with self.subTest(case=case):
                world = World()
                final = world.containers[1]
                if case == "id": final["Id"] = "f" * 64
                elif case == "started": final["State"]["StartedAt"] = "2026-09-24T12:00:00Z"
                elif case == "dead": final["State"]["Running"] = False
                elif case == "labels": final["Config"]["Labels"]["org.openj92.cpk.plan"] = "foreign"
                elif case == "env": final["Config"]["Env"].append("LD_PRELOAD=PRIVATE-CANDIDATE")
                else: final["State"]["Health"]["Log"].append(sample("disconnected" if case == "new-failure" else "connected",
                    start="2026-09-24T12:00:01.1Z", end="2026-09-24T12:00:01.2Z"))
                self.assert_outcome(world, "unknown")
                self.assertEqual(len(world.api.calls), 3)
                self.assertEqual(world.api.calls[-1], ("container", CONTAINER_ID))

    def test_provider_failure_is_redacted_and_never_retried(self):
        world = World()
        world.error = RuntimeError("PRIVATE-CANDIDATE credential error")
        self.assert_outcome(world, "unknown")
        self.assertEqual(world.api.calls, [("container", world.name)])


class RetainedConnectorConnectionTests(unittest.TestCase):
    """#148 new-law admission and strengthened existing passive-reader laws."""

    assert_outcome = DockerConnectorConnectionTests.assert_outcome

    def qualify(self, world, **changes):
        def no_clock():
            raise AssertionError("qualification must not read time")
        options = dict(activity_id=world.request.activity_id, plan=world.plan,
            current=world.current, desired=world.desired, material=world.material,
            authority_ref=world.request.authority_ref)
        options.update(changes)
        return module.DockerConnectorConnectionObserver(world.client, world.reference,
            world.material.product.image.execution_reference, no_clock).qualify(**options)

    def test_qualification_is_pure_and_does_not_substitute_for_installation_proof(self):
        for world_type, mode in ((World, module.ConnectorConnectionQualification.FRESH),
                (RetainedWorld, module.ConnectorConnectionQualification.RETAINED_CONTENT_UPDATE)):
            with self.subTest(mode=mode):
                world = world_type(lazy=True)
                self.assertIs(self.qualify(world), mode)
                self.assertEqual(world.initializations + world.api.calls, [])
        result = self.assert_outcome(world, "refused", installation_request=None, installation_receipt=None)
        self.assertIsNone(result.effect_id)
        self.assertIsNone(result.activity_id)
        self.assertEqual(world.initializations + world.api.calls, [])

    def test_qualification_checks_actual_plan_material_and_current_authority(self):
        for world_type in (World, RetainedWorld):
            for case in ("activity", "plan", "authority", "material", "image", "graph"):
                with self.subTest(world=world_type.__name__, case=case):
                    world = world_type(lazy=True)
                    changes = {}
                    if case == "activity": changes["activity_id"] = ActivityId("missing")
                    elif case == "plan": changes["plan"] = ActivityPlan(())
                    elif case == "authority": changes["authority_ref"] = replace(world.request.authority_ref, reference_id="foreign")
                    elif case == "material": changes["material"] = replace(world.material, node_id="foreign")
                    elif case == "image": changes["material"] = replace(world.material,
                        product=replace(world.material.product, image=replace(world.material.product.image, digest="sha256:" + "f" * 64)))
                    else: changes["desired"] = world.current
                    self.assertIsNone(self.qualify(world, **changes))
                    self.assertEqual(world.initializations + world.api.calls, [])

    def test_retained_observation_uses_installation_labels_and_returns_current_correlation(self):
        from control_plane_kit_core.secret_installation import SecretInstallationDisposition
        for reconcile, disposition in ((False, SecretInstallationDisposition.CREATED),
                (True, SecretInstallationDisposition.CREATED), (True, SecretInstallationDisposition.REPLACED)):
            for outcome in ("connected", "disconnected", "unknown"):
                with self.subTest(reconcile=reconcile, disposition=disposition, outcome=outcome):
                    world = RetainedWorld(reconcile=reconcile)
                    world.install_receipt(disposition=disposition)
                    world.mutate("State", "Health", {"Status": "healthy", "Log": [sample(), sample(outcome)]})
                    self.assertNotEqual(world.installation_request.source.plan_id, world.request.source.plan_id)
                    self.assertNotEqual(world.installation_request.effect_id, world.request.effect_id)
                    result = self.assert_outcome(world, outcome)
                    self.assertEqual((result.effect_id, result.activity_id),
                        (world.request.effect_id, world.request.activity_id.value))
                    self.assertEqual(world.api.calls, [("container", world.name),
                        ("image", world.material.product.image.execution_reference), ("container", CONTAINER_ID)])
                    if outcome != "unknown":
                        self.assertEqual(result.container_id, CONTAINER_ID)

    def test_historical_authority_reference_does_not_supply_current_authority(self):
        world = RetainedWorld()
        world.installation_request = replace(world.installation_request,
            authority_ref=replace(world.installation_request.authority_ref, reference_id="historical-authority"))
        world.install_receipt()
        self.assert_outcome(world, "connected")
        world = RetainedWorld(lazy=True)
        self.assert_outcome(world, "refused", request=replace(world.request,
            authority_ref=replace(world.request.authority_ref, reference_id="foreign-current")))
        self.assertEqual(world.initializations + world.api.calls, [])

    def test_reused_installation_with_earlier_creation_labels_is_unknown(self):
        from control_plane_kit_core.secret_installation import SecretInstallationDisposition
        from control_plane_kit_interpreters.docker.runtime import _node_labels
        world = RetainedWorld(reconcile=True)
        # Actual fingerprint-equal reconciliation preserves C's labels, while
        # the accepted REUSED receipt commits A and that same immutable ID.
        creation = replace(world.installation_request, operation=core.StartNode(world.installation_request.operation.target),
            source=replace(world.installation_request.source,
            plan_id="earlier-creation-c", desired_graph_id="graph-c"))
        for container in world.containers:
            container["Config"]["Labels"] = _node_labels(creation, world.material)
        world.install_receipt(disposition=SecretInstallationDisposition.REUSED)
        self.assertEqual(world.installation_receipt.prior_realization_fingerprint,
            world.installation_receipt.current_realization_fingerprint)
        self.assert_outcome(world, "unknown")
        self.assertEqual(world.api.calls, [("container", world.name)])

    def test_missing_half_foreign_or_mismatched_proof_refuses_before_lazy_io(self):
        from control_plane_kit_core.configuration_installation import ConfigurationInstallationReceipt
        from control_plane_kit_core.secret_installation import SecretInstallationReceipt
        for case in ("none", "request-only", "receipt-only", "wrong-request", "generic-receipt",
                "request-fingerprint", "selection-fingerprint", "malformed-receipt", "workspace",
                "runtime", "node", "product", "image", "version", "runtime-kind", "grants", "authority-deliveries",
                "observation-as-installation"):
            with self.subTest(case=case):
                world = RetainedWorld(lazy=True)
                original, receipt = world.installation_request, world.installation_receipt
                if case == "none": original, receipt = None, None
                elif case == "request-only": receipt = None
                elif case == "receipt-only": original = None
                elif case == "wrong-request": original = object()
                elif case == "observation-as-installation": original = world.request
                elif case == "generic-receipt": receipt = ConfigurationInstallationReceipt(
                    receipt.request_fingerprint, receipt.selection_fingerprint, receipt.disposition,
                    receipt.prior_realization_fingerprint, receipt.current_realization_fingerprint)
                elif case == "request-fingerprint": receipt = replace(receipt, request_fingerprint="f" * 64)
                elif case == "selection-fingerprint": receipt = replace(receipt, selection_fingerprint="f" * 64)
                elif case == "malformed-receipt":
                    receipt = deepcopy(receipt)
                    object.__setattr__(receipt, "current_realization_fingerprint", "PRIVATE-CANDIDATE")
                    self.assertIs(type(receipt), SecretInstallationReceipt)
                else:
                    if case == "workspace": original = replace(original, source=replace(original.source, workspace_id="foreign"))
                    elif case == "runtime-kind": original = replace(original, runtime_kind=RuntimeKind.KUBERNETES)
                    elif case in ("grants", "authority-deliveries"):
                        original = deepcopy(original)
                        field = "secret_resolution_grants" if case == "grants" else "authority_deliveries"
                        object.__setattr__(original, field, ("PRIVATE-CANDIDATE",))
                    else:
                        material = world.material
                        if case in ("runtime", "node"):
                            material = replace(material, **{case + "_id": "foreign"})
                            if case == "node": original = replace(original,
                                operation=replace(original.operation, target=replace(original.operation.target, node_id="foreign")),
                                products=(material,))
                        elif case == "product": material = replace(material,
                            reference=replace(material.reference, descriptor_sha256=replace(material.reference.descriptor_sha256, value="f" * 64)))
                        elif case == "image": material = replace(material,
                            product=replace(material.product, image=replace(material.product.image, digest="sha256:" + "f" * 64)))
                        else: material = replace(material, secret_selections=(replace(material.secret_selections[0], version_id="foreign-version"),))
                        original = replace(original, products=(material,))
                    if case not in ("grants", "authority-deliveries"):
                        world.installation_request = original
                        world.install_receipt()
                        receipt = world.installation_receipt
                result = self.assert_outcome(world, "refused", installation_request=original, installation_receipt=receipt)
                self.assertIsNone(result.effect_id)
                self.assertIsNone(result.activity_id)
                self.assertEqual(world.initializations + world.api.calls, [])

    def test_fresh_observation_refuses_unexpected_installation_pair(self):
        installation = RetainedWorld()
        world = World(lazy=True)
        self.assert_outcome(world, "refused", installation_request=installation.installation_request,
            installation_receipt=installation.installation_receipt)
        self.assertEqual(world.initializations + world.api.calls, [])

    def test_receipt_incarnation_must_match_even_with_exact_owned_name_and_labels(self):
        for case in ("different-container", "different-receipt", "malformed-provider-id"):
            with self.subTest(case=case):
                world = RetainedWorld()
                if case == "different-receipt": world.install_receipt(container_id="f" * 64)
                else:
                    for container in world.containers:
                        container["Id"] = "f" * 64 if case == "different-container" else "PRIVATE-CANDIDATE"
                self.assert_outcome(world, "unknown")
                self.assertEqual(world.api.calls, [("container", world.name)])

    def test_retained_provider_evidence_preserves_bounded_failure_and_freshness_laws(self):
        for case, calls in (("launch", 2), ("mount", 1), ("stale", 1), ("future-nanosecond", 1),
                ("final-id", 3), ("final-new-sample", 3), ("provider-error", 1)):
            with self.subTest(case=case):
                world = RetainedWorld()
                if case == "launch":
                    world.mutate("Config", "Cmd", ["PRIVATE-CANDIDATE"])
                    for container in world.containers:
                        container["Args"] = container["Config"]["Entrypoint"][1:] + container["Config"]["Cmd"]
                elif case == "mount":
                    for container in world.containers: container["Mounts"][0]["RW"] = True
                elif case == "stale": world.now += timedelta(seconds=11)
                elif case == "future-nanosecond": world.mutate("State", "Health", {"Log": [sample(end="2026-09-24T12:00:02.000000001Z")]})
                elif case == "final-id": world.containers[1]["Id"] = "f" * 64
                elif case == "final-new-sample": world.containers[1]["State"]["Health"]["Log"].append(sample("disconnected"))
                else: world.error = RuntimeError("PRIVATE-CANDIDATE credential error")
                self.assert_outcome(world, "unknown")
                self.assertEqual(len(world.api.calls), calls)

    def test_other_graph_and_artifact_changes_are_outside_closed_content_profile(self):
        for case in ("no-change", "path", "two-files", "wrapper", "declaration", "other-runtime", "gateway", "connector", "add-node", "remove-node", "graph-name"):
            with self.subTest(case=case):
                world = RetainedWorld(lazy=True)
                before = world.current.graph.nodes["workload"]
                after = world.desired.graph.nodes["workload"]
                wrapper, app = before.configuration_artifacts
                if case == "no-change": world.desired = world.current
                elif case == "path": world.desired = validate_graph(world.current.graph.update_node(replace(before,
                    configuration_artifacts=(wrapper, replace(app, target_path="/etc/application/other.json")))))
                elif case == "two-files":
                    second = replace(app, artifact_id="second", target_path="/etc/application/second.json")
                    world.current = validate_graph(world.current.graph.update_node(replace(before,
                        configuration_artifacts=before.configuration_artifacts + (second,))))
                    world.desired = validate_graph(world.desired.graph.update_node(replace(after,
                        configuration_artifacts=after.configuration_artifacts + (replace(second, content='{"mode":"new"}', source_digest=None),))))
                elif case == "wrapper": world.desired = validate_graph(world.current.graph.update_node(replace(before,
                    configuration_artifacts=(replace(wrapper, content=wrapper.content + "\n", source_digest=None), app))))
                elif case == "declaration":
                    surface = replace(world.receiver.declaration.surface, health_reads=(core.NodeHealthReadKind.LIVENESS,))
                    configured = replace(world.receiver, declaration=replace(world.receiver.declaration, surface=surface))
                    changed_wrapper = replace(wrapper,
                        content=core.ReceiverNodeControlConfigurationCodec().encode_bytes(configured).decode(), source_digest=None)
                    world.desired = validate_graph(world.current.graph.update_node(replace(before,
                        block_spec=replace(before.block_spec, control_surfaces=(surface,)),
                        configuration_artifacts=(changed_wrapper, app))))
                elif case == "other-runtime":
                    from control_plane_kit_core.topology import RuntimeRecord
                    pair = []
                    for value in (world.current, world.desired):
                        graph = value.graph
                        node = replace(graph.nodes["workload"], runtime_id="other")
                        configured = replace(world.receiver, target=replace(world.receiver.target,
                            runtime_id=replace(world.receiver.target.runtime_id, value="other")))
                        node = replace(node, configuration_artifacts=(replace(wrapper,
                            content=core.ReceiverNodeControlConfigurationCodec().encode_bytes(configured).decode(), source_digest=None),
                            node.configuration_artifacts[1]))
                        pair.append(validate_graph(replace(graph, nodes={**graph.nodes, "workload": node}, runtimes={
                            "docker": replace(graph.runtimes["docker"], children=("gateway", "connector")),
                            "other": RuntimeRecord("other", RuntimeKind.DOCKER, ("workload",))})))
                    world.current, world.desired = pair
                elif case in ("gateway", "connector"):
                    node = world.desired.graph.nodes[case]
                    world.desired = validate_graph(world.desired.graph.update_node(replace(node, metadata={**node.metadata, "changed": "yes"})))
                elif case in ("add-node", "remove-node"):
                    graph = world.current.graph if case == "add-node" else world.desired.graph
                    reduced = replace(graph, nodes={key:value for key, value in graph.nodes.items() if key != "workload"},
                        runtimes={"docker": replace(graph.runtimes["docker"], children=("gateway", "connector"))})
                    if case == "add-node": world.current = validate_graph(reduced)
                    else: world.desired = validate_graph(reduced)
                else: world.desired = validate_graph(replace(world.desired.graph, name="other"))
                world.recompile_retained(require_ready=False)
                self.assertIsNone(self.qualify(world))
                self.assert_outcome(world, "refused")
                self.assertEqual(world.initializations + world.api.calls, [])

    def test_ready_image_secret_and_verifier_plans_do_not_qualify_as_content_updates(self):
        from control_plane_kit_core.secrets import SecretReference
        for case in ("image", "secret", "verifier"):
            with self.subTest(case=case):
                world = RetainedWorld(lazy=True)
                before = world.current.graph.nodes["workload"]
                if case == "image":
                    before = replace(before, metadata={"product_identity": "fixture/workload/1",
                        "product_descriptor_digest": "a" * 64, "oci_image": "ghcr.io/fixture/workload@sha256:" + "a" * 64})
                    after = replace(before, metadata={"product_identity": "fixture/workload/2",
                        "product_descriptor_digest": "b" * 64, "oci_image": "ghcr.io/fixture/workload@sha256:" + "b" * 64})
                elif case == "secret":
                    delivery = SecretEnvironmentDelivery("APPLICATION_TOKEN", SecretReference("secret://fixture/application"),
                        SecretUseIntent.APPLICATION_CONTROL_TOKEN)
                    selection = SecretVersionSelection(delivery.reference, delivery.intent, "version-one")
                    before = replace(before, secret_deliveries=(delivery,), secret_selections=(selection,))
                    after = replace(before, secret_selections=(replace(selection, version_id="version-two"),))
                else:
                    wrapper, app = before.configuration_artifacts
                    configured = replace(world.receiver, verifiers=tuple(replace(value, issuer=value.issuer + "-new")
                        for value in world.receiver.verifiers))
                    content = core.ReceiverNodeControlConfigurationCodec().encode_bytes(configured).decode()
                    after = replace(before, configuration_artifacts=(replace(wrapper, content=content, source_digest=None), app))
                world.current = validate_graph(world.current.graph.update_node(before))
                world.desired = validate_graph(world.current.graph.update_node(after))
                world.recompile_retained()
                self.assertTrue(world.plan.ready_for_execution)
                self.assertIsNone(self.qualify(world))
                self.assert_outcome(world, "refused")
                self.assertEqual(world.initializations + world.api.calls, [])
