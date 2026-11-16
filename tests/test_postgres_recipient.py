"""Actual SDK normalization over bounded external Docker inspection fixtures."""
from dataclasses import replace
import unittest

import control_plane_kit_core as core
from control_plane_kit_core.receiver_management_routes import ReceiverManagementRouteBinding
from control_plane_kit_interpreters.docker.sdk import DockerSdkClient
from control_plane_kit_interpreters.docker.postgres_recipient import (
    PostgresRecipientUnavailable, observe_postgres_recipient_route,
    require_same_postgres_recipient_route,
)
from test_docker_sdk_client import FakeDockerClient, FakeDockerModule, FakeResource


NETWORK, GATEWAY, POSTGRES, OTHER = (character * 64 for character in "abcd")
STARTED = "2026-11-08T16:00:00.123456789Z"


class PostgresRecipientTests(unittest.TestCase):
    def setUp(self):
        self.raw = FakeDockerClient()
        self.client = DockerSdkClient(docker_module=FakeDockerModule(self.raw))
        roles = core.NodeControlGraphReferenceRole
        target = core.NodeControlReceiverTarget(*(core.NodeControlGraphReference(role, text)
            for role, text in ((roles.WORKSPACE, "workspace-a"), (roles.RUNTIME, "runtime-a"),
                (roles.NODE, "postgres-a"), (roles.PROVIDER_SOCKET, "management"))), "e" * 32)
        declaration = core.WorkloadNodeControlSurfaceDeclaration(
            core.WorkloadNodeControlSurfaceDescriptor(target.provider_socket_name, (),
                health_reads=(core.NodeHealthReadKind.READINESS,)),
            profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2)
        self.route = ReceiverManagementRouteBinding("postgres-management", target,
            declaration, "http://postgres-a:8090")
        self.network = FakeResource("selected")
        self.network.attrs.update(Id=NETWORK, Containers={GATEWAY: {}, POSTGRES: {}})
        self.raw.networks.resources["selected"] = self.network
        self.gateway = self.member(GATEWAY, "gateway-a", "10.0.0.2", ["gateway-a"])
        self.postgres = self.member(POSTGRES, "recipient-container", "10.0.0.3", ["postgres-a"])
        self.reads = []
        inspect_container = self.client.inspect_container
        def bounded_container(identity):
            self.reads.append(identity)
            return inspect_container(identity)
        self.client.inspect_container = bounded_container

    def member(self, identity, name, address, aliases):
        value = FakeResource(name, image="fixture/image", running=True)
        value.attrs.update(Id=identity)
        value.attrs["State"]["StartedAt"] = STARTED
        value.attrs["Config"]["Hostname"] = name
        value.attrs["NetworkSettings"]["Networks"] = {"selected": {
            "NetworkID": NETWORK, "IPAddress": address, "Aliases": aliases,
            "DNSNames": sorted({name, identity[:12], *aliases})}}
        self.raw.containers.resources[identity] = value
        return value

    def observe(self, **changes):
        return observe_postgres_recipient_route(self.client, **{
            "network_name": "selected", "network_id": NETWORK, "gateway_id": GATEWAY,
            "recipient_id": POSTGRES, "route": self.route, "deadline": 105.0,
            "clock": lambda: 100.0, **changes})

    def test_stable_exact_pair_and_alias_snapshot_is_private_and_bounded(self):
        before = self.observe()
        after = self.observe()
        require_same_postgres_recipient_route(before, after)
        self.assertEqual(self.reads, [GATEWAY, POSTGRES] * 2)
        self.assertNotIn(POSTGRES, repr(before))
        self.assertNotIn("10.0.0.3", repr(before))

    def test_same_container_restart_is_not_hidden_by_sdk_snapshot_equality(self):
        before = self.observe()
        self.postgres.attrs["State"]["StartedAt"] = "2026-11-08T16:00:01Z"
        after = self.observe()
        with self.assertRaises(PostgresRecipientUnavailable):
            require_same_postgres_recipient_route(before, after)

    def test_unknown_empty_missing_foreign_or_excessive_membership_refuses(self):
        for participants in (None, {}, {GATEWAY: {}}, {GATEWAY: {}, OTHER: {}},
                {f"{number:064x}": {} for number in range(65)}):
            with self.subTest(participants=type(participants).__name__):
                self.network.attrs["Containers"] = participants
                with self.assertRaises(PostgresRecipientUnavailable):
                    self.observe()
        self.assertEqual(self.reads, [])

    def test_missing_generation_alias_or_attachment_and_stopped_pair_refuse(self):
        for field, value in (("StartedAt", None), ("Running", False)):
            with self.subTest(field=field):
                saved = self.postgres.attrs["State"][field]
                self.postgres.attrs["State"][field] = value
                with self.assertRaises(PostgresRecipientUnavailable):
                    self.observe()
                self.postgres.attrs["State"][field] = saved
        attachment = self.postgres.attrs["NetworkSettings"]["Networks"]["selected"]
        for field, value in (("Aliases", None), ("NetworkID", "f" * 64), ("IPAddress", "")):
            with self.subTest(field=field):
                saved = attachment[field]
                attachment[field] = value
                with self.assertRaises(PostgresRecipientUnavailable):
                    self.observe()
                attachment[field] = saved

    def test_duplicate_alias_or_container_name_and_ambiguous_gateway_network_refuse(self):
        self.network.attrs["Containers"][OTHER] = {}
        other = self.member(OTHER, "other", "10.0.0.4", ["postgres-a"])
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe()
        other.attrs["NetworkSettings"]["Networks"]["selected"]["Aliases"] = ["other"]
        other.name = "postgres-a"
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe()
        del self.network.attrs["Containers"][OTHER]
        self.gateway.attrs["NetworkSettings"]["Networks"]["other"] = {
            "NetworkID": "f" * 64, "IPAddress": "10.1.0.2", "Aliases": ["gateway-a"]}
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe()

    def test_alias_drift_on_third_member_and_network_membership_drift_refuse(self):
        self.network.attrs["Containers"][OTHER] = {}
        other = self.member(OTHER, "other", "10.0.0.4", ["other"])
        before = self.observe()
        other.attrs["NetworkSettings"]["Networks"]["selected"]["Aliases"] = ["other-new"]
        other.attrs["NetworkSettings"]["Networks"]["selected"]["DNSNames"] = [
            "other", OTHER[:12], "other-new"]
        with self.assertRaises(PostgresRecipientUnavailable):
            require_same_postgres_recipient_route(before, self.observe())
        original = self.client.inspect_network
        count = 0
        def changed(name):
            nonlocal count
            count += 1
            result = original(name)
            return replace(result, network_container_ids=(GATEWAY, POSTGRES)) if count == 2 else result
        self.client.inspect_network = changed
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe()

    def test_expired_or_exhausted_read_window_refuses_without_retry(self):
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe(deadline=100.0)
        self.assertEqual(self.reads, [])
        now = [100.0]
        original = self.client.inspect_network
        def delayed(name):
            result = original(name)
            now[0] = 106.0
            return result
        self.client.inspect_network = delayed
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe(clock=lambda: now[0])
        self.assertEqual(self.reads, [])

    def test_literal_numeric_localhost_or_other_dns_alias_is_not_node_route_proof(self):
        attachment = self.postgres.attrs["NetworkSettings"]["Networks"]["selected"]
        for hostname in ("10.0.0.9", "localhost", "127.1", "2130706433", "0x7f000001",
                         "ip6-localhost", "postgres.other", "other-alias"):
            with self.subTest(hostname=hostname):
                attachment["Aliases"] = [hostname]
                attachment["DNSNames"] = ["recipient-container", POSTGRES[:12], hostname]
                candidate = replace(self.route, origin=f"http://{hostname}:8090")
                with self.assertRaises(PostgresRecipientUnavailable):
                    self.observe(route=candidate)
        self.assertEqual(self.reads, [])

    def test_peer_configured_hostname_in_dns_names_alone_refuses(self):
        self.network.attrs["Containers"][OTHER] = {}
        other = self.member(OTHER, "other", "10.0.0.4", ["other"])
        other.attrs["Config"]["Hostname"] = "postgres-a"
        other.attrs["NetworkSettings"]["Networks"]["selected"]["DNSNames"] = [
            "other", OTHER[:12], "postgres-a"]
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe()

    def test_unknown_dns_names_never_fall_back_to_aliases_and_dns_drift_refuses(self):
        attachment = self.postgres.attrs["NetworkSettings"]["Networks"]["selected"]
        names = attachment.pop("DNSNames")
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe()
        attachment["DNSNames"] = []
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe()
        attachment["DNSNames"] = names
        before = self.observe()
        attachment["DNSNames"] = [*names, "another-name"]
        with self.assertRaises(PostgresRecipientUnavailable):
            require_same_postgres_recipient_route(before, self.observe())

    def test_forbidden_legal_graph_id_matching_origin_is_still_not_supported_dns(self):
        attachment = self.postgres.attrs["NetworkSettings"]["Networks"]["selected"]
        # Core rejects localhost and canonical IP literals as graph references.
        # These numeric/non-ordinary IDs are legal Core values, so equality
        # with target.node_id cannot conceal the observer's domain guards.
        for hostname in ("1234", "127.1", "0x7f000001", "ip6-localhost", "postgres.other"):
            with self.subTest(hostname=hostname):
                target = replace(self.route.target, node_id=core.NodeControlGraphReference(
                    core.NodeControlGraphReferenceRole.NODE, hostname))
                candidate = replace(self.route, target=target, origin=f"http://{hostname}:8090")
                attachment["Aliases"] = [hostname]
                attachment["DNSNames"] = ["recipient-container", POSTGRES[:12], hostname]
                with self.assertRaises(PostgresRecipientUnavailable):
                    self.observe(route=candidate)
        self.assertEqual(self.reads, [])

    def test_intended_node_dns_name_must_also_be_an_authored_alias(self):
        # DNSNames can expose a configured hostname without an explicit alias.
        # This observer promises the ordinary authored node-alias convention.
        self.postgres.attrs["NetworkSettings"]["Networks"]["selected"]["Aliases"] = []
        with self.assertRaises(PostgresRecipientUnavailable):
            self.observe()
