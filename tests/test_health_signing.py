"""#155 effect laws, using canonical receiver owners rather than copied verifiers."""
from dataclasses import replace
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
import jwt
import control_plane_kit_core as core
import control_plane_kit_interpreters.probes.gateway as old_signer
from control_plane_kit_core.secrets import SecretDenied, SecretMissing, SecretResolved, SecretUseIntent, SecretValue
from control_plane_kit_server_sdk.verification import (
    Ed25519WorkloadNodeHealthReadVerifier, WorkloadNodeHealthReadVerificationError,
)
from control_plane_kit_server_sdk.verifier_keys import (
    AtomicWorkloadNodeHealthReadVerifierKeySet, WorkloadNodeHealthReadVerifierKeySet,
)
from control_plane_kit_servers_cpk_local_gateway.health_transit_configuration import (
    ARTIFACT_ID, CONFIGURATION_PATH, PROFILE,
)
from control_plane_kit_servers_cpk_local_gateway.health_transit_verification import (
    GatewayHealthTransitVerificationError, gateway_health_transit_verifier_from_artifact,
)
from control_plane_kit_core.configuration import ConfigurationArtifact, ConfigurationFileMode, ConfigurationMediaType
from health_signing_fixtures import Provider, RecordingResolver, key, private_pem, world

MODULE = "control_plane_kit_interpreters.probes.health_signing"


def gateway_artifact(value):
    public = value.publics[0]
    # The actual receiver's declared slot and public configuration schema.
    return ConfigurationArtifact(ARTIFACT_ID, CONFIGURATION_PATH, ConfigurationMediaType.JSON, json.dumps({
        "profile": PROFILE, "workspace_id": value.target.workspace_id.value,
        "gateway_node_id": value.gateway.value, "runtime_id": value.runtime.value,
        "issuer": "transit-issuer", "purpose": core.DelegationKeyPurpose.GATEWAY_NODE_HEALTH_READ_TRANSIT.value,
        "public_keys": [{"key_id": public.key_id, "algorithm": public.algorithm.value,
                         "public_key_pem": public.public_key_pem}],
    }, sort_keys=True, separators=(",", ":")), ConfigurationFileMode.READ_ONLY)


def workload_verifier(value, now=150):
    return Ed25519WorkloadNodeHealthReadVerifier(
        AtomicWorkloadNodeHealthReadVerifierKeySet(WorkloadNodeHealthReadVerifierKeySet(
            core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ, (value.publics[1],))),
        expected_issuer="workload-issuer", expected_audience=core.workload_node_control_audience(value.target),
        clock=lambda: now)


def admit_workload(value, credential, now=150, **changes):
    return workload_verifier(value, now).admit(credential, **{
        "route_kind": value.request.kind, "candidate": None, "expected_target": value.target,
        "expected_runtime_id": value.runtime, "expected_declaration": value.declaration, **changes})


def admit_transit(value, credential, now=150, **changes):
    return gateway_health_transit_verifier_from_artifact(gateway_artifact(value)).verify(
        credential, value.request, **{"expected_attempt_id": "attempt-a", "expected_target": value.target,
        "expected_runtime_id": value.runtime, "expected_declaration": value.declaration,
        "expected_kind": value.request.kind, "now": now, **changes})


class HealthSigningPrerequisiteTests(unittest.TestCase):
    def test_actual_owner_provenance_and_candidate_origin(self):
        for package, coordinate in (
            ("control-plane-kit-servers", "4d781b5b87464d522bd157bab491456e52449a9f"),
            ("control-plane-kit-secrets", "8273b7de86dcaac254a8fcaca22b2769c5e16a4d"),
            ("control-plane-kit-server-sdk", "2c5b588237fbe289c965029b4bc2f072715c42f3"),
        ):
            metadata = json.loads(importlib.metadata.distribution(package).read_text("direct_url.json"))
            self.assertEqual(metadata["url"], f"https://github.com/OpenJ92/{package}/archive/{coordinate}.zip")
        origin = json.loads(importlib.metadata.distribution("control-plane-kit-interpreters").read_text("direct_url.json"))
        self.assertEqual(origin["url"], "file:///app")
        source = Path("/app/src/control_plane_kit_interpreters/probes/gateway.py")
        self.assertEqual(hashlib.sha256(source.read_bytes()).digest(),
                         hashlib.sha256(Path(old_signer.__file__).read_bytes()).digest())

    def test_real_health_provider_and_receiver_configuration_prerequisites(self):
        value = world()
        with tempfile.TemporaryDirectory() as directory:
            provider = Provider(self, directory, value)
            for resolution in value.resolutions:
                self.assertIsInstance(provider.resolver.resolve(resolution), SecretResolved)
            self.assertEqual([item["intent"] for item in provider.calls[-2:]],
                             [resolution.intent.value for resolution in value.resolutions])
            self.assertTrue(callable(gateway_health_transit_verifier_from_artifact(gateway_artifact(value)).verify))
            self.assertIsInstance(workload_verifier(value), Ed25519WorkloadNodeHealthReadVerifier)

    def test_selected_receiver_artifacts_reach_sdk_bytes_and_readonly_mount_specifications(self):
        # This recording-client composition proves the Interpreter boundary only.
        # Real mounted bytes and engine cleanup remain the separate #156 gate.
        from io import BytesIO
        import tarfile
        import test_docker_runtime_interpreter as docker
        from control_plane_kit_core.planning import StartNode, NodeTarget
        from control_plane_kit_core.operations.execution import EffectResultKind
        default, selected = world(), world()

        def artifacts(value):
            public = value.publics[1]
            family = {"issuer": "workload-issuer", "public_keys": [{
                "key_id": public.key_id, "algorithm": public.algorithm.value,
                "public_key_pem": public.public_key_pem}]}
            content = json.dumps({"profile": "cpk-control-configuration.v1",
                "target": value.target.descriptor(), "runtime_id": value.runtime.value,
                "declaration": value.declaration.descriptor(),
                "surface_read": family, "health_read": family}, sort_keys=True)
            return (gateway_artifact(value), ConfigurationArtifact("cpk-control",
                "/etc/cpk/cpk-server/control.json", ConfigurationMediaType.JSON, content))

        original, chosen = artifacts(default), artifacts(selected)
        product = docker._product()
        product = replace(product, runtime_contract=replace(product.runtime_contract, configuration_artifacts=original))
        material = docker._material(product)
        # This is the existing public output of Operations' selected-node join.
        material = replace(material, product=replace(product,
            runtime_contract=replace(product.runtime_contract, configuration_artifacts=chosen)))
        raw = docker.FakeDockerClient()
        sdk = docker.DockerSdkClient(client=raw, docker_module=docker.FakeDockerModule(raw))
        interpreter = docker.DockerRuntimeInterpreter(sdk)
        request = docker._request(StartNode(NodeTarget("api")), products=(material,))
        first = interpreter.execute(request)
        self.assertIs(first.kind, EffectResultKind.SUCCEEDED)
        volumes = docker._configuration_volumes(raw)
        self.assertEqual(len(volumes), 2)
        mounts = docker._workload_container_record(raw)["mounts"]
        for expected, old in zip(chosen, original, strict=True):
            self.assertNotEqual(expected.content_digest, old.content_digest)
            volume = next(item for item in volumes
                if item["labels"]["org.openj92.cpk.artifact.digest"] == expected.content_digest)
            with tarfile.open(fileobj=BytesIO(raw.containers.volume_archives[volume["name"]]["/artifact"]), mode="r") as archive:
                self.assertEqual(archive.extractfile("content").read(), expected.content.encode("utf-8"))
            self.assertIn({"Type": "volume", "Source": volume["name"],
                "Target": expected.target_path, "ReadOnly": True,
                "VolumeOptions": {"Subpath": "content"}}, mounts)
        volume = volumes[0]
        raw.containers.resources.pop(str(first.evidence["container"]))
        raw.containers.volume_archives[volume["name"]].clear()
        sdk.materialize_configuration_artifact(volume["name"], original[0])
        raw.images.pulled.clear()
        result = interpreter.execute(request)
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.configuration-digest-conflict")
        self.assertEqual(raw.images.pulled, [])
        self.assertEqual(len(docker._workload_container_records(raw)), 1)


class HealthCredentialPairTests(unittest.TestCase):
    def setUp(self):
        self.value = world()
        self.resolver = RecordingResolver(self.value)
        # Deliberate causal red, after existing Core/owner imports and fixture construction.
        self.assertIsNotNone(importlib.util.find_spec(MODULE), "#155 paired health signer is missing")
        self.api = importlib.import_module(MODULE)
        self.context = self.api.HealthSigningContext(self.value.request, "attempt-a", self.value.gateway,
            self.value.declaration, "transit-issuer", "workload-issuer")

    def arguments(self):
        value = self.value
        return dict(transit_grant=value.transit, workload_grant=value.workload,
            transit_key=self.api.HealthSigningKey(value.publics[0], value.resolutions[0]),
            workload_key=self.api.HealthSigningKey(value.publics[1], value.resolutions[1]))

    def sign(self, *, resolver=None, clock=lambda: 150, context=None, **changes):
        return self.api.Ed25519HealthCredentialPairSigner(
            self.resolver if resolver is None else resolver, clock).sign(
                self.context if context is None else context, **{**self.arguments(), **changes})

    def refused(self, action):
        # Synthetic resolver failures cannot justify opening any HTTP client.
        with patch.object(httpx, "Client") as network:
            with self.assertRaises(self.api.HealthCredentialSigningError) as caught:
                action()
            network.assert_not_called()
        error = caught.exception
        self.assertEqual(str(error), "health credential signing failed")
        self.assertEqual(vars(error), {})
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        return error

    def test_both_actual_receivers_admit_exact_original_request_and_claims(self):
        pair = self.sign()
        self.assertEqual(pair.request, self.value.request)
        self.assertEqual(self.resolver.calls, list(self.value.resolutions))
        self.assertEqual(admit_transit(self.value, pair.transit_credential), self.value.request)
        self.assertEqual(admit_workload(self.value, pair.workload_credential), self.value.request)
        for credential, grant, claim, typ in (
            (pair.transit_credential, self.value.transit, "gateway_node_health_read_transit",
                "CPK-GATEWAY-NODE-HEALTH-READ-TRANSIT+JWT"),
            (pair.workload_credential, self.value.workload, "workload_node_health_read",
                "CPK-WORKLOAD-NODE-HEALTH-READ+JWT"),
        ):
            self.assertIs(type(credential), bytes)
            self.assertEqual(jwt.get_unverified_header(credential), {"alg": "EdDSA", "kid": grant.key_id, "typ": typ})
            # Owner verifiers above already authenticate; this only checks representation fidelity.
            self.assertEqual(jwt.decode(credential, options={"verify_signature": False}),
                {"iss": grant.issuer, "aud": grant.audience, "iat": grant.issued_at,
                 "nbf": grant.not_before, "exp": grant.expires_at, "jti": grant.jti, claim: grant.descriptor()})
            self.assertNotIn(credential.decode("ascii"), repr(pair))
        again = self.sign()
        self.assertEqual(again.request.canonical_digest(), pair.request.canonical_digest())
        self.assertEqual(again.request.request_id, pair.request.request_id)

    def test_actual_receivers_refuse_wrong_local_context_expiry_and_other_family(self):
        pair = self.sign()
        for action in (
            lambda: admit_transit(self.value, pair.transit_credential, expected_attempt_id="attempt-b"),
            lambda: admit_transit(self.value, pair.transit_credential, now=200),
            lambda: admit_transit(self.value, pair.workload_credential),
        ):
            with self.assertRaises(GatewayHealthTransitVerificationError):
                action()
        for action in (
            lambda: admit_workload(self.value, pair.workload_credential,
                expected_runtime_id=replace(self.value.runtime, value="runtime-b")),
            lambda: admit_workload(self.value, pair.workload_credential, now=200),
            lambda: admit_workload(self.value, pair.transit_credential),
        ):
            with self.assertRaises(WorkloadNodeHealthReadVerificationError):
                action()

    def test_both_families_are_preflighted_before_either_material_resolution(self):
        value = self.value
        wrong_resolution = replace(value.resolutions[1], intent=SecretUseIntent.GATEWAY_PROBE_SIGNING_KEY)
        arguments = self.arguments()
        for changes in (
            {"workload_grant": None}, {"transit_key": None},
            {"transit_grant": replace(value.transit, attempt_id="attempt-b")},
            {"workload_grant": replace(value.workload, request_id="observation-b")},
            {"workload_grant": replace(value.workload, runtime_id=replace(value.runtime, value="runtime-b"))},
            {"workload_grant": replace(value.workload, expires_at=199)},
            {"workload_key": self.api.HealthSigningKey(value.publics[1], wrong_resolution)},
            {"workload_key": self.api.HealthSigningKey(value.publics[1], replace(value.resolutions[1], operation_id="attempt-b"))},
            {"workload_key": self.api.HealthSigningKey(value.publics[1], replace(value.resolutions[1], workspace_id="workspace-b"))},
            {"workload_key": self.api.HealthSigningKey(value.publics[1], replace(value.resolutions[1], session_id="session-b"))},
            {"workload_key": self.api.HealthSigningKey(value.publics[1], replace(value.resolutions[1], reference=value.resolutions[0].reference))},
            {"workload_key": arguments["transit_key"]},
        ):
            with self.subTest(fields=tuple(changes)):
                self.refused(lambda: self.sign(**changes))
                self.assertEqual(self.resolver.calls, [])
        self.refused(lambda: self.sign(context=replace(self.context,
            request=replace(value.request, declaration_identity=replace(value.request.declaration_identity, value="a" * 64)))))
        self.assertEqual(self.resolver.calls, [])

    def test_original_window_is_checked_before_between_and_after_effects(self):
        for now in (100, 200, True, -1):
            with self.subTest(now=now):
                self.refused(lambda: self.sign(clock=lambda: now))
                self.assertEqual(self.resolver.calls, [])
        for expires_after in (1, 2):
            self.resolver.calls.clear()
            self.refused(lambda: self.sign(clock=lambda: 200 if len(self.resolver.calls) >= expires_after else 150))
            self.assertEqual(len(self.resolver.calls), expires_after)
        self.resolver.calls.clear()
        encoded = []
        original = jwt.encode

        def slow_encode(*args, **kwargs):
            result = original(*args, **kwargs)
            encoded.append(True)
            return result

        with patch.object(jwt, "encode", side_effect=slow_encode):
            self.refused(lambda: self.sign(clock=lambda: 200 if encoded else 150))
        self.assertTrue(encoded)

    def test_partial_resolution_and_wrong_private_identity_publish_no_pair(self):
        value = self.value
        for index in (0, 1):
            reference = value.resolutions[index].reference
            for result in (SecretMissing(reference), SecretDenied(reference),
                    SecretResolved(value.resolutions[1 - index].reference, SecretValue("substituted")),
                    SecretResolved(reference, SecretValue("hostile-private-sentinel")),
                    SecretResolved(reference, SecretValue(private_pem(key("other")[0]))),
                    RuntimeError("hostile-provider-payload")):
                with self.subTest(family=index, result_type=type(result).__name__):
                    self.resolver = RecordingResolver(value)
                    self.resolver.results[reference] = result
                    error = self.refused(self.sign)
                    self.assertLessEqual(len(self.resolver.calls), index + 1)
                    self.assertNotIn("hostile", repr(error))
                    self.assertNotIn(private_pem(value.privates[index]), repr(error))

    def test_real_provider_exact_health_purposes_flow_into_receiver_accepted_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = Provider(self, directory, self.value)
            pair = self.sign(resolver=provider.resolver)
            self.assertEqual(admit_transit(self.value, pair.transit_credential), self.value.request)
            self.assertEqual(admit_workload(self.value, pair.workload_credential), self.value.request)
            self.assertEqual([(item["intent"], item["correlation_id"]) for item in provider.calls[-2:]],
                [(grant.intent.value, grant.correlation_id) for grant in self.value.resolutions])

    def test_context_key_and_signer_representations_hide_protected_inputs(self):
        arguments = self.arguments()
        values = (self.context, arguments["transit_key"], arguments["workload_key"],
            self.api.Ed25519HealthCredentialPairSigner(self.resolver, lambda: 150))
        protected = tuple(grant.reference.reference_id for grant in self.value.resolutions)
        for value in values:
            for sentinel in (*protected, "attempt-a", "observation-a"):
                self.assertNotIn(sentinel, repr(value))
