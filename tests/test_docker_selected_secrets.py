"""Selected consumer laws at the archive-backed runtime/SDK boundary (#191)."""
from dataclasses import replace
from io import BytesIO
from types import SimpleNamespace
import json
import tarfile
import unittest
from unittest.mock import patch

from control_plane_kit_core.planning import NodeTarget, ReconcileNode
from control_plane_kit_core.runtime_effects import EffectResultKind, RuntimeEffectKind
from control_plane_kit_core.runtime_effect_observation import runtime_effect_intent_for_request, runtime_effect_intent_fingerprint, runtime_effect_result_fingerprint
from control_plane_kit_core.secret_installation import secret_installation_receipt_for_result, secret_material_selection_fingerprint
from control_plane_kit_core.secret_selections import SecretVersionSelection
from control_plane_kit_core.secret_version_grants import SecretVersionResolutionGrant
from control_plane_kit_core.secrets import SecretEnvironmentDelivery, SecretFileDelivery, SecretFilePathBinding, SecretReference, SecretUseIntent, SecretResolved, SecretValue
from configuration_replacement_fixtures import fixture, selected_request
from test_docker_runtime_interpreter import _grant
from test_docker_installation_receipts import expected_identity
from test_docker_sdk_client import FakeImage


REFERENCE = SecretReference("secret://provider-a/app/token")
INTENT = SecretUseIntent.APPLICATION_CONTROL_TOKEN
LOCAL = SimpleNamespace(runtime_kind="docker", authority_kind="local-docker-socket")


def request_for(*, version="version-a", reconcile=False, files=True, file_count=1, configuration=False, grants=True):
    request = selected_request(reconcile=reconcile)
    material = request.products[0]
    deliveries = (SecretEnvironmentDelivery("APP_TOKEN", REFERENCE, INTENT),)
    if files:
        deliveries += tuple(SecretFileDelivery(
            "/run/secrets/token" if file_count == 1 else f"/run/secrets/token-{index}", REFERENCE, INTENT,
            path_binding=SecretFilePathBinding("APP_TOKEN_FILE") if file_count == 1 else None)
            for index in range(file_count))
    product = replace(material.product, runtime_contract=replace(material.product.runtime_contract,
        secret_deliveries=deliveries, configuration_artifacts=(material.product.runtime_contract.configuration_artifacts if configuration else ())))
    selection = SecretVersionSelection(REFERENCE, INTENT, version)
    request = replace(request, products=(replace(material, product=product, secret_selections=(selection,)),),
        kind=request.kind if configuration else RuntimeEffectKind.REALIZE_ACTIVITY,
        configuration_instances=request.configuration_instances if configuration else None)
    if not grants:
        return request
    operational = _grant(REFERENCE, INTENT)
    grant = SecretVersionResolutionGrant(
        authorization_id=operational.authorization_id, workspace_id=request.source.workspace_id,
        reference_registration_id=operational.reference_registration_id,
        provider_registration_id=operational.provider_registration_id,
        endpoint_reference=operational.endpoint_reference, credential_reference=operational.credential_reference,
        selection=selection, actor_subject=operational.actor_subject, correlation_id="selected-" + version,
        intent_fingerprint=operational.intent_fingerprint, operation_id=request.source.request_id,
        run_id=request.source.run_id.value, activity_id=request.activity_id.value, effect_id=request.effect_id,
        request_fingerprint=runtime_effect_intent_fingerprint(runtime_effect_intent_for_request(request)),
        selection_fingerprint=secret_material_selection_fingerprint(request))
    return replace(request, secret_resolution_grants=(grant,))


class SelectedResolver:
    def __init__(self):
        self.calls = []

    def resolve(self, grant):
        self.calls.append(grant)
        if type(grant) is not SecretVersionResolutionGrant:
            raise AssertionError("consumer must receive exact version grant")
        return SecretResolved(grant.selection.reference, SecretValue("private-" + grant.selection.version_id))


def selected_fixture(request, *, user="10006"):
    raw, sdk, interpreter, events = fixture()
    image = request.products[0].product.image.execution_reference
    raw.images.resources[image] = FakeImage([], repo_digests=(image,))
    raw.images.resources[image].attrs["Config"]["User"] = user
    resolver = SelectedResolver()
    return raw, sdk, replace(interpreter, authorized_secret_resolver=resolver), events, resolver


class DockerSelectedSecretTests(unittest.TestCase):
    def receipt(self, request, result):
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED, repr(result))
        receipt = secret_installation_receipt_for_result(request, result)
        self.assertIsNotNone(receipt)
        runtime_effect_result_fingerprint(result)
        self.assertNotIn("private-version", json.dumps(result.descriptor()))
        return receipt

    def test_missing_consumer_grant_refuses_before_authority_client_or_provider(self):
        request = request_for(grants=False)
        for authority in (False, True):
            with self.subTest(authority=authority):
                raw, sdk, interpreter, events, resolver = selected_fixture(request)
                with patch("control_plane_kit_interpreters.docker.runtime._client_for_runtime_authority") as binding:
                    result = interpreter.execute_with_authority(request, LOCAL) if authority else interpreter.execute(request)
                self.assertIs(result.kind, EffectResultKind.FAILED)
                binding.assert_not_called()
                self.assertEqual(events, [])
                self.assertEqual(resolver.calls, [])

    def test_created_reused_and_replaced_receipts_follow_actual_recipient(self):
        for configuration in (False, True):
            for authority in (False, True):
                with self.subTest(configuration=configuration, authority=authority):
                    request = request_for(configuration=configuration)
                    raw, sdk, interpreter, events, resolver = selected_fixture(request)
                    execute = lambda value: interpreter.execute_with_authority(value, LOCAL) if authority else interpreter.execute(value)
                    first = execute(request)
                    receipt = self.receipt(request, first)
                    self.assertEqual(receipt.disposition.value, "created")
                    old_id = first.evidence["secret_attempt"]["container_id"]
                    self.assertEqual(receipt.current_realization_fingerprint, expected_identity(old_id))
                    old_volumes = dict(raw.containers.volume_archives)
                    self.assertTrue(any(event[:3] == ("read", "workload", old_id) for event in events))
                    replay = execute(request)
                    reused = self.receipt(request, replay)
                    self.assertEqual(reused.disposition.value, "reused")
                    self.assertEqual(replay.evidence["secret_attempt"]["container_id"], old_id)
                    self.assertEqual(reused.current_realization_fingerprint, expected_identity(old_id))
                    self.assertEqual(reused.prior_realization_fingerprint, expected_identity(old_id))
                    changed = request_for(version="version-b", reconcile=True, configuration=configuration)
                    result = execute(changed)
                    replacement = self.receipt(changed, result)
                    self.assertEqual(replacement.disposition.value, "replaced")
                    self.assertEqual(replacement.prior_realization_fingerprint, receipt.current_realization_fingerprint)
                    self.assertNotEqual(result.evidence["secret_attempt"]["container_id"], old_id)
                    self.assertEqual(replacement.current_realization_fingerprint,
                        expected_identity(result.evidence["secret_attempt"]["container_id"]))
                    self.assertEqual(result.evidence["secret_attempt"]["secret_volumes_removed"], 0)
                    for name, archive in old_volumes.items():
                        self.assertEqual(raw.containers.volume_archives[name], archive)
                    self.assertEqual("configuration_invocation_completion" in result.evidence, configuration)

    def test_forged_grant_binding_refuses_before_all_io(self):
        for field, value in (("workspace_id", "another-workspace"), ("effect_id", "another-effect"),
                ("request_fingerprint", "f" * 64), ("selection_fingerprint", "e" * 64),
                ("authorization_id", "")):
            for authority in (False, True):
                with self.subTest(field=field, authority=authority):
                    request = request_for()
                    object.__setattr__(request.secret_resolution_grants[0], field, value)
                    raw, sdk, interpreter, events, resolver = selected_fixture(request)
                    with patch("control_plane_kit_interpreters.docker.runtime._client_for_runtime_authority") as binding:
                        result = interpreter.execute_with_authority(request, LOCAL) if authority else interpreter.execute(request)
                    self.assertIs(result.kind, EffectResultKind.FAILED)
                    self.assertEqual(result.failure.code, "docker.runtime-request-invalid")
                    binding.assert_not_called()
                    self.assertEqual(events, [])
                    self.assertEqual(resolver.calls, [])
                    self.assertEqual(raw.volumes.created, [])

    def test_invalid_resolved_environment_refuses_before_mutation(self):
        for payload in ("invalid\x00environment", "", None, "x" * 65_537):
            with self.subTest(payload_kind=type(payload).__name__, empty=payload == ""):
                request = request_for()
                raw, sdk, interpreter, events, resolver = selected_fixture(request)
                value = SecretValue("valid")
                object.__setattr__(value, "_value", payload)
                with patch.object(resolver, "resolve", return_value=SecretResolved(REFERENCE, value)):
                    result = interpreter.execute(request)
                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertEqual(raw.networks.created, [])
                self.assertEqual(raw.volumes.created, [])
                self.assertEqual(raw.containers.created, [])
                self.assertNotIn("invalid", repr(result.evidence))

    def test_volume_creation_with_unverified_ownership_remains_uncertain(self):
        for configuration in (False, True):
            with self.subTest(configuration=configuration):
                request = request_for(configuration=configuration)
                raw, sdk, interpreter, events, resolver = selected_fixture(request)
                create = sdk.create_volume
                def corrupt(*, name, labels):
                    create(name=name, labels=labels)
                    if labels.get("org.openj92.cpk.volume.kind") == "secret-file":
                        raw.volumes.resources[name].attrs["Config"]["Labels"]["org.openj92.cpk.secret.identity"] = "wrong"
                with patch.object(sdk, "create_volume", side_effect=corrupt):
                    result = interpreter.execute(request)
                self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                attempt = result.evidence["secret_attempt"]
                self.assertTrue(attempt["unknown_created_resource"])
                self.assertEqual(attempt["attempted_indices"], [0])
                self.assertEqual(attempt["staged_indices"], [])
                self.assertEqual(attempt["secret_volumes_removed"], 0)
                self.assertNotIn("secret_installation_receipt", result.evidence)
                self.assertNotIn("configuration_invocation_completion", result.evidence)

    def test_authority_close_fault_strips_all_installation_attestations(self):
        for configuration in (False, True):
            with self.subTest(configuration=configuration):
                request = request_for(configuration=configuration)
                raw, sdk, interpreter, events, resolver = selected_fixture(request)
                binding = SimpleNamespace(client=sdk, close_after_execution=True)
                verified = []
                verify = sdk.verify_secret_recipient
                def verified_recipient(*args, **kwargs):
                    verify(*args, **kwargs)
                    verified.append(True)
                with patch("control_plane_kit_interpreters.docker.runtime._client_for_runtime_authority", return_value=binding), \
                        patch.object(sdk, "verify_secret_recipient", side_effect=verified_recipient), \
                        patch.object(sdk, "close", side_effect=TimeoutError("private-close-detail")):
                    result = interpreter.execute_with_authority(request, LOCAL)
                self.assertEqual(verified, [True])
                self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                self.assertTrue(result.evidence["secret_attempt"]["authority_close_unknown"])
                for key in ("secret_installation_receipt", "secret_resolution_receipt",
                        "configuration_installation_receipt", "configuration_invocation_completion"):
                    self.assertNotIn(key, result.evidence)
                self.assertEqual(result.observations, ())
                self.assertNotIn("private-close-detail", repr(result))
                runtime_effect_result_fingerprint(result)

    def test_environment_only_named_user_does_not_require_numeric_uid(self):
        request = request_for(files=False)
        raw, sdk, interpreter, events, resolver = selected_fixture(request, user="service")
        result = interpreter.execute(request)
        self.receipt(request, result)
        self.assertIsNone(result.evidence["secret_attempt"]["file_owner_uid"])

    def test_same_version_new_image_uid_has_new_immutable_file_identity(self):
        request = request_for()
        raw, sdk, interpreter, events, resolver = selected_fixture(request)
        first = interpreter.execute(request)
        self.receipt(request, first)
        old_volumes = dict(raw.containers.volume_archives)
        changed = request_for(reconcile=True)
        material = changed.products[0]
        image = replace(material.product.image, digest="sha256:" + "c" * 64)
        changed = replace(changed, secret_resolution_grants=(), products=(replace(material,
            product=replace(material.product, image=image)),))
        grant = request_for(reconcile=True).secret_resolution_grants[0]
        changed = replace(changed, secret_resolution_grants=(replace(grant,
            request_fingerprint=runtime_effect_intent_fingerprint(runtime_effect_intent_for_request(changed))),))
        raw.images.resources[image.execution_reference] = FakeImage([], image_id="sha256:" + "d" * 64,
            repo_digests=(image.execution_reference,))
        raw.images.resources[image.execution_reference].attrs["Config"]["User"] = "10007"
        result = interpreter.execute(changed)
        self.receipt(changed, result)
        self.assertEqual(result.evidence["secret_attempt"]["file_owner_uid"], 10007)
        self.assertTrue(set(raw.containers.volume_archives) - set(old_volumes))
        for name, archive in old_volumes.items():
            self.assertEqual(raw.containers.volume_archives[name], archive)

    def test_wrong_private_environment_mount_or_archive_never_attests(self):
        for case in ("env", "duplicate-env", "mount", "readback"):
            with self.subTest(case=case):
                request = request_for()
                raw, sdk, interpreter, events, resolver = selected_fixture(request)
                def corrupt(resource):
                    if case == "env":
                        resource.attrs["Config"]["Env"] = ["APP_TOKEN=wrong", "APP_TOKEN_FILE=/run/secrets/token"]
                    elif case == "duplicate-env":
                        resource.attrs["Config"].setdefault("Env", []).append("APP_TOKEN=wrong")
                    elif case == "mount":
                        resource.attrs["Mounts"][0]["RW"] = True
                    else:
                        resource.get_archive = lambda path: (_ for _ in ()).throw(TimeoutError("private-detail"))
                raw.containers.after_create = corrupt
                result = interpreter.execute(request)
                self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                self.assertNotIn("secret_installation_receipt", result.evidence)
                self.assertNotIn("secret_resolution_receipt", result.evidence)
                self.assertNotIn("private-detail", repr(result))
                self.assertTrue(result.evidence["secret_attempt"]["staged_indices"])
                runtime_effect_result_fingerprint(result)

    def test_partial_staging_preserves_bounded_unknown_residue(self):
        request = request_for()
        raw, sdk, interpreter, events, resolver = selected_fixture(request)
        original = sdk.materialize_secret_file
        def uncertain(*args, **kwargs):
            original(*args, **kwargs)
            raise TimeoutError("private-detail")
        with patch.object(sdk, "materialize_secret_file", side_effect=uncertain):
            result = interpreter.execute(request)
        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        attempt = result.evidence["secret_attempt"]
        self.assertEqual(attempt["attempted_indices"], [0])
        self.assertEqual(attempt["staged_indices"], [])
        self.assertTrue(attempt["unknown_materialization"])
        self.assertEqual(attempt["secret_volumes_removed"], 0)
        self.assertNotIn("private-detail", repr(result))
        self.assertNotIn("secret_installation_receipt", result.evidence)

    def test_actual_recipient_archive_negatives_never_attest(self):
        for defect in ("bytes", "uid", "mode", "symlink", "name", "extra-member", "chunks", "size"):
            with self.subTest(defect=defect):
                request = request_for()
                raw, sdk, interpreter, events, resolver = selected_fixture(request)
                output = BytesIO()
                with tarfile.open(fileobj=output, mode="w") as archive:
                    content = b"wrong-private-value" if defect == "bytes" else b"private-version-a"
                    member = tarfile.TarInfo("wrong" if defect == "name" else "token")
                    member.uid = 10007 if defect == "uid" else 10006
                    member.mode = 0o444 if defect == "mode" else 0o400
                    member.size = len(content)
                    if defect == "symlink":
                        member.type, member.linkname = tarfile.SYMTYPE, "/elsewhere"
                    archive.addfile(member, BytesIO(content))
                    if defect == "extra-member":
                        archive.addfile(tarfile.TarInfo("extra"))
                chunks = ([b""] * 1025 if defect == "chunks" else
                    [b"x" * (16_777_216 + 1)] if defect == "size" else [output.getvalue()])
                raw.containers.after_create = lambda resource: setattr(resource, "get_archive", lambda path: (chunks, {}))
                result = interpreter.execute(request)
                self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                self.assertNotIn("secret_installation_receipt", result.evidence)
                self.assertNotIn("wrong-private-value", repr(result))
                self.assertNotIn("private-version-a", repr(result))
                runtime_effect_result_fingerprint(result)

    def test_file_slot_capacity_is_admitted_before_authority_or_resolution(self):
        request = request_for(file_count=33)
        raw, sdk, interpreter, events, resolver = selected_fixture(request)
        with patch("control_plane_kit_interpreters.docker.runtime._client_for_runtime_authority") as binding:
            result = interpreter.execute_with_authority(request, LOCAL)
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.secret-result-capacity")
        binding.assert_not_called()
        self.assertEqual(events, [])
        self.assertEqual(resolver.calls, [])

    def test_maximum_file_slots_share_exact_resolution_and_fit_complete_result(self):
        request = request_for(file_count=32)
        raw, sdk, interpreter, events, resolver = selected_fixture(request)
        result = interpreter.execute(request)
        self.receipt(request, result)
        self.assertEqual(resolver.calls, list(request.secret_resolution_grants))
        attempt = result.evidence["secret_attempt"]
        self.assertEqual(attempt["attempted_indices"], list(range(32)))
        self.assertEqual(attempt["staged_indices"], list(range(32)))
        self.assertEqual(attempt["file_identity_profile"], "docker.selected-secret-file.v1")

    def test_passive_observer_cannot_attest_selected_installation(self):
        from control_plane_kit_core.runtime_effect_observation import RuntimeEffectObservationRequest, RuntimeEffectObserverUnsupported
        from control_plane_kit_interpreters.docker.observer import DockerRuntimeEffectObserver
        request = request_for()
        raw, sdk, interpreter, events, resolver = selected_fixture(request)
        self.receipt(request, interpreter.execute(request))
        events.clear()
        resolver.calls.clear()
        result = DockerRuntimeEffectObserver(sdk, authorized_secret_resolver=resolver).observe(
            RuntimeEffectObservationRequest(request), None)
        self.assertIs(type(result), RuntimeEffectObserverUnsupported)
        self.assertEqual(events, [])
        self.assertEqual(resolver.calls, [])
