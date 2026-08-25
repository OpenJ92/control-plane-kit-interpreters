from __future__ import annotations

from dataclasses import dataclass, replace
import unittest

from control_plane_kit_core.configuration import (
    ConfigurationArtifact,
    ConfigurationFileMode,
    ConfigurationMediaType,
)
from control_plane_kit_core.operations.execution import EffectResultKind
from control_plane_kit_core.planning import ActivityId, NodeTarget, StartNode
from control_plane_kit_core.products import (
    ProductDescriptorCodec,
    ProductDescriptorDigest,
    ProductReference,
)
from control_plane_kit_core.runtime_effects import (
    ImagePullAuthority,
    RuntimeEffectKind,
    RuntimeEffectRequest,
    RuntimeEffectSource,
    RuntimeProductMaterial,
)
from control_plane_kit_core.secrets import SecretReference, SecretValue
from control_plane_kit_core.types import RuntimeKind

from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter
from control_plane_kit_interpreters.docker.runtime import _node_labels
from control_plane_kit_interpreters.secrets import (
    ImagePullCredentialMissing,
    ImagePullCredentialResolved,
    ResolvedImagePullCredential,
)


HELLO_REFERENCE = (
    "ghcr.io/openj92/control-plane-kit-servers/hello-server@"
    "sha256:e2288b23844b1f0b7526d2798cbc1eaf6e9f536399173a043e7957f0e7730cbf"
)
HELLO_IMAGE_ID = "sha256:bd7a0b049edc893702471a199286ea28a949c670f2b46aaad79e8bcbaf822976"
HELLO_DESCRIPTOR_SHA256 = (
    "57ac661ca3f73ad4fa488df34390240e95da58e302bffb17c2197eeac29c2a24"
)
HELLO_DOCUMENT = (
    b'{"schema":"control-plane-kit.product","product":{"kind":"container-server",'
    b'"identity":{"namespace":"control-plane-kit","name":"hello-server","contract_revision":1},'
    b'"image":{"registry":"ghcr.io","repository":"openj92/control-plane-kit-servers/hello-server",'
    b'"digest":"sha256:e2288b23844b1f0b7526d2798cbc1eaf6e9f536399173a043e7957f0e7730cbf",'
    b'"tag":"seeded-stress-955-observer","platforms":[],"provenance":{"dockerfile":'
    b'"products/hello_server/Dockerfile","publish":"ghcr","source-commit":'
    b'"e5bd98ec68451fc4b0634a604e5d4b5fc6301080"}},"runtime_contract":{"sockets":'
    b'{"requirements":{},"providers":{"internal":{"protocol":{"transport":"tcp",'
    b'"application":"http"}}}},"provider_ports":[{"provider_socket":"internal",'
    b'"container_port":8000}],"public_environment":[{"kind":"public-static",'
    b'"name":"HELLO_DEPENDENCIES_JSON","value":"[]"},{"kind":"public-static",'
    b'"name":"HELLO_MESSAGE","value":"Hello, world!"}],"configuration_artifacts":[], '
    b'"secret_deliveries":[],"retained_data_mounts":[],"capabilities":["health-checkable"],'
    b'"verification":{"checks":[{"kind":"http","check_id":"live","provider_socket":'
    b'"internal","policy":{"timeout_seconds":5.0,"interval_seconds":1.0,'
    b'"maximum_attempts":5,"maximum_evidence_bytes":16384},"path":"/health/live",'
    b'"expected_statuses":[200]},{"kind":"http","check_id":"ready","provider_socket":'
    b'"internal","policy":{"timeout_seconds":5.0,"interval_seconds":1.0,'
    b'"maximum_attempts":5,"maximum_evidence_bytes":16384},"path":"/health/ready",'
    b'"expected_statuses":[200]}]},"lifecycle":{"ownership":"owned","compute":"ephemeral",'
    b'"data":[]}},"display_name":"hello-server","description":"Small HTTP application product for '
    b'control-plane-kit operations acceptance. The base product provides HTTP and reads HELLO_MESSAGE '
    b'plus optional dependency declarations from runtime environment. Dynamic per-instance dependency '
    b'sockets remain an operations product-parameterization handoff.","product_family":"server"}}'
).replace(b'[], "secret', b'[],"secret')


@dataclass(frozen=True)
class _ImageInspection:
    image_id: str
    repo_digests: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ResourceInspection:
    name: str
    running: bool
    image: str | None
    labels: dict[str, str]
    image_id: str | None = None
    network_names: tuple[str, ...] = ()
    published_ports: tuple[object, ...] = ()
    private_addresses: dict[str, str] | None = None


class _PhaseClient:
    def __init__(
        self,
        *,
        cached_image: bool = True,
        fail_at: str | None = None,
        final_running: bool = True,
        final_image_id: str = HELLO_IMAGE_ID,
        include_intended_network: bool = True,
        extra_network: bool = False,
        final_missing: bool = False,
        final_labels: dict[str, str] | None = None,
        cached_repo_digests: tuple[str, ...] = (HELLO_REFERENCE,),
        pulled_repo_digests: tuple[str, ...] = (HELLO_REFERENCE,),
    ) -> None:
        self.cached_image = cached_image
        self.fail_at = fail_at
        self.final_running = final_running
        self.final_image_id = final_image_id
        self.include_intended_network = include_intended_network
        self.extra_network = extra_network
        self.final_missing = final_missing
        self.final_labels = final_labels
        self.cached_repo_digests = cached_repo_digests
        self.pulled_repo_digests = pulled_repo_digests
        self.network_name: str | None = None
        self.network_labels: dict[str, str] | None = None
        self.container_name: str | None = None
        self.container_labels: dict[str, str] | None = None
        self.container_create_kwargs: dict[str, object] = {}
        self.container_created = False
        self.container_network_name: str | None = None
        self.container_started = False
        self.container_inspections = 0
        self.pull_calls: list[tuple[str, object]] = []
        self.image_inspect_references: list[str] = []
        self.calls: list[str] = []
        self.volume_names: list[str] = []

    def inspect_network(self, name: str):
        self.calls.append("network-inspect")
        self._fail("network-inspect")
        if self.network_name is None:
            return None
        return _ResourceInspection(name, False, None, dict(self.network_labels or {}))

    def create_network(self, *, name: str, labels: dict[str, str]) -> None:
        self.calls.append("network-create")
        self._fail("network-create")
        self.network_name = name
        self.network_labels = dict(labels)

    def inspect_container(self, name: str):
        self.container_inspections += 1
        self.calls.append("final-inspect" if self.container_inspections > 1 else "container-inspect")
        if self.container_inspections == 1:
            self._fail("container-inspect")
        if self.container_inspections > 1:
            self._fail("final-inspect")
            if self.final_missing:
                return None
        if not self.container_created:
            return None
        network_names = ()
        if (
            self.include_intended_network
            and self.network_name
            and self.container_network_name == self.network_name
        ):
            network_names += (self.network_name,)
        if self.extra_network:
            network_names += ("foreign-network",)
        return _ResourceInspection(
            name,
            self.final_running and self.container_started,
            HELLO_REFERENCE,
            dict(self.container_labels or {}) if self.final_labels is None else self.final_labels,
            image_id=self.final_image_id,
            network_names=network_names,
            private_addresses={self.network_name: "172.18.0.2"} if network_names else {},
        )

    def inspect_image(self, image: str):
        self.calls.append("image-inspect")
        self.image_inspect_references.append(image)
        if self.pull_calls:
            self._fail("image-post-pull-inspect")
        else:
            self._fail("image-inspect")
        if not self.cached_image:
            return None
        repo_digests = (
            self.pulled_repo_digests if self.pull_calls else self.cached_repo_digests
        )
        return _ImageInspection(HELLO_IMAGE_ID, repo_digests)

    def pull_image(self, image: str, *, auth_config: object = None) -> None:
        self.calls.append("image-pull")
        self._fail("image-pull")
        self.pull_calls.append((image, auth_config))
        self.cached_image = True

    def inspect_volume(self, name: str):
        self.calls.append("configuration-inspect")
        self._fail("configuration-inspect")
        return None

    def create_volume(self, *, name: str, labels: dict[str, str]) -> None:
        self.calls.append("configuration-create")
        self._fail("configuration-create")
        self.volume_names.append(name)

    def materialize_configuration_artifact(
        self,
        volume_name: str,
        artifact: ConfigurationArtifact,
    ) -> None:
        self.calls.append("configuration-materialize")
        self._fail("configuration-materialize")

    def configuration_artifact_digest(self, volume_name: str) -> str:
        self.calls.append("configuration-digest")
        self._fail("configuration-digest")
        return _configuration_artifact().content_digest

    def create_container(self, **kwargs: object) -> None:
        self.calls.append("container-create")
        self._fail("container-create")
        self.container_name = str(kwargs["name"])
        self.container_labels = dict(kwargs["labels"])
        self.container_create_kwargs = dict(kwargs)
        network = kwargs.get("network")
        self.container_network_name = None if network is None else str(network)
        self.container_created = True

    def start_container(self, name: str) -> None:
        self.calls.append("container-start")
        self._fail("container-start")
        self.container_started = True

    def run_container(self, **kwargs: object) -> None:
        self.calls.append("legacy-run-container")
        for operation in ("container-create", "network-connect", "container-start"):
            self._fail(operation)
        self.container_name = str(kwargs["name"])
        self.container_labels = dict(kwargs["labels"])
        self.container_created = True
        self.container_network_name = str(kwargs["network"])
        self.container_started = True

    def _fail(self, operation: str) -> None:
        if self.fail_at == operation:
            raise TimeoutError("provider material must not cross the result boundary")


class DockerStartNodePhaseTotalTests(unittest.TestCase):
    def test_exact_cached_published_hello_succeeds_without_remote_pull(self) -> None:
        request = _hello_request()
        client = _PhaseClient()

        result = DockerRuntimeInterpreter(client).execute(request)

        self.assertEqual(request.products[0].product.image.execution_reference, HELLO_REFERENCE)
        self.assertEqual(
            request.products[0].reference.descriptor_sha256.value,
            HELLO_DESCRIPTOR_SHA256,
        )
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(client.pull_calls, [])
        self.assertEqual(client.image_inspect_references, [HELLO_REFERENCE])
        self.assertEqual(client.calls[:2], ["image-inspect", "network-inspect"])
        self.assertNotIn("legacy-run-container", client.calls)
        self.assertEqual(
            [
                call
                for call in client.calls
                if call in {"container-create", "container-start"}
            ],
            ["container-create", "container-start"],
        )
        create_call = client.container_create_kwargs
        self.assertEqual(create_call["network"], client.network_name)
        self.assertEqual(create_call["aliases"], ("hello",))

    def test_absent_published_digest_uses_declared_pull_then_exact_identity(self) -> None:
        client = _PhaseClient(cached_image=False)

        result = DockerRuntimeInterpreter(client).execute(_hello_request())

        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertEqual(client.pull_calls, [(HELLO_REFERENCE, None)])
        self.assertEqual(
            client.image_inspect_references,
            [HELLO_REFERENCE, HELLO_REFERENCE],
        )
        self.assertEqual(client.calls.count("image-inspect"), 2)
        self.assertEqual(
            client.calls[:4],
            ["image-inspect", "image-pull", "image-inspect", "network-inspect"],
        )

    def test_cache_admission_requires_exact_declared_repo_digest_before_mutation(self) -> None:
        client = _PhaseClient(cached_repo_digests=())

        result = DockerRuntimeInterpreter(client).execute(
            _hello_request(with_configuration=True)
        )

        self.assertEqual(client.calls, ["image-inspect"])
        self.assertEqual(client.volume_names, [])
        self.assertFalse(client.container_created)
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.image-reference-conflict")

    def test_post_pull_identity_must_resolve_same_exact_repo_digest(self) -> None:
        client = _PhaseClient(
            cached_image=False,
            pulled_repo_digests=(
                "ghcr.io/openj92/control-plane-kit-servers/hello-server@sha256:"
                + "f" * 64,
            ),
        )

        result = DockerRuntimeInterpreter(client).execute(_hello_request())

        self.assertEqual(client.pull_calls, [(HELLO_REFERENCE, None)])
        self.assertEqual(
            client.image_inspect_references,
            [HELLO_REFERENCE, HELLO_REFERENCE],
        )
        self.assertEqual(client.calls, ["image-inspect", "image-pull", "image-inspect"])
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.image-reference-conflict")

    def test_pull_authority_is_validated_before_cached_image_admission(self) -> None:
        reference = SecretReference("secret://registry/ghcr/hello-server")
        resolver = _CredentialResolver(ImagePullCredentialMissing(reference))
        client = _PhaseClient()

        result = DockerRuntimeInterpreter(
            client,
            image_pull_credentials=resolver,
        ).execute(_hello_request(pull_authority=_pull_authority(reference)))

        self.assertEqual(resolver.requests, [reference.reference_id])
        self.assertEqual(client.calls, [])
        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.image-pull-credential-missing")

    def test_cache_absence_pulls_once_with_exact_resolved_authority(self) -> None:
        reference = SecretReference("secret://registry/ghcr/hello-server")
        resolver = _CredentialResolver(
            ImagePullCredentialResolved(
                ResolvedImagePullCredential(
                    username="cpk",
                    password=SecretValue("registry-token-not-for-evidence"),
                )
            )
        )
        client = _PhaseClient(cached_image=False)

        result = DockerRuntimeInterpreter(
            client,
            image_pull_credentials=resolver,
        ).execute(_hello_request(pull_authority=_pull_authority(reference)))

        self.assertEqual(len(client.pull_calls), 1)
        image, auth = client.pull_calls[0]
        self.assertEqual(image, HELLO_REFERENCE)
        self.assertEqual(
            auth.docker_auth_config(),
            {"username": "cpk", "password": "registry-token-not-for-evidence"},
        )
        self.assertEqual(client.calls.count("image-inspect"), 2)
        self.assertEqual(
            client.calls[:4],
            ["image-inspect", "image-pull", "image-inspect", "network-inspect"],
        )
        self.assertIs(result.kind, EffectResultKind.SUCCEEDED)
        self.assertNotIn("registry-token-not-for-evidence", repr(result.descriptor()))

    def test_each_start_node_provider_boundary_stops_at_exact_uncertain_phase(self) -> None:
        prefix = ["image-inspect", "network-inspect", "network-create"]
        cases = (
            ("image-inspect", "image-availability", True, False, ["image-inspect"]),
            (
                "image-pull",
                "image-availability",
                False,
                False,
                ["image-inspect", "image-pull"],
            ),
            (
                "image-post-pull-inspect",
                "image-availability",
                False,
                False,
                ["image-inspect", "image-pull", "image-inspect"],
            ),
            (
                "network-inspect",
                "network",
                True,
                False,
                ["image-inspect", "network-inspect"],
            ),
            ("network-create", "network", True, False, prefix),
            (
                "configuration-inspect",
                "configuration",
                True,
                True,
                prefix + ["container-inspect", "configuration-inspect"],
            ),
            (
                "configuration-create",
                "configuration",
                True,
                True,
                prefix
                + [
                    "container-inspect",
                    "configuration-inspect",
                    "configuration-create",
                ],
            ),
            (
                "configuration-materialize",
                "configuration",
                True,
                True,
                prefix
                + [
                    "container-inspect",
                    "configuration-inspect",
                    "configuration-create",
                    "configuration-materialize",
                ],
            ),
            (
                "configuration-digest",
                "configuration",
                True,
                True,
                prefix
                + [
                    "container-inspect",
                    "configuration-inspect",
                    "configuration-create",
                    "configuration-materialize",
                    "configuration-digest",
                ],
            ),
            (
                "container-inspect",
                "container-create",
                True,
                False,
                prefix + ["container-inspect"],
            ),
            (
                "container-create",
                "container-create",
                True,
                False,
                prefix + ["container-inspect", "container-create"],
            ),
            (
                "container-start",
                "container-start",
                True,
                False,
                prefix
                + [
                    "container-inspect",
                    "container-create",
                    "container-start",
                ],
            ),
            (
                "final-inspect",
                "final-inspect",
                True,
                False,
                prefix
                + [
                    "container-inspect",
                    "container-create",
                    "container-start",
                    "final-inspect",
                ],
            ),
        )
        for fail_at, phase, cached, configuration, expected_calls in cases:
            with self.subTest(fail_at=fail_at):
                client = _PhaseClient(cached_image=cached, fail_at=fail_at)
                result = DockerRuntimeInterpreter(client).execute(
                    _hello_request(with_configuration=configuration)
                )

                self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                self.assertEqual(client.calls, expected_calls)
                self.assertEqual(result.failure.code, "docker.effect-uncertain")
                self.assertEqual(result.failure.details, {"phase": phase})
                self.assertEqual(
                    result.failure.message,
                    "Docker runtime effect is uncertain",
                )
                self.assertNotIn("provider material", repr(result.descriptor()))

    def test_missing_final_inspection_is_bounded_uncertain(self) -> None:
        client = _PhaseClient(final_missing=True)

        result = DockerRuntimeInterpreter(client).execute(_hello_request())

        self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
        self.assertEqual(result.failure.code, "docker.effect-uncertain")
        self.assertEqual(result.failure.details, {"phase": "final-inspect"})

    def test_container_image_inspection_ambiguity_is_phase_specific(self) -> None:
        cases = (
            ("container-inspect", "container-create"),
            ("final-inspect", "final-inspect"),
        )
        for fail_at, phase in cases:
            with self.subTest(fail_at=fail_at):
                client = _PhaseClient(fail_at=fail_at)

                result = DockerRuntimeInterpreter(client).execute(_hello_request())

                self.assertIs(result.kind, EffectResultKind.UNCERTAIN)
                self.assertEqual(result.failure.code, "docker.effect-uncertain")
                self.assertEqual(result.failure.details, {"phase": phase})
                self.assertEqual(
                    result.failure.message,
                    "Docker runtime effect is uncertain",
                )

    def test_success_requires_running_exact_image_on_intended_network(self) -> None:
        cases = (
            ("not-running", {"final_running": False}, "docker.container-not-running"),
            (
                "wrong-image",
                {"final_image_id": "sha256:" + "f" * 64},
                "docker.container-image-conflict",
            ),
            (
                "wrong-network",
                {"include_intended_network": False},
                "docker.container-network-conflict",
            ),
            (
                "extra-network",
                {"extra_network": True},
                "docker.container-network-conflict",
            ),
            (
                "wrong-labels",
                {"final_labels": {"org.openj92.cpk.workspace": "foreign"}},
                "docker.container-ownership-conflict",
            ),
        )
        for name, kwargs, code in cases:
            with self.subTest(case=name):
                client = _PhaseClient(**kwargs)
                result = DockerRuntimeInterpreter(client).execute(_hello_request())

                self.assertIs(result.kind, EffectResultKind.FAILED)
                self.assertEqual(result.failure.code, code)
                self.assertTrue(client.container_created)

    def test_preexisting_wrong_network_is_definite_and_untouched(self) -> None:
        request = _hello_request()
        client = _PhaseClient(include_intended_network=False)
        client.container_created = True
        client.container_started = True
        client.container_network_name = "foreign-network"
        client.container_labels = _node_labels(request, request.products[0])

        result = DockerRuntimeInterpreter(client).execute(request)

        self.assertIs(result.kind, EffectResultKind.FAILED)
        self.assertEqual(result.failure.code, "docker.container-network-conflict")
        self.assertNotIn("container-create", client.calls)
        self.assertNotIn("container-start", client.calls)


def _hello_request(
    *,
    pull_authority: ImagePullAuthority | None = None,
    with_configuration: bool = False,
) -> RuntimeEffectRequest:
    document = ProductDescriptorCodec().decode_document(HELLO_DOCUMENT)
    if document.content_digest != HELLO_DESCRIPTOR_SHA256:
        raise AssertionError(document.content_digest)
    product = document.product
    if with_configuration:
        product = replace(
            product,
            runtime_contract=replace(
                product.runtime_contract,
                configuration_artifacts=(_configuration_artifact(),),
            ),
        )
    return RuntimeEffectRequest(
        effect_id="effect-cpk92-exact-hello",
        kind=RuntimeEffectKind.REALIZE_ACTIVITY,
        runtime_kind=RuntimeKind.DOCKER,
        source=RuntimeEffectSource(
            workspace_id="cpk92-exact-hello",
            request_id="request-cpk92-exact-hello",
            run_id="run-cpk92-exact-hello",
            plan_id="plan-cpk92-exact-hello",
            base_graph_id="graph-cpk92-base",
            desired_graph_id="graph-cpk92-desired",
            intent_event_id="event-cpk92-exact-hello",
        ),
        activity_id=ActivityId("start-node:cpk92-exact-hello"),
        operation=StartNode(NodeTarget("hello")),
        products=(
            RuntimeProductMaterial(
                node_id="hello",
                runtime_id="docker",
                reference=ProductReference(
                    product.identity,
                    ProductDescriptorDigest(document.content_digest),
                ),
                product=product,
                public_environment=product.runtime_contract.public_environment,
                pull_authority=pull_authority,
            ),
        ),
    )


def _configuration_artifact() -> ConfigurationArtifact:
    return ConfigurationArtifact(
        "hello-config",
        "/etc/hello/config.json",
        ConfigurationMediaType.JSON,
        '{"message":"Hello, world!"}\n',
        ConfigurationFileMode.READ_ONLY,
    )


def _pull_authority(reference: SecretReference) -> ImagePullAuthority:
    return ImagePullAuthority(
        "ghcr.io",
        "openj92/control-plane-kit-servers/hello-server",
        reference,
    )


class _CredentialResolver:
    def __init__(self, result: object) -> None:
        self.result = result
        self.requests: list[str] = []

    def resolve(self, authority: ImagePullAuthority):
        self.requests.append(authority.credential_reference.reference_id)
        return self.result
