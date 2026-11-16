"""One original SQL check's Core-only prepared inputs; no authority owner."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
import math
import time
from urllib.parse import urlsplit

from control_plane_kit_core.configuration import ConfigurationArtifact
from control_plane_kit_core.postgres_readiness import (
    PostgresReadinessBinding, postgres_readiness_password_supported, postgres_readiness_result_matches,
)
from control_plane_kit_core.products import ProductDescriptorDocument, ProductDescriptorCodec, product_configuration_slots
from control_plane_kit_core.receiver_configuration import ReceiverNodeControlConfiguration, ReceiverNodeControlConfigurationCodec
from control_plane_kit_core.receiver_identity import NodeControlAuthorityContext
from control_plane_kit_core.receiver_management_routes import ReceiverManagementRouteBinding, ReceiverManagementRoutesCodec
from control_plane_kit_core.runtime_effects import RuntimeEffectRequest
from control_plane_kit_core.secret_version_grants import SecretVersionResolutionGrant
from control_plane_kit_core.verification import PostgresQueryCheck
from control_plane_kit_interpreters.docker.postgres_readiness import observe_postgres_readiness_recipient
from control_plane_kit_interpreters.docker.postgres_recipient import require_same_postgres_recipient_route
from control_plane_kit_interpreters.invocations import control_errors, invoke
from control_plane_kit_interpreters.secrets import resolve_selected_secret_deliveries
from .health_signing import HealthSigningContext, HealthSigningKey, Ed25519HealthCredentialPairSigner
from .health_transport import SelectedManagementGateway, SignedGatewayHealthClient, _destination


class PostgresReadinessCheckUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("original PostgreSQL readiness check is unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class PostgresReadinessCheckInput:
    binding: PostgresReadinessBinding
    password_grant: SecretVersionResolutionGrant
    signing_context: HealthSigningContext
    transit_key: HealthSigningKey
    workload_key: HealthSigningKey
    transit_grant: object
    workload_grant: object
    destination: SelectedManagementGateway
    route: ReceiverManagementRouteBinding
    gateway_product: ProductDescriptorDocument
    gateway_route_artifact: ConfigurationArtifact
    gateway_transit_artifact: ConfigurationArtifact


@dataclass(frozen=True, slots=True, repr=False)
class PostgresReadinessRouteInput:
    authority_context: NodeControlAuthorityContext
    receiver: ReceiverNodeControlConfiguration
    destination: SelectedManagementGateway
    route: ReceiverManagementRouteBinding
    gateway_product: ProductDescriptorDocument
    gateway_route_artifact: ConfigurationArtifact
    gateway_transit_artifact: ConfigurationArtifact


@dataclass(frozen=True, slots=True, repr=False)
class PostgresReadinessCheckExecutor:
    authorized_secret_resolver: object
    signer: object
    health_client: object
    clock_epoch_ms: object
    managed_verification_support: object
    monotonic: object = time.monotonic

    def __post_init__(self):
        _require(type(self.signer) is Ed25519HealthCredentialPairSigner
            and self.signer.authorized_secret_resolver is self.authorized_secret_resolver
            and callable(getattr(self.authorized_secret_resolver, "resolve", None))
            and type(self.health_client) is SignedGatewayHealthClient
            and callable(self.clock_epoch_ms) and callable(self.monotonic)
            and self.managed_verification_support is not None)

    def acquire(self, runtime_request, parent):
        controls = control_errors(parent, required=True)
        try:
            value = parent.acquire_managed_verification_route()
            _require(type(value) is PostgresReadinessRouteInput and type(runtime_request) is RuntimeEffectRequest
                and len(runtime_request.products) == 1 and type(value.receiver) is ReceiverNodeControlConfiguration)
            ReceiverNodeControlConfigurationCodec().encode(value.receiver)
            material, = runtime_request.products
            target = value.receiver.target
            _require(type(value.authority_context) is NodeControlAuthorityContext
                and value.authority_context.authored_graph_id == runtime_request.source.desired_graph_id
                and (target.workspace_id.value, target.runtime_id.value, target.node_id.value)
                    == (runtime_request.source.workspace_id, material.runtime_id, material.node_id)
                and type(value.route) is ReceiverManagementRouteBinding
                and value.route.target == target and value.route.declaration == value.receiver.declaration)
            return value
        except controls:
            raise
        except Exception:
            failure = PostgresReadinessCheckUnavailable()
        raise failure

    def execute(self, runtime_request, check, child, *, docker, acquired):
        controls = control_errors(child, required=True)
        try:
            prepared = child.prepare_postgres_readiness()
            self._context(prepared, runtime_request, check)
            binding = prepared.binding
            _require(type(acquired) is PostgresReadinessRouteInput and acquired == PostgresReadinessRouteInput(
                binding.request().authority_context, binding.receiver, prepared.destination, prepared.route,
                prepared.gateway_product, prepared.gateway_route_artifact, prepared.gateway_transit_artifact))
            now = self.clock_epoch_ms()
            _require(type(now) is int and binding.started_at_epoch_ms <= now < binding.deadline_epoch_ms)
            # Integral JWT expiry can be earlier than the retained millisecond
            # deadline; it can never extend that original authority window.
            expires = min(binding.deadline_epoch_ms,
                prepared.transit_grant.expires_at * 1000, prepared.workload_grant.expires_at * 1000)
            mono = self.monotonic()
            _require(type(mono) in (int, float) and math.isfinite(mono) and now < expires)
            deadline = mono + (expires - now) / 1000

            def window():
                epoch, tick = self.clock_epoch_ms(), self.monotonic()
                _require(type(epoch) is int and binding.started_at_epoch_ms <= epoch < expires
                    and type(tick) in (int, float) and math.isfinite(tick) and tick < deadline)
                return min((expires - epoch) / 1000, deadline - tick)

            material, = binding.installation.products
            secret = invoke(child, "secret-resolution", lambda: resolve_selected_secret_deliveries(
                material.product.runtime_contract.secret_deliveries, selections=material.secret_selections,
                grants=(prepared.password_grant,), resolver=self.authorized_secret_resolver),
                authorization_id=prepared.password_grant.authorization_id)
            window()
            _require(len(secret.files) == 1 and postgres_readiness_password_supported(secret.files[0].value))
            pair = self.signer.sign(prepared.signing_context, transit_grant=prepared.transit_grant,
                workload_grant=prepared.workload_grant, transit_key=prepared.transit_key,
                workload_key=prepared.workload_key, invocations=child)
            window()

            def exchange():
                before = observe_postgres_readiness_recipient(docker, prepared, secret,
                    deadline=deadline, clock=self.monotonic, check_window=window)
                async def send():
                    async with asyncio.timeout(window()):
                        return await self.health_client.dispatch(prepared.signing_context, pair,
                            prepared.destination, transit_grant=prepared.transit_grant,
                            workload_grant=prepared.workload_grant)
                # This synchronous runtime can be called from the async API.
                # Exactly one owned worker and one dispatch; never retry.
                with ThreadPoolExecutor(max_workers=1, thread_name_prefix="cpk-postgres-readiness") as worker:
                    received = worker.submit(lambda: asyncio.run(send())).result()
                observed_at = self.clock_epoch_ms()
                window()
                _require(received.code.value == "received" and received.result is not None
                    and postgres_readiness_result_matches(binding, received.result, observed_at_epoch_ms=observed_at))
                after = observe_postgres_readiness_recipient(docker, prepared, secret,
                    deadline=deadline, clock=self.monotonic, check_window=window)
                require_same_postgres_recipient_route(before, after)
                window()
                return dict(profile="cpk.original-postgres-readiness.v1", check_id=binding.check_id,
                    result=received.result.descriptor(), observed_at_epoch_ms=observed_at)

            return invoke(child, "ordinary-verification-check", exchange)
        except controls:
            raise
        except Exception:
            failure = PostgresReadinessCheckUnavailable()
        raise failure

    def _context(self, value, runtime, check):
        _require(type(value) is PostgresReadinessCheckInput and type(runtime) is RuntimeEffectRequest
            and type(check) is PostgresQueryCheck and type(value.binding) is PostgresReadinessBinding
            and type(value.password_grant) is SecretVersionResolutionGrant
            and type(value.signing_context) is HealthSigningContext
            and type(value.transit_key) is type(value.workload_key) is HealthSigningKey)
        binding = replace(value.binding)
        document = binding.descriptor()
        password = replace(value.password_grant)
        _require(runtime == binding.wait and runtime.authority_ref is not None
            and not runtime.authority_deliveries and not binding.installation.authority_deliveries
            and runtime.products[0].product.runtime_contract.verification.checks == (check,)
            and not runtime.products[0].runtime_authority_deliveries
            and check.check_id == binding.check_id
            and password.selection.descriptor() == document["credential_selection"]
            and password.request_fingerprint == document["request_fingerprint"]
            and password.selection_fingerprint == binding.receipt.selection_fingerprint
            and (password.operation_id, password.effect_id) == (runtime.source.request_id, runtime.effect_id))
        material, = runtime.products
        _require(material.secret_selections == (password.selection,)
            and len(material.product.runtime_contract.secret_deliveries) == 1)
        roles = (password, value.transit_key.resolution_grant, value.workload_key.resolution_grant)
        for role in roles:
            _require((role.workspace_id, role.run_id, role.activity_id)
                == (runtime.source.workspace_id, runtime.source.run_id.value, runtime.activity_id.value)
                and role.actor_subject == password.actor_subject
                and password.session_id is not None and role.session_id == password.session_id)
        _require(len({role.authorization_id for role in roles}) == 3
            and value.signing_context.request == binding.request()
            and value.signing_context.declaration == binding.receiver.declaration)
        context = value.signing_context
        _require(context.gateway_target.workspace_id == binding.receiver.target.workspace_id
            and context.gateway_target.runtime_id == binding.receiver.target.runtime_id)
        _require(type(value.route) is ReceiverManagementRouteBinding
            and replace(value.route) == value.route and value.route.target == binding.receiver.target
            and value.route.declaration == binding.receiver.declaration
            and value.route.target_id == value.destination.target_id)
        control_port, = (port.container_port for port in material.product.runtime_contract.provider_ports
            if port.provider_socket == binding.receiver.target.provider_socket_name.value)
        _require(urlsplit(value.route.origin).port == control_port)
        _destination(value.destination, context)
        _require(type(value.gateway_product) is ProductDescriptorDocument
            and ProductDescriptorCodec().decode_document(value.gateway_product.content) == value.gateway_product)
        # Registered products may declare slots, with selected bytes owned by
        # the prepared graph projection. Match the declared slot here and the
        # exact selected mounted bytes in the physical observer.
        slots = product_configuration_slots(value.gateway_product.product.runtime_contract)
        identity = lambda artifact: (artifact.artifact_id, artifact.target_path, artifact.media_type, artifact.file_mode)
        _require(value.gateway_route_artifact != value.gateway_transit_artifact)
        for artifact in (value.gateway_route_artifact, value.gateway_transit_artifact):
            _require(type(artifact) is ConfigurationArtifact
                and sum(identity(slot) == identity(artifact) for slot in slots) == 1)
        routes = ReceiverManagementRoutesCodec().decode_bytes(value.gateway_route_artifact.content.encode())
        _require(routes.gateway_target == context.gateway_target and value.route in routes.targets)


def _require(condition):
    if condition is not True:
        raise ValueError
