"""Bounded current Docker metadata; no historical outcome or recovery authority."""
from dataclasses import dataclass, replace
from hashlib import sha256
import math
import re
from time import monotonic

import rfc8785

from control_plane_kit_core.planning import StartNode
from control_plane_kit_core.configuration_invocation import (
    configuration_invocation_correlation_for_request, configuration_invocation_selection_fingerprint,
)
from control_plane_kit_core.runtime_effect_observation import (
    RuntimeEffectObservationEvidence, RuntimeEffectObservationFailure,
    RuntimeEffectObservationRequest, RuntimeEffectObservedIndeterminate,
    RuntimeEffectObserverUnsupported,
)
from control_plane_kit_core.runtime_effects import RuntimeEffectKind
from control_plane_kit_core.secrets import (
    SecretEnvironmentDelivery, SecretFileDelivery, SecretReferenceEnvironmentDelivery,
)
from control_plane_kit_core.types import RuntimeKind
from control_plane_kit_interpreters.docker.configuration import (
    configuration_volume_labels, configuration_volume_name,
)
from control_plane_kit_interpreters.docker.runtime import (
    _container_name, _network_name, _node_labels, _runtime_labels,
    _secret_volume_name, _selected_secret_identity,
)
from control_plane_kit_interpreters.docker.sdk import (
    DockerSdkClient, _secret_file_owner_uid, matches_image_reference,
)


_PREFIX = "org.openj92.cpk."
_BINDING_DOMAIN = b"control-plane-kit.docker-provider-binding.v1\0"
_SELECTOR_DOMAIN = b"control-plane-kit.docker-recovery-selector.v1\0"
_VOLUME_DOMAIN = b"control-plane-kit.docker-recovery-volume.v1\0"
_DAEMON = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}")
_ID = re.compile(r"[a-f0-9]{64}")


class _Stopped(Exception):
    pass


class _Malformed(Exception):
    pass


class _Unavailable(Exception):
    def __init__(self, reason):
        self.reason = reason


class _ResourceUnavailable(Exception):
    def __init__(self, row):
        self.row = row


class _Budget:
    """Scheduling bound, not hard cancellation of an in-flight SDK request."""
    def __init__(self):
        self.started = self.previous = self._now()

    @staticmethod
    def _now():
        try:
            value = monotonic()
            if type(value) not in (int, float) or not math.isfinite(value):
                raise _Stopped
            return value
        except Exception:
            raise _Stopped from None

    def check(self):
        now = self._now()
        if now < self.previous or now - self.started >= 30:
            raise _Stopped
        self.previous = now

    def call(self, method, *args, **kwargs):
        self.check()
        return method(*args, **kwargs)


@dataclass(frozen=True)
class _Target:
    role: str
    index: int
    coordinate: str | None
    labels: dict | None = None
    file: object | None = None
    destination: str | None = None


def _commit(domain, value):
    return sha256(domain + rfc8785.dumps(value)).hexdigest()


def _row(target, *, state="unknown", ownership="unestablished", identity=None,
         attachment=None, reason="provider-unavailable"):
    return dict(role=target.role, index=target.index,
        selector=None if target.coordinate is None else _commit(
            _SELECTOR_DOMAIN, [target.role, target.coordinate]),
        state=state, ownership=ownership, identity=identity,
        attachment=attachment or ("unknown" if target.role.endswith("-volume") else "not-applicable"),
        reason=reason)


def _result(observation, rows, binding=None, *, complete=False, unsupported=False):
    # Only this closed producer constructs wire evidence. The Core carrier also
    # enforces its real canonical-byte ceiling; nothing is truncated to fit.
    evidence = RuntimeEffectObservationEvidence(dict(
        profile="docker.recovery-metadata.v1", provider_binding_fingerprint=binding,
        coverage="selected-addresses-observed" if complete else "incomplete", resources=rows))
    result_type = RuntimeEffectObserverUnsupported if unsupported else RuntimeEffectObservedIndeterminate
    code, message = (
        ("docker.recovery-metadata-unsupported", "Recovery metadata inspection is unsupported for this request.")
        if unsupported else
        ("docker.recovery-metadata-indeterminate", "Recovery metadata does not establish the historical effect outcome."))
    return result_type(effect_id=observation.effect_id,
        request_fingerprint=observation.request_fingerprint, evidence=evidence,
        failure=RuntimeEffectObservationFailure(code, message), observations=())


def _expected_node_labels(request, material):
    labels = _node_labels(request, material)
    if request.kind is RuntimeEffectKind.CONFIGURATION_ACTIVITY_V1:
        correlation = configuration_invocation_correlation_for_request(request)
        labels[_PREFIX + "configuration.selection"] = configuration_invocation_selection_fingerprint(correlation.selection)
    return labels


def _targets(observer, observation, authority, expected):
    request = observation.runtime_request
    policy = observer.local_client_config
    kind = getattr(authority, "runtime_kind", None)
    authority_kind = getattr(authority, "authority_kind", None)
    if (policy is None or observer.client is not None or policy.request_timeout > 10
            or type(expected) is not str or _DAEMON.fullmatch(expected) is None
            or getattr(kind, "value", kind) != "docker"
            or getattr(authority_kind, "value", authority_kind) != "local-docker-socket"
            or observation.connection_admission is not None
            or request.runtime_kind is not RuntimeKind.DOCKER
            or request.kind not in (RuntimeEffectKind.REALIZE_ACTIVITY, RuntimeEffectKind.CONFIGURATION_ACTIVITY_V1)
            or type(request.operation) is not StartNode or len(request.products) != 1
            or request.secret_resolution_grants or request.authority_deliveries):
        return None
    material, = request.products
    contract = material.product.runtime_contract
    if material.node_id != request.operation.target.node_id or contract.retained_data_mounts:
        return None
    if contract.configuration_artifacts and request.configuration_instances is None:
        # Legacy runtime preparation creates additional configuration volumes;
        # this capability deliberately admits only exact allocation selections.
        return None
    if any(type(delivery) not in (SecretEnvironmentDelivery, SecretReferenceEnvironmentDelivery, SecretFileDelivery)
           for delivery in contract.secret_deliveries):
        return None
    files = list(enumerate(delivery for delivery in contract.secret_deliveries
                           if type(delivery) is SecretFileDelivery))
    configurations = (() if request.configuration_instances is None else request.configuration_instances.instances)
    if len(configurations) + len(files) > 8:
        return None
    # No legacy secret naming: every file must have one exact immutable selection.
    for _, delivery in files:
        if sum(s.reference == delivery.reference and s.intent is delivery.intent
               for s in material.secret_selections) != 1:
            return None
    targets = [
        _Target("container", 0, _container_name(request, material.node_id), _expected_node_labels(request, material)),
        _Target("network", 0, _network_name(request, material.runtime_id), _runtime_labels(request, material.runtime_id)),
        _Target("image", 0, material.product.image.execution_reference),
    ]
    targets += [_Target("configuration-volume", index, configuration_volume_name(ref), configuration_volume_labels(ref), destination=ref.target_path)
                for index, ref in enumerate(configurations)]
    targets += [_Target("secret-volume", index, None, file=delivery, destination=delivery.target_path) for index, delivery in files]
    coordinates = [t.coordinate for t in targets[3:] if t.coordinate is not None]
    if len(coordinates) != len(set(coordinates)):
        return None
    return targets


def _mapping(value, limit=64):
    if type(value) is not dict or len(value) > limit:
        raise _Malformed
    return value


def _text(value, limit):
    if type(value) is not str or len(value) > limit:
        raise _Malformed
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise _Malformed from None
    return value


def _labels(value):
    values = _mapping(value)
    size = 0
    result = {}
    for key, item in values.items():
        _text(key, 256)
        _text(item, 2048)
        size += len(key) + len(item)
        if size > 16384:
            raise _Malformed
        result[key] = item
    return result


def _identity(value, *, image=False):
    if type(value) is not str or (not value.startswith("sha256:") if image else False):
        raise _Malformed
    if _ID.fullmatch(value[7:] if image else value) is None:
        raise _Malformed
    return value


def _mounts(value, *, holder=False):
    if type(value) is not list or len(value) > 64:
        raise _Malformed
    result = []
    for mount in value:
        mount = _mapping(mount, 16)
        kind = _text(mount.get("Type"), 32)
        name = _text(mount.get("Name", ""), 256)
        if holder:
            result.append((kind, name))
        else:
            destination = _text(mount.get("Destination"), 1024)
            read_write = mount.get("RW")
            if type(read_write) is not bool:
                raise _Malformed
            result.append((kind, name, destination, read_write))
    if len(result) != len(set(result)):
        raise _Malformed
    return sorted(result)


def _container_facts(raw):
    image = _identity(raw.get("Image"), image=True)
    name = _text(raw.get("Name"), 256)
    networks = _mapping(_mapping(raw.get("NetworkSettings")).get("Networks"), 32)
    network_ids = {}
    for network, data in networks.items():
        network_ids[_text(network, 256)] = _identity(_mapping(data).get("NetworkID"))
    mounts = _mounts(raw.get("Mounts"))
    state = _mapping(raw.get("State"))
    running = state.get("Running")
    status = _text(state.get("Status"), 32)
    if type(running) is not bool or not status:
        raise _Malformed
    return dict(name=name, image=image, networks=network_ids, mounts=mounts,
                running=running, status=status)


def _project(raw, target, context):
    raw = _mapping(raw)
    if target.role == "image":
        identity = _identity(raw.get("Id"), image=True)
        digests = raw.get("RepoDigests")
        if type(digests) is not list or len(digests) > 32:
            raise _Malformed
        for digest in digests:
            _text(digest, 1024)
        matches = matches_image_reference(target.coordinate, tuple(digests))
        config = _mapping(raw.get("Config"))
        user = config.get("User", "")
        # User affects selectors, never public evidence. Unsupported values do
        # not turn a real exact image into an absent image.
        try:
            uid = _secret_file_owner_uid(user) if matches else None
        except ValueError:
            uid = None
        return (_row(target, state="present", ownership="not-applicable" if matches else "conflicting",
                     identity=identity, reason="none" if matches else "ownership-conflict"), uid,
                dict(identity=identity, uid=uid, matches=matches))
    facts = None
    coordinate_matches = True
    if target.role == "container":
        labels = _labels(_mapping(raw.get("Config")).get("Labels"))
        identity = _identity(raw.get("Id"))
        facts = _container_facts(raw)
        coordinate_matches = (facts["name"] == "/" + target.coordinate
            and tuple(facts["networks"]) == (context["network"],)
            and all(mount in facts["mounts"] for mount in context["mounts"]))
        if context["image_id"] is not None:
            coordinate_matches = coordinate_matches and facts["image"] == context["image_id"]
        if context["complete"]:
            coordinate_matches = coordinate_matches and facts["mounts"] == context["mounts"]
    elif target.role == "network":
        labels = _labels(raw.get("Labels"))
        identity = _identity(raw.get("Id"))
        coordinate_matches = _text(raw.get("Name"), 256) == target.coordinate
    else:
        labels = _labels(raw.get("Labels"))
        name = _text(raw.get("Name"), 256)
        driver = _text(raw.get("Driver"), 128)
        scope = _text(raw.get("Scope"), 128)
        created = _text(raw.get("CreatedAt"), 128)
        if not created or "\x00" in created:
            raise _Malformed
        if name != target.coordinate:
            raise _Malformed
        identity = _commit(_VOLUME_DOMAIN, dict(name=name, labels=labels, driver=driver, scope=scope, created_at=created))
    matches = (coordinate_matches
        and {key: value for key, value in labels.items() if key.startswith(_PREFIX)} == target.labels)
    row = _row(target, state="present", ownership="matching" if matches else "conflicting",
               identity=identity, reason="none" if matches else "ownership-conflict")
    if target.role == "container" and matches and not context["complete"]:
        row.update(ownership="unestablished", reason="selector-unavailable")
    return row, None, facts


def _resource(api, budget, target, context):
    from docker.errors import NotFound
    from control_plane_kit_interpreters.docker.observer import _provider_error

    method = getattr(api, "inspect_volume" if target.role.endswith("-volume") else "inspect_" + target.role)
    try:
        raw = budget.call(method, target.coordinate)
    except NotFound:
        row, uid, facts = _row(target, state="absent", ownership="not-applicable", reason="not-found"), None, None
    except Exception as error:
        if not _provider_error(error):
            raise
        raise _ResourceUnavailable(_row(target)) from None
    else:
        try:
            row, uid, facts = _project(raw, target, context)
        except _Malformed:
            raise _ResourceUnavailable(_row(target, reason="malformed")) from None
    if target.role.endswith("-volume"):
        try:
            holders = budget.call(api.containers, all=True, filters={"volume": target.coordinate}, limit=1)
            if type(holders) is not list or len(holders) > 1:
                raise _Malformed
            if holders:
                holder = _mapping(holders[0])
                _identity(holder.get("Id"))
                if ("volume", target.coordinate) not in _mounts(holder.get("Mounts"), holder=True):
                    raise _Malformed
            row["attachment"] = "observed" if holders else "not-observed"
            if holders and row["state"] == "absent":
                raise _ResourceUnavailable(_row(target, attachment="observed", reason="drift"))
        except Exception as error:
            if isinstance(error, _ResourceUnavailable):
                raise
            if not isinstance(error, _Malformed) and not _provider_error(error):
                raise
            row["attachment"] = "unknown"
            row["reason"] = "malformed" if isinstance(error, _Malformed) else "provider-unavailable"
            raise _ResourceUnavailable(row) from None
    return row, uid, facts


def _sweep(api, budget, targets, request, expected, rows):
    from control_plane_kit_interpreters.docker.observer import _provider_error

    try:
        daemon = _mapping(budget.call(api.info)).get("ID")
        if type(daemon) is not str or _DAEMON.fullmatch(daemon) is None or daemon != expected:
            raise _Unavailable("provider-binding-unavailable")
    except Exception as error:
        if isinstance(error, _Malformed) or _provider_error(error):
            raise _Unavailable("provider-binding-unavailable") from None
        raise
    facts = [None] * len(targets)
    try:
        rows[2], uid, facts[2] = _resource(api, budget, targets[2], {})
    except _ResourceUnavailable as error:
        rows[2] = error.row
        raise
    concrete = list(targets)
    material, = request.products
    for index, target in enumerate(targets[3:], 3):
        if target.file is None:
            continue
        if uid is None:
            rows[index] = _row(target, state="unsupported", reason="selector-unavailable")
            continue
        secret = target.file
        selection, = (s for s in material.secret_selections
                      if s.reference == secret.reference and s.intent is secret.intent)
        labels = {**_expected_node_labels(request, material), _PREFIX + "volume.kind": "secret-file",
                  _PREFIX + "secret.target": secret.target_path,
                  _PREFIX + "secret.reference": secret.reference.reference_id,
                  _PREFIX + "secret.identity": _selected_secret_identity(request, material.node_id, secret, selection, uid)}
        concrete[index] = replace(target, coordinate=_secret_volume_name(
            request, material.node_id, secret, owner_uid=uid), labels=labels)
    coordinates = [t.coordinate for t in concrete[3:] if t.coordinate is not None]
    if len(coordinates) != len(set(coordinates)):
        raise _Unavailable("unsupported")
    context = dict(image_id=rows[2]["identity"] if rows[2]["ownership"] == "not-applicable" else None,
        network=targets[1].coordinate,
        mounts=sorted(("volume", t.coordinate, t.destination, False) for t in concrete[3:] if t.coordinate is not None),
        complete=rows[2]["state"] == "present" and rows[2]["ownership"] == "not-applicable"
                 and all(t.coordinate is not None for t in concrete[3:]))
    for index, target in enumerate(concrete[3:], 3):
        if target.coordinate is not None:
            rows[index] = _row(target)
    for index, target in enumerate(concrete):
        if index == 2 or target.coordinate is None:
            continue
        try:
            rows[index], _, facts[index] = _resource(api, budget, target, context)
        except _ResourceUnavailable as error:
            rows[index] = error.row
            raise
    if facts[0] is not None and rows[1]["state"] == "present":
        if facts[0]["networks"].get(targets[1].coordinate) != rows[1]["identity"]:
            rows[0].update(ownership="conflicting", reason="ownership-conflict")
    if facts[0] is not None:
        mounted = {mount[1] for mount in facts[0]["mounts"] if mount[0] == "volume"}
        for index, target in enumerate(concrete[3:], 3):
            if rows[index]["state"] == "absent" and target.coordinate in mounted:
                rows[index] = _row(target, reason="drift")
    return facts


def observe_metadata(observer, observation, authority, expected):
    from control_plane_kit_interpreters.docker.observer import _provider_error

    if type(observation) is not RuntimeEffectObservationRequest:
        raise TypeError("Docker observer requires RuntimeEffectObservationRequest")
    targets = _targets(observer, observation, authority, expected)
    if targets is None:
        return _result(observation, [], unsupported=True)
    rows = [_row(t, reason="selector-unavailable" if t.coordinate is None else "provider-unavailable") for t in targets]
    client = None
    binding = None
    complete = False
    read_error = close_error = None
    try:
        budget = _Budget()
        budget.check()
        client = DockerSdkClient.from_authority(observer.local_client_config,
            docker_module=observer.docker_module, connect_on_init=False)
        client._before_provider_call = budget.check
        api = client._client().api
        first_facts = _sweep(api, budget, targets, observation.runtime_request, expected, rows)
        first = rows
        rows = [_row(t, reason="selector-unavailable" if t.coordinate is None else "provider-unavailable") for t in targets]
        second_facts = _sweep(api, budget, targets, observation.runtime_request, expected, rows)
        binding = sha256(_BINDING_DOMAIN + expected.encode("ascii")).hexdigest()
        for index, (before, after) in enumerate(zip(first, rows, strict=True)):
            if before != after or first_facts[index] != second_facts[index]:
                rows[index] = {**after, "state": "unknown", "ownership": "unestablished",
                               "identity": None, "attachment": "unknown" if targets[index].role.endswith("-volume") else "not-applicable",
                               "reason": "drift"}
        complete = all(row["state"] in ("present", "absent") and row["attachment"] != "unknown"
                       and row["ownership"] != "unestablished" for row in rows)
    except _ResourceUnavailable:
        # The current sweep already retained the failed row and earlier facts.
        # No later coordinate or second sweep is scheduled after this failure.
        pass
    except (_Stopped, _Unavailable) as error:
        reason = error.reason if isinstance(error, _Unavailable) else "provider-unavailable"
        rows = [_row(t, reason="selector-unavailable" if t.coordinate is None else reason) for t in targets]
    except BaseException as error:
        read_error = error
    if client is not None:
        try:
            client.close()
        except BaseException as error:
            close_error = error
    for error in (read_error, close_error):
        if error is not None:
            if not _provider_error(error):
                raise error
            complete = False
    return _result(observation, rows, binding, complete=complete)
