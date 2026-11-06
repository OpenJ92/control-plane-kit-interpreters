"""Fixed Secrets policy transport; admission and command history belong to callers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable
import time
from urllib.parse import quote, urlencode
from uuid import uuid4

import httpx

from control_plane_kit_core.provider_policy import (
    ProviderPolicyCommandResult, ProviderPolicyCommandResultRequest,
    ProviderPolicyCoordinate, ProviderPolicyErrorCode, ProviderPolicyFailure,
    ProviderPolicyGrantCommand, ProviderPolicyGrantPage, ProviderPolicyGrantRead,
    ProviderPolicyGrantRecord, ProviderPolicyIntentMode, ProviderPolicyListRequest,
    ProviderPolicyOperation, ProviderPolicyOutcome, ProviderPolicyReadRequest,
    ProviderPolicyRevokeCommand,
)
from .bootstrap import SecretProviderClientConfiguration
from .client import (
    ControlPlaneKitSecretsClient, SecretProviderClientCode, SecretProviderClientError,
    SecretProviderClientPolicy, SecretProviderOutcomeCertainty,
)

_COORDINATE_FIELDS = {"subject", "workspace_id", "action", "intent"}
_RESULT_FIELDS = _COORDINATE_FIELDS | {
    "provider_id", "correlation_id", "operation", "expected_revision", "outcome",
    "code", "grant_id", "resulting_revision", "actor", "occurred_at",
}
_GRANT_FIELDS = _COORDINATE_FIELDS | {
    "grant_id", "provider_id", "origin", "granted_by", "grant_correlation_id",
    "granted_at", "revoked_by", "revoke_correlation_id", "revoked_at",
}
_ERRORS = {
    SecretProviderClientCode.MALFORMED_CONFIGURATION: ProviderPolicyErrorCode.UNAVAILABLE,
    SecretProviderClientCode.MALFORMED_REQUEST: ProviderPolicyErrorCode.INVALID,
    SecretProviderClientCode.DENIED: ProviderPolicyErrorCode.DENIED,
    SecretProviderClientCode.MISSING: ProviderPolicyErrorCode.MISSING,
    SecretProviderClientCode.CONFLICT: ProviderPolicyErrorCode.CONFLICT,
    SecretProviderClientCode.UNAVAILABLE: ProviderPolicyErrorCode.UNAVAILABLE,
    SecretProviderClientCode.INTEGRITY_FAILURE: ProviderPolicyErrorCode.UNAVAILABLE,
    SecretProviderClientCode.REDIRECTED: ProviderPolicyErrorCode.TRANSPORT,
    SecretProviderClientCode.TIMED_OUT: ProviderPolicyErrorCode.TRANSPORT,
    SecretProviderClientCode.TRANSPORT_FAILED: ProviderPolicyErrorCode.TRANSPORT,
}


def _failure(code, *, mutation=False):
    return ProviderPolicyFailure(code, "provider-policy request failed: " + code.value,
        effect_may_have_occurred=mutation and code in (
            ProviderPolicyErrorCode.UNAVAILABLE, ProviderPolicyErrorCode.TRANSPORT,
            ProviderPolicyErrorCode.MALFORMED_RESULT))


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        raise ValueError("invalid provider-policy response shape")
    return value


def _coordinate(value):
    return ProviderPolicyCoordinate(**{key: value[key] for key in _COORDINATE_FIELDS})


def _result(value):
    _object(value, _RESULT_FIELDS)
    return ProviderPolicyCommandResult(
        provider_id=value["provider_id"], correlation_id=value["correlation_id"],
        operation=ProviderPolicyOperation(value["operation"]), coordinate=_coordinate(value),
        expected_revision=value["expected_revision"], outcome=ProviderPolicyOutcome(value["outcome"]),
        code=value["code"], grant_id=value["grant_id"], resulting_revision=value["resulting_revision"],
        provider_actor=value["actor"], occurred_at=value["occurred_at"],
    )


def _grant(value):
    _object(value, _GRANT_FIELDS)
    return ProviderPolicyGrantRecord(coordinate=_coordinate(value),
        **{key: value[key] for key in _GRANT_FIELDS - _COORDINATE_FIELDS})


@dataclass(frozen=True, repr=False)
class ControlPlaneKitSecretsPolicyClient:
    """One bounded request per call using a separately admitted fixed binding.

    Construct only after current caller admission. This client cannot authorize
    callers, discover bindings, retry commands, or reconcile durable outcomes.
    """
    configuration: SecretProviderClientConfiguration
    logical_provider_id: str
    provider_id: str
    policy: SecretProviderClientPolicy = field(default_factory=SecretProviderClientPolicy)
    transport: httpx.BaseTransport | None = field(default=None, repr=False)
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)

    def __post_init__(self):
        valid = False
        try:
            ProviderPolicyReadRequest(self.logical_provider_id, "binding-validation")
            valid = (type(self.configuration) is SecretProviderClientConfiguration
                and type(self.policy) is SecretProviderClientPolicy and callable(self.clock)
                and type(self.provider_id) is str and bool(self.provider_id.strip())
                and len(self.provider_id) <= 512
                and not any(ord(char) < 32 for char in self.provider_id))
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise _failure(ProviderPolicyErrorCode.INVALID)

    def __repr__(self):
        return "ControlPlaneKitSecretsPolicyClient(<redacted>)"

    def _validate(self, request, expected_type):
        if (type(request) is not expected_type
                or request.logical_provider_id != self.logical_provider_id):
            raise _failure(ProviderPolicyErrorCode.INVALID)
        if expected_type in (ProviderPolicyGrantCommand, ProviderPolicyRevokeCommand):
            if request.provider_id != self.provider_id or len(request.provider_correlation) > 128:
                raise _failure(ProviderPolicyErrorCode.INVALID)

    def _request(self, method, path, payload, decode):
        mutation = method == "POST"
        failure = None
        try:
            raw = ControlPlaneKitSecretsClient(self.configuration, policy=self.policy,
                transport=self.transport, clock=self.clock)._request_json(
                    method, path, payload, mutation=mutation,
                    audit_correlation_id=None if mutation else "cpk-policy-read." + uuid4().hex)
        except SecretProviderClientError as exc:
            code = _ERRORS.get(exc.code, ProviderPolicyErrorCode.MALFORMED_RESULT)
            failure = _failure(code, mutation=mutation and
                (exc.certainty is SecretProviderOutcomeCertainty.UNCERTAIN
                 or code is ProviderPolicyErrorCode.MALFORMED_RESULT))
        # Raise outside the except block: retained exception context cannot carry
        # provider text, endpoint or credential material into caller diagnostics.
        if failure is not None:
            raise failure
        try:
            return decode(raw)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            failure = _failure(ProviderPolicyErrorCode.MALFORMED_RESULT, mutation=mutation)
        raise failure

    def _mutation(self, command, expected_type):
        self._validate(command, expected_type)
        path = "/v1/provider-policy/grants"
        if expected_type is ProviderPolicyRevokeCommand:
            path += "/" + quote(command.grant_id, safe="") + "/revoke"
        payload = {**command.coordinate.descriptor(), "expected_revision": command.expected_revision,
            "correlation_id": command.provider_correlation}
        def decode(raw):
            result = _result(raw)
            if not result.matches(command):
                raise ValueError("provider-policy command mismatch")
            return result
        return self._request("POST", path, payload, decode)

    def grant(self, command: ProviderPolicyGrantCommand) -> ProviderPolicyCommandResult:
        return self._mutation(command, ProviderPolicyGrantCommand)

    def revoke(self, command: ProviderPolicyRevokeCommand) -> ProviderPolicyCommandResult:
        return self._mutation(command, ProviderPolicyRevokeCommand)

    def read(self, request: ProviderPolicyReadRequest) -> ProviderPolicyGrantRead:
        self._validate(request, ProviderPolicyReadRequest)
        def decode(raw):
            _object(raw, {"revision", "grant"})
            result = ProviderPolicyGrantRead(raw["revision"], _grant(raw["grant"]))
            if (result.grant.provider_id != self.provider_id
                    or result.grant.grant_id != request.grant_id):
                raise ValueError("provider-policy grant mismatch")
            return result
        return self._request("GET", "/v1/provider-policy/grants/" +
            quote(request.grant_id, safe=""), None, decode)

    def list(self, request: ProviderPolicyListRequest) -> ProviderPolicyGrantPage:
        self._validate(request, ProviderPolicyListRequest)
        query = {key: getattr(request, key) for key in
            ("subject", "workspace_id", "action", "intent", "limit", "after_grant_id")
            if getattr(request, key) is not None}
        query["intent_mode"] = request.intent_mode.value
        def decode(raw):
            _object(raw, {"revision", "grants", "next_after"})
            if type(raw["grants"]) is not list or len(raw["grants"]) > request.limit:
                raise ValueError("provider-policy page bound exceeded")
            result = ProviderPolicyGrantPage(raw["revision"],
                tuple(_grant(value) for value in raw["grants"]), raw["next_after"])
            previous = request.after_grant_id or ""
            for grant in result.grants:
                if (grant.provider_id != self.provider_id or grant.revoked_at is not None
                        or grant.grant_id <= previous):
                    raise ValueError("provider-policy page identity mismatch")
                previous = grant.grant_id
                for key in ("subject", "workspace_id", "action"):
                    if getattr(request, key) is not None and getattr(grant.coordinate, key) != getattr(request, key):
                        raise ValueError("provider-policy page filter mismatch")
                if (request.intent_mode is ProviderPolicyIntentMode.NONE and grant.coordinate.intent is not None
                        or request.intent_mode is ProviderPolicyIntentMode.EXACT and grant.coordinate.intent != request.intent):
                    raise ValueError("provider-policy page intent mismatch")
            if result.next_after is not None and (
                    len(result.grants) != request.limit or result.next_after != previous):
                raise ValueError("provider-policy page cursor mismatch")
            return result
        return self._request("GET", "/v1/provider-policy/grants?" + urlencode(query), None, decode)

    def command_result(self, request: ProviderPolicyCommandResultRequest) -> ProviderPolicyCommandResult:
        self._validate(request, ProviderPolicyCommandResultRequest)
        def decode(raw):
            result = _result(raw)
            if (result.provider_id != self.provider_id
                    or result.correlation_id != request.provider_correlation):
                raise ValueError("provider-policy command-result mismatch")
            return result
        return self._request("GET", "/v1/provider-policy/commands/" +
            quote(request.provider_correlation, safe=""), None, decode)
