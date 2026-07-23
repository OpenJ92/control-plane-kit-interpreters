from __future__ import annotations

from dataclasses import dataclass, field
import socket
import unittest

import httpx

from control_plane_kit_core.probe_intents import (
    EndpointContext,
    LiteralEndpointMaterial,
    RuntimeEndpointObservation,
)
from control_plane_kit_core.types import Protocol
from control_plane_kit_core.verification import (
    HttpCheck,
    HttpVerificationEvidence,
    PostgresQueryCheck,
    RedisCheck,
    RedisVerificationEvidence,
    VerificationCapability,
    VerificationOutcome,
    VerificationPolicy,
)

from control_plane_kit_interpreters.probes import ProbeAddressPolicy
from control_plane_kit_interpreters.verification import (
    HttpVerificationInterpreter,
    PostgresVerificationInterpreter,
    RedisVerificationInterpreter,
    VerificationCheckMaterial,
)


@dataclass
class ScriptedRedisTransport:
    responses: list[bytes | Exception]
    calls: list[tuple[str, int, float, int]] = field(default_factory=list)

    def ping(
        self,
        host: str,
        port: int,
        *,
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> bytes:
        self.calls.append((host, port, timeout_seconds, maximum_response_bytes))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@dataclass
class ScriptedPostgresTransport:
    responses: list[bool | Exception]
    calls: list[tuple[str, int, float]] = field(default_factory=list)

    def select_one(self, target, *, timeout_seconds: float) -> bool:
        self.calls.append((target.connect_host, target.port, timeout_seconds))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class VerificationAdapterTests(unittest.TestCase):
    def test_http_check_is_redirect_free_bounded_and_status_driven(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, content=b"semantic-ok")

        interpreter = HttpVerificationInterpreter(
            ProbeAddressPolicy(
                runtime_private_authorities=frozenset(("http://api:8080",))
            ),
            transport=httpx.MockTransport(handler),
        )

        result = interpreter.execute(_http_material())

        self.assertIs(result.outcome, VerificationOutcome.PASSED)
        self.assertIs(result.capability, VerificationCapability.HTTP)
        self.assertEqual(result.evidence, HttpVerificationEvidence(200, 11))
        self.assertEqual(requests[0].url.path, "/verify")

        redirect = HttpVerificationInterpreter(
            interpreter.policy,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    302,
                    headers={"Location": "http://other/"},
                )
            ),
        ).execute(_http_material())
        oversized = HttpVerificationInterpreter(
            interpreter.policy,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"x" * 65)
            ),
        ).execute(_http_material(maximum_bytes=64))
        self.assertIs(redirect.outcome, VerificationOutcome.MALFORMED)
        self.assertIs(oversized.outcome, VerificationOutcome.MALFORMED)

    def test_http_address_outside_policy_is_rejected_without_attempt(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(200)

        result = HttpVerificationInterpreter(
            ProbeAddressPolicy(),
            transport=httpx.MockTransport(handler),
        ).execute(_http_material())

        self.assertIs(result.outcome, VerificationOutcome.REJECTED)
        self.assertEqual(calls, 0)

    def test_redis_ping_retries_bounded_exchange_and_retains_no_payload(self) -> None:
        transport = ScriptedRedisTransport([OSError(), b"+PONG\r\n"])
        interpreter = RedisVerificationInterpreter(
            ProbeAddressPolicy(
                runtime_private_authorities=frozenset(("redis://cache:6379",))
            ),
            transport=transport,
        )

        result = interpreter.execute(_redis_material(attempts=2))

        self.assertIs(result.outcome, VerificationOutcome.PASSED)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(result.evidence, RedisVerificationEvidence(7))
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(transport.calls[0][0:2], ("cache", 6379))

    def test_postgres_select_one_is_semantic_readiness_not_tcp_reachability(self) -> None:
        transport = ScriptedPostgresTransport([False, True])
        interpreter = PostgresVerificationInterpreter(
            ProbeAddressPolicy(
                runtime_private_authorities=frozenset(("postgres://db:5432",))
            ),
            transport=transport,
        )

        result = interpreter.execute(_postgres_material(attempts=2))

        self.assertIs(result.outcome, VerificationOutcome.PASSED)
        self.assertIs(result.capability, VerificationCapability.POSTGRES)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(transport.calls, [("db", 5432, 5.0), ("db", 5432, 5.0)])
        self.assertIsNone(result.evidence)

    def test_postgres_timeout_remains_distinct_from_failed_query(self) -> None:
        transport = ScriptedPostgresTransport([socket.timeout()])
        result = PostgresVerificationInterpreter(
            ProbeAddressPolicy(
                runtime_private_authorities=frozenset(("postgres://db:5432",))
            ),
            transport=transport,
        ).execute(_postgres_material())

        self.assertIs(result.outcome, VerificationOutcome.TIMED_OUT)


def _http_material(*, maximum_bytes: int = 64) -> VerificationCheckMaterial:
    return VerificationCheckMaterial(
        "api",
        "graph-1",
        HttpCheck(
            check_id="semantic-http",
            provider_socket="internal",
            path="/verify",
            policy=VerificationPolicy(maximum_evidence_bytes=maximum_bytes),
        ),
        RuntimeEndpointObservation(
            "api",
            "internal",
            "graph-1",
            Protocol.HTTP,
            EndpointContext.RUNTIME_PRIVATE,
            LiteralEndpointMaterial("http://api:8080"),
        ),
    )


def _redis_material(*, attempts: int = 1) -> VerificationCheckMaterial:
    return VerificationCheckMaterial(
        "cache",
        "graph-1",
        RedisCheck(
            check_id="redis-ping",
            provider_socket="redis",
            policy=VerificationPolicy(maximum_attempts=attempts),
        ),
        RuntimeEndpointObservation(
            "cache",
            "redis",
            "graph-1",
            Protocol.REDIS,
            EndpointContext.RUNTIME_PRIVATE,
            LiteralEndpointMaterial("redis://cache:6379"),
        ),
    )


def _postgres_material(*, attempts: int = 1) -> VerificationCheckMaterial:
    return VerificationCheckMaterial(
        "db",
        "graph-1",
        PostgresQueryCheck(
            check_id="select-one",
            provider_socket="postgres",
            policy=VerificationPolicy(maximum_attempts=attempts),
        ),
        RuntimeEndpointObservation(
            "db",
            "postgres",
            "graph-1",
            Protocol.POSTGRES,
            EndpointContext.RUNTIME_PRIVATE,
            LiteralEndpointMaterial("postgres://db:5432"),
        ),
    )


if __name__ == "__main__":
    unittest.main()
