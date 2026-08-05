"""Bounded fresh public DNS resolution for public endpoint verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlsplit

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import httpx


_DNS_MEDIA_TYPE = "application/dns-message"
_MAXIMUM_RESPONSE_BYTES = 65_535
_MAXIMUM_RECORDS = 128


class PublicDnsResolutionCode(StrEnum):
    MALFORMED_CONFIGURATION = "malformed-configuration"
    INVALID_HOSTNAME = "invalid-hostname"
    TIMED_OUT = "timed-out"
    TRANSPORT_FAILED = "transport-failed"
    RESPONSE_TOO_LARGE = "response-too-large"
    REJECTED_RESPONSE = "rejected-response"
    MALFORMED_RESPONSE = "malformed-response"


class PublicDnsResolutionError(RuntimeError):
    """Bounded resolver failure without endpoint or query material."""

    def __init__(self, code: PublicDnsResolutionCode) -> None:
        self.code = code
        super().__init__(f"public DNS resolution failed: {code.value}")


@dataclass(frozen=True)
class PublicDnsResolverPolicy:
    timeout_seconds: float = 3.0
    maximum_response_bytes: int = 16 * 1024
    maximum_records: int = 32

    def __post_init__(self) -> None:
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not 0 < float(self.timeout_seconds) <= 30
            or type(self.maximum_response_bytes) is not int
            or not 64 <= self.maximum_response_bytes <= _MAXIMUM_RESPONSE_BYTES
            or type(self.maximum_records) is not int
            or not 1 <= self.maximum_records <= _MAXIMUM_RECORDS
        ):
            raise PublicDnsResolutionError(
                PublicDnsResolutionCode.MALFORMED_CONFIGURATION
            )


@dataclass(frozen=True)
class _DnsAnswer:
    addresses: tuple[str, ...]
    nxdomain: bool = False


@dataclass(repr=False)
class DnsOverHttpsPublicAddressResolver:
    """Issue one fresh bounded RFC 8484 query for each address family."""

    endpoint_url: str
    policy: PublicDnsResolverPolicy = field(default_factory=PublicDnsResolverPolicy)
    transport: httpx.BaseTransport | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.policy, PublicDnsResolverPolicy):
            raise PublicDnsResolutionError(
                PublicDnsResolutionCode.MALFORMED_CONFIGURATION
            )
        if not isinstance(self.endpoint_url, str):
            raise PublicDnsResolutionError(
                PublicDnsResolutionCode.MALFORMED_CONFIGURATION
            )
        try:
            endpoint = urlsplit(self.endpoint_url)
            endpoint.port
        except ValueError:
            raise PublicDnsResolutionError(
                PublicDnsResolutionCode.MALFORMED_CONFIGURATION
            ) from None
        if (
            endpoint.scheme != "https"
            or endpoint.hostname is None
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.path in ("", "/")
            or endpoint.query
            or endpoint.fragment
        ):
            raise PublicDnsResolutionError(
                PublicDnsResolutionCode.MALFORMED_CONFIGURATION
            )

    def resolve(self, hostname: str) -> tuple[str, ...]:
        qname = _query_name(hostname)
        addresses: set[str] = set()
        record_count = 0
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            answer = self._query(qname, rdtype)
            if answer.nxdomain:
                return ()
            addresses.update(answer.addresses)
            record_count += len(answer.addresses)
            if record_count > self.policy.maximum_records:
                raise PublicDnsResolutionError(
                    PublicDnsResolutionCode.MALFORMED_RESPONSE
                )
        return tuple(sorted(addresses))

    def _query(self, qname: dns.name.Name, rdtype: int) -> _DnsAnswer:
        query = dns.message.make_query(
            qname,
            rdtype,
            rdclass=dns.rdataclass.IN,
            use_edns=0,
            payload=1232,
        )
        request_body = query.to_wire()
        try:
            with httpx.Client(
                transport=self.transport,
                timeout=httpx.Timeout(float(self.policy.timeout_seconds)),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "POST",
                    self.endpoint_url,
                    headers={
                        "Accept": _DNS_MEDIA_TYPE,
                        "Content-Type": _DNS_MEDIA_TYPE,
                    },
                    content=request_body,
                ) as response:
                    if response.status_code != 200:
                        raise PublicDnsResolutionError(
                            PublicDnsResolutionCode.REJECTED_RESPONSE
                        )
                    media_type = response.headers.get("content-type", "").split(
                        ";",
                        1,
                    )[0].strip().lower()
                    if media_type != _DNS_MEDIA_TYPE:
                        raise PublicDnsResolutionError(
                            PublicDnsResolutionCode.MALFORMED_RESPONSE
                        )
                    response_body = bytearray()
                    for chunk in response.iter_bytes():
                        response_body.extend(chunk)
                        if len(response_body) > self.policy.maximum_response_bytes:
                            raise PublicDnsResolutionError(
                                PublicDnsResolutionCode.RESPONSE_TOO_LARGE
                            )
        except PublicDnsResolutionError:
            raise
        except httpx.TimeoutException:
            raise PublicDnsResolutionError(
                PublicDnsResolutionCode.TIMED_OUT
            ) from None
        except httpx.HTTPError:
            raise PublicDnsResolutionError(
                PublicDnsResolutionCode.TRANSPORT_FAILED
            ) from None

        try:
            message = dns.message.from_wire(bytes(response_body))
            if not query.is_response(message):
                raise dns.exception.FormError
            response_code = message.rcode()
            if response_code == dns.rcode.NXDOMAIN:
                return _DnsAnswer((), nxdomain=True)
            if response_code != dns.rcode.NOERROR:
                raise dns.exception.FormError
            if sum(len(rrset) for rrset in message.answer) > self.policy.maximum_records:
                raise dns.exception.FormError
            answer = dns.resolver.Answer(
                qname,
                rdtype,
                dns.rdataclass.IN,
                message,
            )
            if answer.rrset is None:
                return _DnsAnswer(())
            addresses = tuple(
                record.address
                for record in answer.rrset
                if answer.rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
            )
        except (dns.exception.DNSException, AttributeError, TypeError, ValueError):
            raise PublicDnsResolutionError(
                PublicDnsResolutionCode.MALFORMED_RESPONSE
            ) from None
        return _DnsAnswer(addresses)

    def __repr__(self) -> str:
        return (
            "DnsOverHttpsPublicAddressResolver("
            "endpoint_url=<redacted>, "
            f"policy={self.policy!r})"
        )


def _query_name(hostname: str) -> dns.name.Name:
    if not isinstance(hostname, str) or not hostname or hostname != hostname.strip():
        raise PublicDnsResolutionError(PublicDnsResolutionCode.INVALID_HOSTNAME)
    try:
        qname = dns.name.from_unicode(hostname, origin=dns.name.root)
        wire = qname.to_wire()
    except (dns.exception.DNSException, UnicodeError, ValueError):
        raise PublicDnsResolutionError(
            PublicDnsResolutionCode.INVALID_HOSTNAME
        ) from None
    if qname == dns.name.root or len(wire) > 255:
        raise PublicDnsResolutionError(PublicDnsResolutionCode.INVALID_HOSTNAME)
    return qname
