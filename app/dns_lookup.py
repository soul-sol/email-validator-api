from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from time import monotonic

import dns.exception
import dns.resolver

DNS_TIMEOUT_SECONDS = 3.0
CACHE_TTL_SECONDS = 600.0


@dataclass(frozen=True, slots=True)
class DnsResult:
    has_mx: bool | None
    mx_hosts: tuple[str, ...]
    note: str


_cache: dict[str, tuple[float, DnsResult]] = {}
_cache_lock = Lock()


def clear_dns_cache() -> None:
    """Clear the process-local cache. Primarily useful for deterministic tests."""
    with _cache_lock:
        _cache.clear()


def lookup_mail_dns(domain: str) -> DnsResult:
    now = monotonic()
    with _cache_lock:
        cached = _cache.get(domain)
        if cached is not None and cached[0] > now:
            return cached[1]
        if cached is not None:
            _cache.pop(domain, None)

    result = _lookup_uncached(domain)
    with _cache_lock:
        _cache[domain] = (monotonic() + CACHE_TTL_SECONDS, result)
    return result


def _lookup_uncached(domain: str) -> DnsResult:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_TIMEOUT_SECONDS

    try:
        answers = resolver.resolve(domain, "MX", lifetime=DNS_TIMEOUT_SECONDS)
        records = sorted(
            (
                (int(record.preference), record.exchange.to_text().rstrip("."))
                for record in answers
            ),
            key=lambda item: (item[0], item[1]),
        )
        # A single MX target of "." explicitly declares that the domain accepts no
        # email (RFC 7505), so an address-record fallback would be incorrect.
        if records and all(not host for _, host in records):
            return DnsResult(False, (), "Domain publishes a null MX and does not accept email.")
        hosts = tuple(host for _, host in records if host)[:3]
        if hosts:
            return DnsResult(True, hosts, "MX records found; no SMTP probe was performed.")
    except dns.resolver.NXDOMAIN:
        return DnsResult(False, (), "Domain does not exist in DNS.")
    except dns.resolver.NoAnswer:
        pass
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        return DnsResult(None, (), "DNS lookup timed out; result is unknown.")
    except (dns.resolver.NoNameservers, dns.exception.DNSException):
        return DnsResult(None, (), "DNS lookup failed temporarily; result is unknown.")

    # RFC 5321 permits implicit mail routing to a domain's address when no MX exists.
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(domain, record_type, lifetime=DNS_TIMEOUT_SECONDS)
            if any(True for _ in answers):
                return DnsResult(
                    True,
                    (),
                    f"No MX record; {record_type} address fallback is available (RFC 5321).",
                )
        except dns.resolver.NXDOMAIN:
            return DnsResult(False, (), "Domain does not exist in DNS.")
        except dns.resolver.NoAnswer:
            continue
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            return DnsResult(None, (), "DNS lookup timed out; result is unknown.")
        except (dns.resolver.NoNameservers, dns.exception.DNSException):
            return DnsResult(None, (), "DNS lookup failed temporarily; result is unknown.")

    return DnsResult(False, (), "No MX, A, or AAAA mail-routing records were found.")

