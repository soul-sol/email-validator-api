from __future__ import annotations

import re
from dataclasses import dataclass

from app.disposable import DISPOSABLE_DOMAINS
from app.dns_lookup import DnsResult, lookup_mail_dns
from app.models import ValidationResult
from app.providers import COMMON_PROVIDER_DOMAINS, FREE_PROVIDER_DOMAINS, ROLE_LOCAL_PARTS

LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$")
DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True, slots=True)
class NormalizedAddress:
    value: str
    local: str
    domain: str | None
    idn: bool
    is_ascii: bool
    normalization_error: bool = False


def _normalize(raw: str) -> NormalizedAddress:
    trimmed = raw.strip()
    if trimmed.count("@") != 1:
        return NormalizedAddress(trimmed, "", None, False, trimmed.isascii(), True)

    local, original_domain = trimmed.rsplit("@", 1)
    lowered_domain = original_domain.lower()
    idn = not lowered_domain.isascii()
    try:
        ascii_domain = lowered_domain.encode("idna").decode("ascii")
    except UnicodeError:
        return NormalizedAddress(trimmed, local, lowered_domain, idn, trimmed.isascii(), True)

    value = f"{local}@{ascii_domain}"
    return NormalizedAddress(value, local, ascii_domain, idn, trimmed.isascii())


def _valid_syntax(address: NormalizedAddress) -> bool:
    if address.normalization_error or address.domain is None:
        return False
    if not address.local or len(address.local) > 64 or len(address.value) > 254:
        return False
    if not address.local.isascii() or not LOCAL_RE.fullmatch(address.local):
        return False
    if address.local.startswith(".") or address.local.endswith(".") or ".." in address.local:
        return False
    if len(address.domain) > 253 or address.domain.endswith("."):
        return False
    labels = address.domain.split(".")
    if len(labels) < 2 or any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return False
    if labels[-1].isdigit():
        return False
    return True


def _domain_in(domain: str | None, domains: frozenset[str]) -> bool:
    if domain is None:
        return False
    return domain in domains or any(domain.endswith(f".{candidate}") for candidate in domains)


def _edit_distance(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def _suggestion(local: str, domain: str | None) -> str | None:
    if not local or domain is None or domain in COMMON_PROVIDER_DOMAINS:
        return None
    ranked = sorted((_edit_distance(domain, candidate), candidate) for candidate in COMMON_PROVIDER_DOMAINS)
    distance, candidate = ranked[0]
    threshold = 1 if len(candidate) < 8 else 2
    if distance <= threshold:
        return f"{local}@{candidate}"
    return None


def _score(
    *,
    syntax_valid: bool,
    dns_result: DnsResult,
    is_disposable: bool,
    is_role_account: bool,
    suggestion: str | None,
) -> tuple[int, str]:
    if not syntax_valid:
        return 0, "undeliverable"

    score = 60
    if dns_result.has_mx is True:
        score += 30
    elif dns_result.has_mx is False:
        score -= 40
    else:
        score -= 10
    if is_disposable:
        score -= 30
    if is_role_account:
        score -= 10
    if suggestion is not None:
        score -= 20
    score = max(0, min(100, score))

    if score >= 75:
        verdict = "deliverable_likely"
    elif score >= 40:
        verdict = "risky"
    else:
        verdict = "undeliverable"
    return score, verdict


def validate_email(raw: str) -> ValidationResult:
    normalized = _normalize(raw)
    syntax_valid = _valid_syntax(normalized)
    local_key = normalized.local.split("+", 1)[0].lower()
    is_disposable = _domain_in(normalized.domain, DISPOSABLE_DOMAINS)
    is_role_account = local_key in ROLE_LOCAL_PARTS
    is_free_provider = _domain_in(normalized.domain, FREE_PROVIDER_DOMAINS)
    suggestion = _suggestion(normalized.local, normalized.domain)

    if syntax_valid and normalized.domain is not None:
        dns_result = lookup_mail_dns(normalized.domain)
    else:
        dns_result = DnsResult(None, (), "DNS lookup skipped because syntax is invalid.")

    score, verdict = _score(
        syntax_valid=syntax_valid,
        dns_result=dns_result,
        is_disposable=is_disposable,
        is_role_account=is_role_account,
        suggestion=suggestion,
    )
    return ValidationResult(
        input=raw,
        normalized=normalized.value,
        syntax_valid=syntax_valid,
        domain=normalized.domain,
        is_ascii=normalized.is_ascii,
        idn=normalized.idn,
        has_mx=dns_result.has_mx,
        mx_hosts=list(dns_result.mx_hosts),
        is_disposable=is_disposable,
        is_role_account=is_role_account,
        is_free_provider=is_free_provider,
        suggestion=suggestion,
        score=score,
        verdict=verdict,
        note=dns_result.note,
    )
