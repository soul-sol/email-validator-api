from __future__ import annotations

from dataclasses import dataclass

import dns.exception
import dns.resolver
import pytest
from fastapi.testclient import TestClient

from app.dns_lookup import DnsResult, clear_dns_cache, lookup_mail_dns
from app.main import app


@pytest.fixture(autouse=True)
def deterministic_validator_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.validator.lookup_mail_dns",
        lambda domain: DnsResult(True, (f"mx.{domain}",), "Mock MX record found."),
    )


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.mark.parametrize(
    ("email", "expected"),
    [
        ("person@example.com", True),
        ("first.last+tag@example.co.uk", True),
        ("personexample.com", False),
        ("person@@example.com", False),
        (".person@example.com", False),
        ("person..tag@example.com", False),
        (f"{'a' * 65}@example.com", False),
        (f"a@{'b' * 250}.com", False),
        ("person@bad_domain.com", False),
    ],
)
def test_syntax_cases(client: TestClient, email: str, expected: bool) -> None:
    response = client.get("/validate", params={"email": email})
    assert response.status_code == 200
    assert response.json()["syntax_valid"] is expected


def test_normalizes_trim_case_and_idn(client: TestClient) -> None:
    response = client.get("/validate", params={"email": "  User@BÜCHER.de  "})
    body = response.json()

    assert body["normalized"] == "User@xn--bcher-kva.de"
    assert body["domain"] == "xn--bcher-kva.de"
    assert body["idn"] is True
    assert body["is_ascii"] is False
    assert body["syntax_valid"] is True


def test_role_free_and_disposable_detection(client: TestClient) -> None:
    role = client.get("/validate", params={"email": "Support+eu@GMAIL.com"}).json()
    disposable = client.get("/validate", params={"email": "person@mailinator.com"}).json()

    assert role["is_role_account"] is True
    assert role["is_free_provider"] is True
    assert role["is_disposable"] is False
    assert disposable["is_disposable"] is True
    assert disposable["is_free_provider"] is False
    assert disposable["verdict"] == "risky"


@pytest.mark.parametrize(
    ("email", "suggestion"),
    [
        ("person@gmial.com", "person@gmail.com"),
        ("person@hotmial.com", "person@hotmail.com"),
        ("person@gmail.com", None),
        ("person@company-example.com", None),
    ],
)
def test_provider_typo_suggestion(client: TestClient, email: str, suggestion: str | None) -> None:
    assert client.get("/validate", params={"email": email}).json()["suggestion"] == suggestion


def test_single_and_batch_post(client: TestClient) -> None:
    single = client.post("/validate", json={"email": "person@example.com"})
    batch = client.post(
        "/validate",
        json={"emails": ["first@example.com", "bad-address"]},
    )

    assert single.status_code == 200
    assert single.json()["input"] == "person@example.com"
    assert batch.status_code == 200
    assert batch.json()["count"] == 2
    assert [item["syntax_valid"] for item in batch.json()["results"]] == [True, False]


def test_batch_limit_and_request_shape(client: TestClient) -> None:
    too_many = client.post(
        "/validate",
        json={"emails": [f"person{index}@example.com" for index in range(51)]},
    )
    both = client.post(
        "/validate",
        json={"email": "one@example.com", "emails": ["two@example.com"]},
    )

    assert too_many.status_code == 422
    assert "at most 50" in too_many.text
    assert both.status_code == 422


@dataclass
class FakeName:
    value: str

    def to_text(self) -> str:
        return self.value


@dataclass
class FakeMx:
    preference: int
    exchange: FakeName


def test_dns_mocked_mx_path_and_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_resolve(self: object, domain: str, record_type: str, **kwargs: object) -> list[FakeMx]:
        calls.append((domain, record_type))
        assert kwargs["lifetime"] == 3.0
        return [FakeMx(20, FakeName("mx2.example.")), FakeMx(10, FakeName("mx1.example."))]

    clear_dns_cache()
    monkeypatch.setattr("dns.resolver.Resolver.resolve", fake_resolve)

    first = lookup_mail_dns("dns-mock.example")
    second = lookup_mail_dns("dns-mock.example")

    assert first.has_mx is True
    assert first.mx_hosts == ("mx1.example", "mx2.example")
    assert second == first
    assert calls == [("dns-mock.example", "MX")]


def test_dns_timeout_degrades_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(self: object, domain: str, record_type: str, **kwargs: object) -> None:
        raise dns.exception.Timeout

    clear_dns_cache()
    monkeypatch.setattr("dns.resolver.Resolver.resolve", timeout)

    result = lookup_mail_dns("timeout.example")

    assert result.has_mx is None
    assert result.mx_hosts == ()
    assert "timed out" in result.note


def test_dns_uses_rfc5321_address_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_resolve(self: object, domain: str, record_type: str, **kwargs: object) -> list[object]:
        calls.append(record_type)
        if record_type == "MX":
            raise dns.resolver.NoAnswer
        if record_type == "A":
            return [object()]
        raise AssertionError("AAAA must not be queried after an A record is found")

    clear_dns_cache()
    monkeypatch.setattr("dns.resolver.Resolver.resolve", fake_resolve)

    result = lookup_mail_dns("fallback.example")

    assert result.has_mx is True
    assert result.mx_hosts == ()
    assert "A address fallback" in result.note
    assert calls == ["MX", "A"]


def test_null_mx_does_not_fall_back(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_resolve(self: object, domain: str, record_type: str, **kwargs: object) -> list[FakeMx]:
        calls.append(record_type)
        return [FakeMx(0, FakeName("."))]

    clear_dns_cache()
    monkeypatch.setattr("dns.resolver.Resolver.resolve", fake_resolve)

    result = lookup_mail_dns("null-mx.example")

    assert result.has_mx is False
    assert result.mx_hosts == ()
    assert "null MX" in result.note
    assert calls == ["MX"]


def test_health_root_openapi_and_cors(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}
    assert "No email is sent" in client.get("/").text
    assert "/validate" in client.get("/openapi.json").json()["paths"]

    preflight = client.options(
        "/validate",
        headers={
            "Origin": "https://client.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "*"
