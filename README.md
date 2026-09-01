# Email Validator API

**Live instance:** https://email.lifestep.io — try `/health`, and see `/openapi.json` for the full spec. Free, no signup.

**Self-host it:** `docker compose up -d` (see below). MIT licensed.

A small FastAPI utility for checking email-address syntax, mail-routing DNS, and
common risk signals without sending an email and without a paid third-party API.

## Run locally

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Or run the hardened container definition:

```bash
docker compose up --build
```

Docker Compose maps the service to `http://127.0.0.1:8087`. Interactive API docs
are at `/docs`; OpenAPI JSON is always available at `/openapi.json`.

## Endpoints

- `GET /validate?email=person@example.com`
- `POST /validate` with `{"email":"person@example.com"}`
- `POST /validate` with `{"emails":["one@example.com","two@example.com"]}`
  (1–50 addresses)
- `GET /health`
- `GET /` for a tiny usage page

Examples:

```bash
curl --get http://127.0.0.1:8087/validate \
  --data-urlencode 'email=User@BÜCHER.de'

curl http://127.0.0.1:8087/validate \
  -H 'Content-Type: application/json' \
  -d '{"emails":["person@gmail.com","person@gmial.com"]}'
```

A single request returns one result object. A batch returns
`{"count": 2, "results": [...]}`. Each result contains:

```json
{
  "input": " person@GMIAL.com ",
  "normalized": "person@gmial.com",
  "syntax_valid": true,
  "domain": "gmial.com",
  "is_ascii": true,
  "idn": false,
  "has_mx": false,
  "mx_hosts": [],
  "is_disposable": false,
  "is_role_account": false,
  "is_free_provider": false,
  "suggestion": "person@gmail.com",
  "score": 0,
  "verdict": "undeliverable",
  "note": "No MX, A, or AAAA mail-routing records were found."
}
```

`normalized` trims surrounding whitespace, preserves the local-part's case, and
lowercases the domain. Unicode domains are IDNA/punycode encoded; `idn` reports
that conversion. `is_ascii` reports whether the trimmed input was entirely ASCII.

## Checks and scoring

- Practical RFC-5322-style dot-atom syntax, including local-part length ≤64 and
  total normalized length ≤254. This intentionally does not accept every obscure
  quoted-address form allowed by the full RFC.
- MX lookup with a 3-second lifetime. When there is no MX response, A and AAAA are
  checked as the RFC 5321 implicit routing fallback. Up to three MX hosts are
  returned in preference order.
- DNS results are cached in process for 600 seconds. Each worker has its own cache;
  it is intentionally not shared or persistent.
- Batch validation uses a bounded 10-thread pool so independent DNS waits do not
  serialize all 50 addresses.
- A static bundled set of 218 established disposable-mail domains, plus role-account
  and common free-provider sets. Nothing is fetched at runtime.
- Provider typo suggestions use Levenshtein edit distance. A suggestion is the full
  corrected address, not an automatic rewrite.

The score begins at 60 for valid syntax, adds 30 for usable mail-routing DNS, and
subtracts risk weights for missing/unknown DNS, disposable domains, role accounts,
or a likely provider typo. It is clamped to 0–100. Scores ≥75 are
`deliverable_likely`, 40–74 are `risky`, and lower scores are `undeliverable`.

## Honest limits

- **No SMTP probe is performed.** The API never connects to a mail server or sends
  mail.
- Syntax and DNS cannot prove that a mailbox exists, accepts mail, is monitored, or
  will accept a particular future message. There is no deliverability guarantee.
- `has_mx: true` means usable mail-routing DNS was found. It can come from an MX
  record or, when MX is absent, the RFC 5321 A/AAAA fallback; `mx_hosts` remains
  empty for an address-record fallback.
- `has_mx: null` means DNS was unavailable or timed out, not that the address is
  invalid. The `note` field explains the state.
- Disposable-domain lists, role labels, free-provider lists, typo detection, score,
  and verdict are heuristics. Domains and provider behavior change over time.
- Internationalized domains are supported through IDNA. Unicode local parts
  (SMTPUTF8) are not accepted by this practical validator.

## Tests

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
PYTHONPATH=. .venv/bin/pytest -q
```

The test suite mocks DNS; it does not depend on public resolvers or network access.
