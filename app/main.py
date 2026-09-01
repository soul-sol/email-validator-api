from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.models import BatchValidationResult, ValidateRequest, ValidationResult
from app.validator import validate_email

_VALIDATION_POOL = ThreadPoolExecutor(max_workers=10, thread_name_prefix="email-validation")

app = FastAPI(
    title="Email Validator API",
    version="1.0.0",
    description=(
        "Heuristic email syntax and domain validation without sending mail. "
        "No SMTP probe is performed, so results cannot guarantee mailbox existence "
        "or deliverability."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def usage_page() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Email Validator API</title></head><body>
<main><h1>Email Validator API</h1>
<p>Heuristic validation only. No email is sent and no SMTP probe is performed.</p>
<pre>GET /validate?email=user@example.com
POST /validate  {"emails":["first@example.com","second@example.com"]}</pre>
<p><a href="/docs">Interactive docs</a> · <a href="/openapi.json">OpenAPI JSON</a></p>
</main></body></html>"""


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/validate", response_model=ValidationResult)
def validate_get(email: str = Query(..., min_length=1, max_length=1024)) -> ValidationResult:
    return validate_email(email)


@app.post("/validate", response_model=ValidationResult | BatchValidationResult)
def validate_post(payload: ValidateRequest) -> ValidationResult | BatchValidationResult:
    if payload.email is not None:
        return validate_email(payload.email)
    addresses = payload.emails or []
    results = list(_VALIDATION_POOL.map(validate_email, addresses))
    return BatchValidationResult(count=len(results), results=results)
