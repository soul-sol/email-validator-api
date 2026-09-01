from typing import Self

from pydantic import BaseModel, Field, model_validator


class ValidateRequest(BaseModel):
    email: str | None = Field(default=None, max_length=1024)
    emails: list[str] | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if (self.email is None) == (self.emails is None):
            raise ValueError("provide exactly one of 'email' or 'emails'")
        if self.emails is not None:
            if not self.emails:
                raise ValueError("'emails' must contain at least one address")
            if len(self.emails) > 50:
                raise ValueError("'emails' may contain at most 50 addresses")
            if any(len(value) > 1024 for value in self.emails):
                raise ValueError("each email must be at most 1024 characters")
        return self


class ValidationResult(BaseModel):
    input: str
    normalized: str
    syntax_valid: bool
    domain: str | None
    is_ascii: bool
    idn: bool
    has_mx: bool | None
    mx_hosts: list[str]
    is_disposable: bool
    is_role_account: bool
    is_free_provider: bool
    suggestion: str | None
    score: int = Field(ge=0, le=100)
    verdict: str
    note: str


class BatchValidationResult(BaseModel):
    count: int
    results: list[ValidationResult]

