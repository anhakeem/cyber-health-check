"""API contract models (pydantic) — frozen v1."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

_VERDICTS = {"malicious", "suspicious", "clean", "unknown"}
_SEVERITIES = {"low", "medium", "high", "critical"}


class CheckRequest(BaseModel):
    url: str = Field(min_length=1)
    user_id: str | None = None

    @field_validator("url")
    @classmethod
    def _validate_url_scheme(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must be http(s)")
        return v


class CheckResponse(BaseModel):
    indicator: str
    verdict: str
    category: str | None = None
    confidence: float = 0.0
    sources: list[str] = Field(default_factory=list)
    cached: bool = False

    @field_validator("verdict")
    @classmethod
    def _validate_verdict(cls, v: str) -> str:
        if v not in _VERDICTS:
            raise ValueError(f"verdict must be one of {_VERDICTS}")
        return v


class AlertResponse(BaseModel):
    id: str
    org_id: str
    user_id: str
    indicator: str
    verdict: str
    category: str | None = None
    url: str | None = None
    severity: str
    created_at: str

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        if v not in _SEVERITIES:
            raise ValueError(f"severity must be one of {_SEVERITIES}")
        return v


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int = 3600


class HealthResponse(BaseModel):
    status: str
    feeds: dict[str, str]


class ErrorResponse(BaseModel):
    error: dict[str, object]
