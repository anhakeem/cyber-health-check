"""TDD: models.py — API contract shapes. RED phase."""
import pytest
from pydantic import ValidationError

from chc.models import (
    AlertResponse,
    AuthResponse,
    CheckRequest,
    CheckResponse,
    ErrorResponse,
    HealthResponse,
)


def test_check_request_requires_url():
    with pytest.raises(ValidationError):
        CheckRequest()


def test_check_request_optional_user_id():
    r = CheckRequest(url="https://x.example/")
    assert r.user_id is None


def test_check_request_rejects_non_http_url():
    with pytest.raises(ValidationError):
        CheckRequest(url="javascript:alert(1)")


def test_check_response_fields():
    r = CheckResponse(
        indicator="https://bad.example/login",
        verdict="malicious",
        category="phishing",
        confidence=0.97,
        sources=["phishtank", "misp"],
        cached=False,
    )
    assert r.verdict == "malicious"
    assert r.cached is False


def test_check_response_verdict_enum():
    with pytest.raises(ValidationError):
        CheckResponse(indicator="x", verdict="bogus")


def test_alert_response_fields():
    r = AlertResponse(
        id="a1",
        org_id="o1",
        user_id="u1",
        indicator="https://bad.example/",
        verdict="malicious",
        category="phishing",
        url="https://bad.example/",
        severity="high",
        created_at="2026-10-11T00:00:00Z",
    )
    assert r.severity == "high"


def test_alert_response_severity_enum():
    with pytest.raises(ValidationError):
        AlertResponse(
            id="a1", org_id="o1", user_id="u1", indicator="x",
            verdict="malicious", category=None, url=None,
            severity="extreme", created_at="2026-10-11T00:00:00Z",
        )


def test_health_response_fields():
    r = HealthResponse(status="ok", feeds={"phishtank": "ok", "misp": "ok", "abuseipdb": "ok"})
    assert r.feeds["phishtank"] == "ok"


def test_auth_response_fields():
    r = AuthResponse(access_token="t", refresh_token="r", expires_in=3600)
    assert r.expires_in == 3600


def test_error_response_fields():
    r = ErrorResponse(error={"code": "VALIDATION_ERROR", "message": "url is required", "details": {}})
    assert r.error["code"] == "VALIDATION_ERROR"
