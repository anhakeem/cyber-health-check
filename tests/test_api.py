"""Tests for the Cyber Health Check FastAPI layer (architecture §4 contract)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from chc.api.main import create_app
from chc.reputation import MergedVerdict


class FakeReputationService:
    def __init__(self, verdict=None, raise_on=None):
        self._verdict = verdict or MergedVerdict(
            verdict="malicious", category="phishing", confidence=0.97,
            sources=["phishtank", "misp"],
        )
        self._raise_on = raise_on
        self.calls: list[tuple[str, str | None]] = []

    def check(self, indicator, kind=None):
        self.calls.append((indicator, kind))
        if self._raise_on and kind == self._raise_on:
            raise ValueError("bad indicator")
        return self._verdict


def make_client(service) -> TestClient:
    app = create_app(reputation_factory=lambda: service)
    return TestClient(app)


# ---- POST /api/v1/check-url -----------------------------------------------

def test_check_url_returns_verdict():
    svc = FakeReputationService()
    client = make_client(svc)
    resp = client.post("/api/v1/check-url", json={"url": "https://bad.example/login"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "malicious"
    assert body["category"] == "phishing"
    assert body["sources"] == ["phishtank", "misp"]
    assert svc.calls[0][1] == "url"


def test_check_url_rejects_non_http_scheme():
    client = make_client(FakeReputationService())
    resp = client.post("/api/v1/check-url", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_check_url_rejects_private_ip():
    """SSRF: a private-IP URL must be refused at the boundary."""
    svc = FakeReputationService(raise_on="url")
    client = make_client(svc)
    resp = client.post("/api/v1/check-url", json={"url": "http://169.254.169.254/"})
    assert resp.status_code == 422


# ---- POST /api/v1/check-domain --------------------------------------------

def test_check_domain_accepts_bare_domain():
    svc = FakeReputationService()
    client = make_client(svc)
    resp = client.post("/api/v1/check-domain", json={"domain": "bad.example"})
    assert resp.status_code == 200
    assert svc.calls[0][1] == "domain"


# ---- GET /api/v1/health ----------------------------------------------------

def test_health_ok():
    client = make_client(FakeReputationService())
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---- error shape -----------------------------------------------------------

def test_error_shape_is_consistent():
    client = make_client(FakeReputationService())
    resp = client.post("/api/v1/check-url", json={"url": "ftp://x"})
    err = resp.json()["error"]
    assert set(err) >= {"code", "message"}
