"""Tests for the alert store + /alerts endpoint (architecture §3, §4)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from chc.alerts import AlertStore
from chc.api.main import create_app
from chc.reputation import MergedVerdict


# ---- AlertStore ------------------------------------------------------------

def test_store_add_and_list(tmp_path):
    store = AlertStore(db_path=str(tmp_path / "a.db"))
    store.add(org_id="o1", user_id="u1", indicator="https://bad.example/x",
              verdict="malicious", category="phishing", severity="high")
    rows = store.list(org_id="o1")
    assert len(rows) == 1
    assert rows[0]["indicator"] == "https://bad.example/x"
    assert rows[0]["severity"] == "high"


def test_store_isolates_tenants(tmp_path):
    """Tenant isolation: org A must never see org B's alerts."""
    store = AlertStore(db_path=str(tmp_path / "a.db"))
    store.add(org_id="o1", user_id="u1", indicator="https://a.example",
              verdict="malicious", category="phishing", severity="high")
    store.add(org_id="o2", user_id="u2", indicator="https://b.example",
              verdict="malicious", category="malware", severity="high")
    a = store.list(org_id="o1")
    assert len(a) == 1 and a[0]["indicator"] == "https://a.example"


def test_store_severity_filter(tmp_path):
    store = AlertStore(db_path=str(tmp_path / "a.db"))
    store.add(org_id="o1", user_id="u1", indicator="https://x", verdict="suspicious",
              category=None, severity="low")
    store.add(org_id="o1", user_id="u1", indicator="https://y", verdict="malicious",
              category="phishing", severity="critical")
    crit = store.list(org_id="o1", severity="critical")
    assert len(crit) == 1 and crit[0]["indicator"] == "https://y"


def test_store_newest_first(tmp_path):
    store = AlertStore(db_path=str(tmp_path / "a.db"))
    for i in range(3):
        store.add(org_id="o1", user_id="u1", indicator=f"https://{i}",
                  verdict="malicious", category=None, severity="high")
    rows = store.list(org_id="o1")
    assert rows[0]["indicator"] == "https://2"  # newest first


def test_store_pagination(tmp_path):
    store = AlertStore(db_path=str(tmp_path / "a.db"))
    for i in range(10):
        store.add(org_id="o1", user_id="u1", indicator=f"https://{i}",
                  verdict="malicious", category=None, severity="high")
    page = store.list(org_id="o1", limit=3, offset=0)
    assert len(page) == 3


# ---- /alerts endpoint ------------------------------------------------------

class FakeReputation:
    def check(self, indicator, kind=None):
        return MergedVerdict("malicious", "phishing", 0.9, ["phishtank"])


def test_alerts_endpoint_returns_recorded(tmp_path):
    store = AlertStore(db_path=str(tmp_path / "a.db"))
    store.add(org_id="o1", user_id="u1", indicator="https://bad.example",
              verdict="malicious", category="phishing", severity="high")
    app = create_app(reputation_factory=lambda: FakeReputation(),
                     alert_store_factory=lambda: store)
    client = TestClient(app)
    resp = client.get("/api/v1/alerts?org_id=o1")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["alerts"]) == 1
    assert body["alerts"][0]["indicator"] == "https://bad.example"


def test_alerts_endpoint_paginates(tmp_path):
    store = AlertStore(db_path=str(tmp_path / "a.db"))
    for i in range(5):
        store.add(org_id="o1", user_id="u1", indicator=f"https://{i}",
                  verdict="malicious", category=None, severity="high")
    app = create_app(reputation_factory=lambda: FakeReputation(),
                     alert_store_factory=lambda: store)
    client = TestClient(app)
    resp = client.get("/api/v1/alerts?org_id=o1&limit=2")
    body = resp.json()
    assert len(body["alerts"]) == 2
    assert body["pagination"]["total"] == 5
