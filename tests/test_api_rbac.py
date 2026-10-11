"""Tests for RBAC-enforced API endpoints (alerts read, users list)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from chc.alerts import AlertStore
from chc.api.main import create_app
from chc.auth import OrgStore
from chc.reputation import MergedVerdict


class FakeReputation:
    def check(self, indicator, kind=None):
        return MergedVerdict("malicious", "phishing", 0.9, ["phishtank"])


def _client(tmp_path):
    alerts = AlertStore(db_path=str(tmp_path / "a.db"))
    orgs = OrgStore(db_path=str(tmp_path / "o.db"))
    org = orgs.create_org(name="Acme")
    owner = orgs.add_user(org_id=org, email="o@acme.test", role="owner")
    member = orgs.add_user(org_id=org, email="m@acme.test", role="member")
    alerts.add(org_id=org, user_id=member, indicator="https://bad.example",
               verdict="malicious", category="phishing", severity="high")
    app = create_app(reputation_factory=lambda: FakeReputation(),
                     alert_store_factory=lambda: alerts,
                     org_store_factory=lambda: orgs)
    return TestClient(app), org, owner, member


def test_alerts_read_allowed_for_member(tmp_path):
    client, org, owner, member = _client(tmp_path)
    r = client.get(f"/api/v1/alerts?org_id={org}", headers={"x-user-id": member})
    assert r.status_code == 200
    assert len(r.json()["alerts"]) == 1


def test_alerts_read_forbidden_for_non_member(tmp_path):
    client, org, owner, member = _client(tmp_path)
    r = client.get(f"/api/v1/alerts?org_id={org}", headers={"x-user-id": "ghost-user"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"


def test_users_list_requires_admin(tmp_path):
    client, org, owner, member = _client(tmp_path)
    # member is below users:read (admin)
    r = client.get(f"/api/v1/users?org_id={org}", headers={"x-user-id": member})
    assert r.status_code == 403
    # owner passes
    r2 = client.get(f"/api/v1/users?org_id={org}", headers={"x-user-id": owner})
    assert r2.status_code == 200
    assert len(r2.json()["users"]) == 2


def test_users_endpoint_requires_identity_header(tmp_path):
    client, org, owner, member = _client(tmp_path)
    r = client.get(f"/api/v1/users?org_id={org}")
    assert r.status_code == 422  # missing required header
