"""Tests for the compliance + audit-export endpoints (RBAC-gated)."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from chc.alerts import AlertStore
from chc.api.main import create_app
from chc.audit import AuditLog
from chc.auth import OrgStore
from chc.reputation import MergedVerdict


class FakeReputation:
    def check(self, indicator, kind=None):
        return MergedVerdict("malicious", "phishing", 0.9, ["phishtank"])


def _client(tmp_path):
    alerts = AlertStore(db_path=str(tmp_path / "a.db"))
    orgs = OrgStore(db_path=str(tmp_path / "o.db"))
    audit = AuditLog(db_path=str(tmp_path / "au.db"))
    org = orgs.create_org(name="Acme")
    owner = orgs.add_user(org_id=org, email="o@acme.test", role="owner")
    member = orgs.add_user(org_id=org, email="m@acme.test", role="member")
    alerts.add(org_id=org, user_id=member, indicator="https://bad.example",
               verdict="malicious", category="phishing", severity="critical")
    app = create_app(reputation_factory=lambda: FakeReputation(),
                     alert_store_factory=lambda: alerts,
                     org_store_factory=lambda: orgs,
                     audit_log_factory=lambda: audit)
    return TestClient(app), org, owner, member, audit


def test_compliance_report_requires_admin(tmp_path):
    client, org, owner, member, audit = _client(tmp_path)
    r = client.get(f"/api/v1/compliance/report?org_id={org}", headers={"x-user-id": member})
    assert r.status_code == 403


def test_compliance_report_ok_for_owner(tmp_path):
    client, org, owner, member, audit = _client(tmp_path)
    r = client.get(f"/api/v1/compliance/report?org_id={org}", headers={"x-user-id": owner})
    assert r.status_code == 200
    body = r.json()
    assert body["org_id"] == org
    assert body["alerts"]["total"] == 1
    assert body["alerts"]["by_severity"]["critical"] == 1
    assert body["controls"]["rbac_enforced"] is True
    # generating a report is itself audited
    assert audit.count(org_id=org) == 1


def test_audit_export_jsonl(tmp_path):
    client, org, owner, member, audit = _client(tmp_path)
    audit.record(org_id=org, actor=owner, action="alert.view", target="https://x", meta={"a": 1})
    r = client.get(f"/api/v1/audit/export?org_id={org}", headers={"x-user-id": owner})
    assert r.status_code == 200
    lines = [json.loads(l) for l in r.text.strip().split("\n")]
    assert lines[0]["action"] == "alert.view"


def test_audit_export_forbidden_for_member(tmp_path):
    client, org, owner, member, audit = _client(tmp_path)
    r = client.get(f"/api/v1/audit/export?org_id={org}", headers={"x-user-id": member})
    assert r.status_code == 403
