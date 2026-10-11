"""Tests for the audit log, SIEM export, and compliance reporting (architecture §3, §8)."""
from __future__ import annotations

import json

import pytest

from chc.audit import AuditLog
from chc.integrations.siem import SplunkHecExporter, SyslogExporter, to_cef
from chc.reports import compliance_report


# ---- AuditLog --------------------------------------------------------------

def test_audit_append_and_list(tmp_path):
    log = AuditLog(db_path=str(tmp_path / "au.db"))
    log.record(org_id="o1", actor="u1", action="alert.view", target="https://x", meta={"k": "v"})
    rows = log.list(org_id="o1")
    assert len(rows) == 1
    assert rows[0]["action"] == "alert.view"
    assert rows[0]["actor"] == "u1"


def test_audit_is_append_only(tmp_path):
    """No update/delete API: a second record adds a row, never replaces."""
    log = AuditLog(db_path=str(tmp_path / "au.db"))
    log.record(org_id="o1", actor="u1", action="a", target="t", meta={})
    log.record(org_id="o1", actor="u1", action="a", target="t", meta={})
    assert len(log.list(org_id="o1")) == 2


def test_audit_tenant_isolation(tmp_path):
    log = AuditLog(db_path=str(tmp_path / "au.db"))
    log.record(org_id="o1", actor="u1", action="a", target="t", meta={})
    log.record(org_id="o2", actor="u2", action="b", target="t", meta={})
    assert len(log.list(org_id="o1")) == 1
    assert log.list(org_id="o1")[0]["action"] == "a"


def test_audit_export_jsonl(tmp_path):
    log = AuditLog(db_path=str(tmp_path / "au.db"))
    log.record(org_id="o1", actor="u1", action="a", target="t", meta={"n": 1})
    out = log.export_jsonl(org_id="o1")
    lines = [json.loads(line) for line in out.strip().split("\n")]
    assert lines[0]["action"] == "a"
    assert lines[0]["meta"] == {"n": 1}


# ---- CEF / SIEM ------------------------------------------------------------

def test_to_cef_shape():
    event = {
        "action": "alert.detected", "actor": "u1", "indicator": "https://bad.example",
        "verdict": "malicious", "severity": "high",
    }
    cef = to_cef(event)
    assert cef.startswith("CEF:0|CyberHealthCheck|")
    assert "https://bad.example" in cef
    # CEF encodes severity numerically (high -> 8), not as a word.
    assert "|8|" in cef
    assert "cs1=malicious" in cef


def test_splunk_export_posts_events():
    sent = []

    def fake_post(url, json=None, headers=None, timeout=None):
        sent.append((url, json, headers))

        class R:
            status_code = 200
            def raise_for_status(self): pass
        return R()

    exp = SplunkHecExporter(hec_url="https://splunk.example:8088", token="tok", post=fake_post)
    n = exp.export([{"action": "alert.detected", "severity": "high", "indicator": "https://x"}])
    assert n == 1
    assert sent[0][1]["event"]["action"] == "alert.detected"
    assert sent[0][2]["Authorization"] == "Splunk tok"


def test_syslog_export_formats_lines():
    lines = []
    exp = SyslogExporter(send=lambda line: lines.append(line))
    n = exp.export([{"action": "alert.detected", "severity": "high", "indicator": "https://x"}])
    assert n == 1
    assert "CEF:0|CyberHealthCheck" in lines[0]


# ---- Compliance report -----------------------------------------------------

def test_compliance_report_counts_by_severity(tmp_path):
    from chc.alerts import AlertStore
    store = AlertStore(db_path=str(tmp_path / "a.db"))
    store.add(org_id="o1", user_id="u1", indicator="https://a", verdict="malicious",
              category="phishing", severity="critical")
    store.add(org_id="o1", user_id="u1", indicator="https://b", verdict="suspicious",
              category=None, severity="low")
    log = AuditLog(db_path=str(tmp_path / "au.db"))
    log.record(org_id="o1", actor="u1", action="alert.view", target="https://a", meta={})

    report = compliance_report(org_id="o1", alert_store=store, audit_log=log)
    assert report["org_id"] == "o1"
    assert report["alerts"]["total"] == 2
    assert report["alerts"]["by_severity"]["critical"] == 1
    assert report["audit_events"] == 1
    assert "generated_at" in report
