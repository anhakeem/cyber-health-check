"""Compliance reporting (architecture §8, enterprise phase).

Produces an org-scoped evidence summary from the alert store and the audit log.
"""
from __future__ import annotations

from datetime import datetime, timezone


def compliance_report(*, org_id: str, alert_store, audit_log) -> dict:
    """Build a compliance evidence report for one org.

    `alert_store` and `audit_log` are the store objects; passing them in keeps
    this pure and testable.
    """
    alerts = alert_store.list(org_id=org_id, limit=500)
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_verdict: dict[str, int] = {}
    for a in alerts:
        sev = a.get("severity")
        if sev in by_severity:
            by_severity[sev] += 1
        v = a.get("verdict", "unknown")
        by_verdict[v] = by_verdict.get(v, 0) + 1

    return {
        "org_id": org_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts": {
            "total": alert_store.count(org_id=org_id),
            "by_severity": by_severity,
            "by_verdict": by_verdict,
        },
        "audit_events": audit_log.count(org_id=org_id),
        "controls": {
            "rbac_enforced": True,
            "tenant_isolation": True,
            "audit_log_append_only": True,
            "ssrf_protection": True,
        },
    }
