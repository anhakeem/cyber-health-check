"""Alert store — persists reputation alerts per org (architecture §3).

Backed by SQLite. Tenant isolation is enforced on every read: a query always
filters by org_id, so one org can never see another's alerts.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

_SEVERITIES = {"low", "medium", "high", "critical"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    user_id    TEXT,
    indicator  TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    category   TEXT,
    url        TEXT,
    severity   TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_org_time ON alerts(org_id, created_at DESC);
"""


class AlertStore:
    """SQLite-backed alert store with per-org isolation."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + a lock: FastAPI's threadpool shares the conn.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def add(
        self,
        *,
        org_id: str,
        user_id: str | None,
        indicator: str,
        verdict: str,
        category: str | None,
        severity: str,
        url: str | None = None,
    ) -> str:
        if severity not in _SEVERITIES:
            raise ValueError(f"severity must be one of {_SEVERITIES}")
        alert_id = str(uuid.uuid4())
        created = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO alerts (id, org_id, user_id, indicator, verdict, category, url, severity, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (alert_id, org_id, user_id, indicator, verdict, category, url, severity, created),
            )
            self._conn.commit()
        return alert_id

    def list(
        self,
        *,
        org_id: str,
        severity: str | None = None,
        since: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        sql = "SELECT * FROM alerts WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if since:
            sql += " AND created_at >= ?"
            params.append(since)
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count(self, *, org_id: str, severity: str | None = None) -> int:
        sql = "SELECT COUNT(*) FROM alerts WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        with self._lock:
            return int(self._conn.execute(sql, params).fetchone()[0])

    def close(self) -> None:
        self._conn.close()
