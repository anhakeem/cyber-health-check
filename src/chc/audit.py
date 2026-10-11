"""Append-only audit log (architecture §3 audit_log, §7 Repudiation).

Every administrative / security-relevant action is recorded with actor, action,
target, and a JSON metadata blob. There is deliberately no update or delete
method: the log is append-only, which is what makes it usable as compliance
evidence (SOC 2 / ISO 27001).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id         TEXT PRIMARY KEY,
    org_id     TEXT,
    actor      TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    meta       TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_log(org_id, created_at DESC);
"""


class AuditLog:
    """SQLite-backed append-only audit trail with per-org isolation."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record(
        self,
        *,
        org_id: str | None,
        actor: str | None,
        action: str,
        target: str | None = None,
        meta: dict | None = None,
    ) -> str:
        entry_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log (id, org_id, actor, action, target, meta, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (entry_id, org_id, actor, action, target,
                 json.dumps(meta or {}), datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()
        return entry_id

    def list(self, *, org_id: str, limit: int = 100, offset: int = 0) -> list[dict]:
        limit = max(1, min(limit, 1000))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE org_id = ?"
                " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                (org_id, limit, max(0, offset)),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["meta"] = json.loads(d.get("meta") or "{}")
            except (json.JSONDecodeError, TypeError):
                d["meta"] = {}
            out.append(d)
        return out

    def count(self, *, org_id: str) -> int:
        with self._lock:
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
            )

    def export_jsonl(self, *, org_id: str) -> str:
        """Newline-delimited JSON, oldest first — the standard export shape."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE org_id = ? ORDER BY created_at ASC, rowid ASC",
                (org_id,),
            ).fetchall()
        lines = []
        for r in rows:
            d = dict(r)
            try:
                d["meta"] = json.loads(d.get("meta") or "{}")
            except (json.JSONDecodeError, TypeError):
                d["meta"] = {}
            lines.append(json.dumps(d))
        return "\n".join(lines) + ("\n" if lines else "")

    def close(self) -> None:
        self._conn.close()
