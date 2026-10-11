"""RBAC + org/user management (architecture §3 orgs/users, §7 elevation).

Roles: owner > admin > member. Authorization is a single table-driven check so
every route gets the same answer (architecture §7, STRIDE "Elevation").

Tenant isolation is enforced here too: a principal may only ever act on its own
org — passing another org as the target is denied regardless of role.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROLE_RANK = {"member": 1, "admin": 2, "owner": 3}
ROLES = tuple(ROLE_RANK)

# permission -> minimum role rank required
PERMISSIONS: dict[str, int] = {
    "alerts:read": ROLE_RANK["member"],
    "alerts:export": ROLE_RANK["admin"],
    "users:read": ROLE_RANK["admin"],
    "users:write": ROLE_RANK["admin"],
    "org:settings": ROLE_RANK["admin"],
    "org:delete": ROLE_RANK["owner"],
    "billing:write": ROLE_RANK["owner"],
}


class AuthError(Exception):
    """Raised when a principal is not allowed to perform an action."""


@dataclass(frozen=True)
class Principal:
    org_id: str
    user_id: str
    role: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    tier       TEXT NOT NULL DEFAULT 'starter',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    email      TEXT UNIQUE NOT NULL,
    role       TEXT NOT NULL DEFAULT 'member',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
"""


class OrgStore:
    """SQLite-backed orgs + users with table-driven RBAC."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ---- orgs ------------------------------------------------------------

    def create_org(self, *, name: str, tier: str = "starter") -> str:
        org_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO orgs (id, name, tier, created_at) VALUES (?,?,?,?)",
                (org_id, name, tier, datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()
        return org_id

    def org(self, org_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
        return dict(row) if row else None

    # ---- users -----------------------------------------------------------

    def add_user(self, *, org_id: str, email: str, role: str = "member") -> str:
        if role not in ROLE_RANK:
            raise ValueError(f"role must be one of {ROLES}")
        if self.org(org_id) is None:
            raise ValueError(f"unknown org {org_id!r}")
        user_id = str(uuid.uuid4())
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO users (id, org_id, email, role, created_at) VALUES (?,?,?,?,?)",
                    (user_id, org_id, email, role, datetime.now(timezone.utc).isoformat()),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"email already registered: {email!r}") from exc
        return user_id

    def role_of(self, org_id: str, user_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT role FROM users WHERE id = ? AND org_id = ?", (user_id, org_id)
            ).fetchone()
        return row["role"] if row else None

    def list_users(self, org_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, org_id, email, role, created_at FROM users WHERE org_id = ?"
                " ORDER BY created_at ASC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- authorization ---------------------------------------------------

    def authorize(self, principal: Principal, permission: str, *, target_org: str | None = None) -> bool:
        """Raise AuthError unless `principal` may perform `permission`.

        Tenant isolation: a principal may only act within its own org.
        """
        if target_org is not None and target_org != principal.org_id:
            raise AuthError("cross-tenant access denied")

        required = PERMISSIONS.get(permission)
        if required is None:
            raise AuthError(f"unknown permission {permission!r}")

        # Re-read the role from the store: the principal's claim is not trusted.
        actual = self.role_of(principal.org_id, principal.user_id)
        if actual is None:
            raise AuthError("principal is not a member of this org")
        if ROLE_RANK[actual] < required:
            raise AuthError(
                f"role {actual!r} may not perform {permission!r} (needs {required})"
            )
        return True

    def close(self) -> None:
        self._conn.close()
