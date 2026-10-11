"""Tests for RBAC + org/user management (architecture §3 orgs/users, §7 elevation)."""
from __future__ import annotations

import pytest

from chc.auth import AuthError, OrgStore, Principal, ROLE_RANK


# ---- OrgStore: orgs + users ------------------------------------------------

def test_create_org_and_owner(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    org_id = store.create_org(name="Acme")
    user_id = store.add_user(org_id=org_id, email="boss@acme.test", role="owner")
    assert store.role_of(org_id, user_id) == "owner"


def test_invalid_role_rejected(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    org_id = store.create_org(name="Acme")
    with pytest.raises(ValueError):
        store.add_user(org_id=org_id, email="x@acme.test", role="superuser")


def test_duplicate_email_rejected(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    o1 = store.create_org(name="A")
    o2 = store.create_org(name="B")
    store.add_user(org_id=o1, email="dup@x.test", role="member")
    with pytest.raises(ValueError):
        store.add_user(org_id=o2, email="dup@x.test", role="member")


def test_user_isolation_between_orgs(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    o1 = store.create_org(name="A")
    o2 = store.create_org(name="B")
    u1 = store.add_user(org_id=o1, email="a@x.test", role="member")
    # A user from org A must not resolve inside org B.
    assert store.role_of(o2, u1) is None


def test_list_users_scoped_to_org(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    o1 = store.create_org(name="A")
    o2 = store.create_org(name="B")
    store.add_user(org_id=o1, email="a@x.test", role="member")
    store.add_user(org_id=o2, email="b@x.test", role="member")
    assert len(store.list_users(o1)) == 1
    assert store.list_users(o1)[0]["email"] == "a@x.test"


# ---- RBAC authorization ----------------------------------------------------

def test_role_rank_ordering():
    assert ROLE_RANK["owner"] > ROLE_RANK["admin"] > ROLE_RANK["member"]


def test_owner_can_manage_users(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    org = store.create_org(name="A")
    owner = store.add_user(org_id=org, email="o@x.test", role="owner")
    p = Principal(org_id=org, user_id=owner, role="owner")
    assert store.authorize(p, "users:write") is True


def test_member_cannot_manage_users(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    org = store.create_org(name="A")
    member = store.add_user(org_id=org, email="m@x.test", role="member")
    p = Principal(org_id=org, user_id=member, role="member")
    with pytest.raises(AuthError):
        store.authorize(p, "users:write")


def test_member_can_read_alerts(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    org = store.create_org(name="A")
    member = store.add_user(org_id=org, email="m@x.test", role="member")
    p = Principal(org_id=org, user_id=member, role="member")
    assert store.authorize(p, "alerts:read") is True


def test_admin_cannot_delete_org(tmp_path):
    """Only owners may delete the org."""
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    org = store.create_org(name="A")
    admin = store.add_user(org_id=org, email="a@x.test", role="admin")
    p = Principal(org_id=org, user_id=admin, role="admin")
    with pytest.raises(AuthError):
        store.authorize(p, "org:delete")


def test_cross_tenant_principal_denied(tmp_path):
    """A principal from org A must not be authorized against org B."""
    store = OrgStore(db_path=str(tmp_path / "o.db"))
    o1 = store.create_org(name="A")
    o2 = store.create_org(name="B")
    owner_a = store.add_user(org_id=o1, email="o@a.test", role="owner")
    p = Principal(org_id=o1, user_id=owner_a, role="owner")
    with pytest.raises(AuthError):
        store.authorize(p, "alerts:read", target_org=o2)
