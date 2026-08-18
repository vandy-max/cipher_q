"""
Tests for `/api/users` — admin-only user listing and role management
(requirement item 8, "User & Role Management" Admin Dashboard section).

Same HTTP-level style as `tests/test_rbac_and_ownership.py`: exercises
the real FastAPI app against an in-memory mongomock database, since
these are RBAC gates enforced by FastAPI dependencies.
"""
from __future__ import annotations

import mongomock
import pytest
from fastapi.testclient import TestClient

import database.session as dbsession


@pytest.fixture()
def db():
    test_client = mongomock.MongoClient()
    test_db = test_client["cipherq_users_test"]
    dbsession.client = test_client
    dbsession.db = test_db
    yield test_db


@pytest.fixture()
def client(db):
    from api.main import app

    return TestClient(app)


def _register(client: TestClient, username: str, role: str | None = None) -> dict:
    r = client.post(
        "/api/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": "Sup3rSecret!"},
    )
    assert r.status_code == 201, r.text
    user_id = r.json()["user_id"]
    if role is not None:
        dbsession.db["users"].update_one({"_id": user_id}, {"$set": {"role": role}})
    login = client.post("/api/auth/login", json={"username": username, "password": "Sup3rSecret!"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['token']}"}, user_id


class TestUserListingRBAC:
    def test_standard_user_cannot_list_users(self, client):
        headers, _ = _register(client, "u_employee")
        resp = client.get("/api/users", headers=headers)
        assert resp.status_code == 403

    def test_user_level_2_cannot_list_users(self, client):
        headers, _ = _register(client, "u_manager", role="USER_LEVEL_2")
        resp = client.get("/api/users", headers=headers)
        assert resp.status_code == 403

    def test_admin_can_list_users(self, client):
        _register(client, "u_alice")
        admin_headers, _ = _register(client, "u_admin", role="ADMIN")
        resp = client.get("/api/users", headers=admin_headers)
        assert resp.status_code == 200
        usernames = {u["username"] for u in resp.json()}
        assert {"u_alice", "u_admin"} <= usernames

    def test_no_auth_is_401_not_500(self, client):
        resp = client.get("/api/users")
        assert resp.status_code == 401


class TestRoleManagementRBAC:
    def test_standard_user_cannot_change_own_role(self, client):
        headers, user_id = _register(client, "r_employee")
        resp = client.put(f"/api/users/{user_id}/role", json={"role": "ADMIN"}, headers=headers)
        assert resp.status_code == 403

    def test_admin_can_promote_a_user(self, client):
        _headers, user_id = _register(client, "r_target")
        admin_headers, _ = _register(client, "r_admin", role="ADMIN")

        resp = client.put(f"/api/users/{user_id}/role", json={"role": "USER_LEVEL_2"}, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["role"] == "USER_LEVEL_2"

        listed = client.get("/api/users", headers=admin_headers).json()
        target = next(u for u in listed if u["id"] == user_id)
        assert target["role"] == "USER_LEVEL_2"

    def test_unknown_role_is_rejected(self, client):
        _headers, user_id = _register(client, "r_target2")
        admin_headers, _ = _register(client, "r_admin2", role="ADMIN")

        resp = client.put(f"/api/users/{user_id}/role", json={"role": "SUPREME_LEADER"}, headers=admin_headers)
        assert resp.status_code == 400

    def test_role_change_is_audited(self, client):
        _headers, user_id = _register(client, "r_target3")
        admin_headers, _ = _register(client, "r_admin3", role="ADMIN")

        resp = client.put(f"/api/users/{user_id}/role", json={"role": "USER_LEVEL_2"}, headers=admin_headers)
        assert resp.status_code == 200

        logs = client.get("/api/audit/logs", headers=admin_headers).json()
        assert any(entry["action"] == "ROLE_CHANGED" for entry in logs)

    def test_role_change_for_missing_user_is_404(self, client):
        admin_headers, _ = _register(client, "r_admin4", role="ADMIN")
        resp = client.put("/api/users/999999/role", json={"role": "ADMIN"}, headers=admin_headers)
        assert resp.status_code == 404


class TestIntentListingRoleScoping:
    """GET /api/intent — backs the Admin Dashboard's approval queue.
    A regular user only sees their own intents; a manager/admin sees
    everyone's, which is what makes discovering an unapproved intent
    to review possible at all."""

    def _cid(self, device_id: str, session_id: str) -> dict:
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        return {
            "sender": "alice",
            "receiver": "vault",
            "purpose": "listing-test",
            "resource": "res/1",
            "operation": "encrypt",
            "device_id": device_id,
            "session_id": session_id,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(hours=1)).isoformat(),
        }

    def test_user_sees_only_own_intents(self, client):
        headers_a, _ = _register(client, "list_a")
        headers_b, _ = _register(client, "list_b")

        client.post("/api/intent", json={"cid": self._cid("d1", "s1"), "reason": "t"}, headers=headers_a)
        client.post("/api/intent", json={"cid": self._cid("d2", "s2"), "reason": "t"}, headers=headers_b)

        seen_by_a = client.get("/api/intent", headers=headers_a).json()
        assert all(row["created_by"] != 0 for row in seen_by_a)
        assert len(seen_by_a) == 1

    def test_manager_sees_all_intents(self, client):
        headers_a, _ = _register(client, "list_c")
        headers_b, _ = _register(client, "list_d")
        manager_headers, _ = _register(client, "list_manager", role="USER_LEVEL_2")

        client.post("/api/intent", json={"cid": self._cid("d3", "s3"), "reason": "t"}, headers=headers_a)
        client.post("/api/intent", json={"cid": self._cid("d4", "s4"), "reason": "t"}, headers=headers_b)

        seen_by_manager = client.get("/api/intent", headers=manager_headers).json()
        assert len(seen_by_manager) >= 2

    def test_lifecycle_state_filter(self, client):
        headers_a, _ = _register(client, "list_e")
        manager_headers, _ = _register(client, "list_manager2", role="USER_LEVEL_2")

        created = client.post(
            "/api/intent", json={"cid": self._cid("d5", "s5"), "reason": "t"}, headers=headers_a
        ).json()

        drafts = client.get("/api/intent?lifecycle_state=draft", headers=manager_headers).json()
        assert any(row["intent_id"] == created["intent_id"] for row in drafts)

        approved = client.get("/api/intent?lifecycle_state=approved", headers=manager_headers).json()
        assert all(row["intent_id"] != created["intent_id"] for row in approved)
