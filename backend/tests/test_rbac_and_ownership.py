"""
RBAC + resource-ownership + production-hardening security tests.

Unlike the rest of tests/ (which call services/routers directly),
these exercise the real, live FastAPI app over HTTP — with real
request/response validation and the real dependency-injection chain —
against an in-memory mongomock database. That's the layer these
security checks actually live in (403s raised by FastAPI dependencies,
ownership comparisons made inside route handlers against the JWT
identity), so it's the layer that has to be tested directly; calling
service functions in isolation would not exercise the RBAC/ownership
gates at all.

Run as part of the normal suite: `pytest` (or directly:
`pytest tests/test_rbac_and_ownership.py -v`).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import mongomock
import pytest
from fastapi.testclient import TestClient

import database.session as dbsession


@pytest.fixture()
def db():
    """A fresh in-memory MongoDB for every test — no state leaks
    between tests, and no real `mongod` is required."""
    test_client = mongomock.MongoClient()
    test_db = test_client["cipherq_rbac_test"]
    dbsession.client = test_client
    dbsession.db = test_db
    yield test_db


@pytest.fixture()
def client(db):
    # Imported lazily, after `db` has patched database.session, so
    # anything evaluated at import time (there's nothing DB-dependent
    # at api.main import time) is safe either way; kept lazy for
    # clarity and to avoid surprises if that ever changes.
    from api.main import app

    return TestClient(app)


def _register(client: TestClient, username: str, role: str | None = None) -> dict:
    """Register a normal (USER_LEVEL_1) user, then, exactly like an
    out-of-band administrator would, optionally elevate its role
    directly in the store — there is no public API that lets a client
    grant itself an elevated role. Returns bearer-auth headers."""
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


def _now_iso(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat()


def _cid(device_id: str, session_id: str, **overrides) -> dict:
    payload = {
        "sender": "alice",
        "receiver": "vault",
        "purpose": "ownership-test",
        "resource": "res/1",
        "operation": "encrypt",
        "device_id": device_id,
        "session_id": session_id,
        "valid_from": _now_iso(-1),
        "valid_until": _now_iso(60),
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------
# 1. RBAC — policy management
# ---------------------------------------------------------------------

class TestPolicyRBAC:
    def test_standard_user_cannot_create_policy(self, client):
        headers, _ = _register(client, "policy_employee", role="USER_LEVEL_1")
        resp = client.post(
            "/api/policies",
            json={"name": "p", "rule_type": "max_risk_score", "config": {}, "active": True},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_standard_user_cannot_update_policy(self, client):
        admin_headers, _ = _register(client, "policy_admin1", role="ADMIN")
        created = client.post(
            "/api/policies",
            json={"name": "p", "rule_type": "max_risk_score", "config": {}, "active": True},
            headers=admin_headers,
        ).json()

        employee_headers, _ = _register(client, "policy_employee2", role="USER_LEVEL_1")
        resp = client.put(
            f"/api/policies/{created['id']}",
            json={"name": "p2", "rule_type": "max_risk_score", "config": {}, "active": True},
            headers=employee_headers,
        )
        assert resp.status_code == 403

    def test_standard_user_cannot_delete_policy(self, client):
        admin_headers, _ = _register(client, "policy_admin2", role="ADMIN")
        created = client.post(
            "/api/policies",
            json={"name": "p", "rule_type": "max_risk_score", "config": {}, "active": True},
            headers=admin_headers,
        ).json()

        employee_headers, _ = _register(client, "policy_employee3", role="USER_LEVEL_1")
        resp = client.delete(f"/api/policies/{created['id']}", headers=employee_headers)
        assert resp.status_code == 403

    def test_user_level_2_cannot_write_policy(self, client):
        # USER_LEVEL_2 is the single elevated non-admin tier (it folds
        # together what used to be the separate UNIT_MANAGER,
        # DATABASE_ADMIN, and AUDITOR roles) — none of those roles
        # could write policy before, and USER_LEVEL_2 can't either.
        headers, _ = _register(client, "policy_role_user_level_2", role="USER_LEVEL_2")
        resp = client.post(
            "/api/policies",
            json={"name": "p", "rule_type": "max_risk_score", "config": {}, "active": True},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_admin_can_manage_policy_full_lifecycle(self, client):
        headers, _ = _register(client, "policy_analyst", role="ADMIN")
        created = client.post(
            "/api/policies",
            json={"name": "p", "rule_type": "max_risk_score", "config": {"threshold": 0.5}, "active": True},
            headers=headers,
        )
        assert created.status_code == 201
        policy_id = created.json()["id"]

        updated = client.put(
            f"/api/policies/{policy_id}",
            json={"name": "p2", "rule_type": "max_risk_score", "config": {"threshold": 0.6}, "active": True},
            headers=headers,
        )
        assert updated.status_code == 200

        deleted = client.delete(f"/api/policies/{policy_id}", headers=headers)
        assert deleted.status_code == 204

    def test_admin_can_create_policy(self, client):
        headers, _ = _register(client, "policy_sysadmin", role="ADMIN")
        created = client.post(
            "/api/policies",
            json={"name": "p", "rule_type": "max_risk_score", "config": {}, "active": True},
            headers=headers,
        )
        assert created.status_code == 201

    def test_policy_read_remains_available_to_any_authenticated_user(self, client):
        headers, _ = _register(client, "policy_reader", role="USER_LEVEL_1")
        resp = client.get("/api/policies", headers=headers)
        assert resp.status_code == 200

    def test_no_auth_at_all_is_401_not_500(self, client):
        resp = client.post(
            "/api/policies",
            json={"name": "p", "rule_type": "max_risk_score", "config": {}, "active": True},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------
# Shared helper: get a user into an APPROVED-intent + live-session state
# ---------------------------------------------------------------------

def _establish_session_and_intent(client, headers, device_id, session_id, *, approve=True, approver_headers=None):
    r = client.post(
        f"/api/authorization/sessions/{session_id}/refresh",
        json={"device_id": device_id, "ttl_minutes": 60},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    cid = _cid(device_id, session_id)
    created = client.post("/api/intent", json={"cid": cid, "reason": "test"}, headers=headers)
    assert created.status_code == 201, created.text
    intent_id = created.json()["intent_id"]
    if approve:
        # Separation of duties: the intent's own owner (`headers`) can
        # never approve their own intent (see
        # api/routers/intent.py::transition_intent) — a distinct,
        # sufficiently-privileged approver is required. Callers that
        # care about who approves pass `approver_headers` explicitly;
        # everyone else gets an auto-registered admin, scoped to this
        # device/session so concurrent calls in the same test never
        # collide on username.
        if approver_headers is None:
            approver_headers, _ = _register(client, f"auto-approver-{device_id}-{session_id}", role="ADMIN")
        tr = client.post(
            f"/api/intent/{intent_id}/transition",
            json={"target_state": "approved", "reason": "test"},
            headers=approver_headers,
        )
        assert tr.status_code == 200, tr.text
    return intent_id, cid


# ---------------------------------------------------------------------
# 2. Device ownership
# ---------------------------------------------------------------------

class TestDeviceOwnership:
    def test_user_a_can_access_own_device(self, client):
        headers_a, _ = _register(client, "dev_owner_a")
        _establish_session_and_intent(client, headers_a, "dev-a-1", "sess-a-1", approve=False)
        resp = client.get("/api/authorization/devices/dev-a-1", headers=headers_a)
        assert resp.status_code == 200

    def test_user_b_cannot_access_user_a_device(self, client):
        headers_a, _ = _register(client, "dev_owner_a2")
        headers_b, _ = _register(client, "dev_owner_b2")
        _establish_session_and_intent(client, headers_a, "dev-a-2", "sess-a-2", approve=False)

        resp = client.get("/api/authorization/devices/dev-a-2", headers=headers_b)
        assert resp.status_code == 403

    def test_system_admin_can_administer_user_a_device(self, client):
        headers_a, _ = _register(client, "dev_owner_a3")
        admin_headers, _ = _register(client, "dev_admin3", role="ADMIN")
        _establish_session_and_intent(client, headers_a, "dev-a-3", "sess-a-3", approve=False)

        resp = client.get("/api/authorization/devices/dev-a-3", headers=admin_headers)
        assert resp.status_code == 200
        revoke = client.post("/api/authorization/devices/dev-a-3/revoke", headers=admin_headers)
        assert revoke.status_code == 200
        assert revoke.json()["revoked"] is True

    def test_standard_user_cannot_revoke_arbitrary_device(self, client):
        headers_a, _ = _register(client, "dev_owner_a4")
        headers_b, _ = _register(client, "dev_owner_b4", role="USER_LEVEL_1")
        _establish_session_and_intent(client, headers_a, "dev-a-4", "sess-a-4", approve=False)

        resp = client.post("/api/authorization/devices/dev-a-4/revoke", headers=headers_b)
        assert resp.status_code == 403

    def test_owner_cannot_self_revoke_device_without_admin_role(self, client):
        # Revoke/unrevoke is an admin-only operation across the board
        # (see api/routers/authorization.py) — even the device's own
        # owner cannot revoke it without ADMIN.
        headers_a, _ = _register(client, "dev_owner_a5", role="USER_LEVEL_1")
        _establish_session_and_intent(client, headers_a, "dev-a-5", "sess-a-5", approve=False)

        resp = client.post("/api/authorization/devices/dev-a-5/revoke", headers=headers_a)
        assert resp.status_code == 403


# ---------------------------------------------------------------------
# 3. Session ownership
# ---------------------------------------------------------------------

class TestSessionOwnership:
    def test_user_a_can_access_own_session(self, client):
        headers_a, _ = _register(client, "sess_owner_a")
        _establish_session_and_intent(client, headers_a, "dev-sa-1", "sess-sa-1", approve=False)
        resp = client.get("/api/authorization/sessions/sess-sa-1", headers=headers_a)
        assert resp.status_code == 200

    def test_user_b_cannot_access_user_a_session(self, client):
        headers_a, _ = _register(client, "sess_owner_a2")
        headers_b, _ = _register(client, "sess_owner_b2")
        _establish_session_and_intent(client, headers_a, "dev-sa-2", "sess-sa-2", approve=False)

        resp = client.get("/api/authorization/sessions/sess-sa-2", headers=headers_b)
        assert resp.status_code == 403

    def test_user_b_cannot_refresh_user_a_session(self, client):
        headers_a, _ = _register(client, "sess_owner_a3")
        headers_b, _ = _register(client, "sess_owner_b3")
        _establish_session_and_intent(client, headers_a, "dev-sa-3", "sess-sa-3", approve=False)

        resp = client.post(
            "/api/authorization/sessions/sess-sa-3/refresh",
            json={"device_id": "dev-sa-3", "ttl_minutes": 30},
            headers=headers_b,
        )
        assert resp.status_code == 403

    def test_system_admin_can_administer_user_a_session(self, client):
        headers_a, _ = _register(client, "sess_owner_a4")
        admin_headers, _ = _register(client, "sess_admin4", role="ADMIN")
        _establish_session_and_intent(client, headers_a, "dev-sa-4", "sess-sa-4", approve=False)

        resp = client.get("/api/authorization/sessions/sess-sa-4", headers=admin_headers)
        assert resp.status_code == 200
        revoke = client.post("/api/authorization/sessions/sess-sa-4/revoke", headers=admin_headers)
        assert revoke.status_code == 200

    def test_standard_user_cannot_revoke_another_users_session(self, client):
        headers_a, _ = _register(client, "sess_owner_a5")
        headers_b, _ = _register(client, "sess_owner_b5", role="USER_LEVEL_1")
        _establish_session_and_intent(client, headers_a, "dev-sa-5", "sess-sa-5", approve=False)

        resp = client.post("/api/authorization/sessions/sess-sa-5/revoke", headers=headers_b)
        assert resp.status_code == 403

    def test_unknown_session_id_is_404_not_500(self, client):
        headers_a, _ = _register(client, "sess_owner_a6")
        resp = client.get("/api/authorization/sessions/does-not-exist", headers=headers_a)
        assert resp.status_code == 404

    def test_user_b_cannot_establish_new_session_against_user_a_device(self, client):
        headers_a, _ = _register(client, "sess_owner_a7")
        headers_b, _ = _register(client, "sess_owner_b7")
        # A establishes a device via their own session first.
        _establish_session_and_intent(client, headers_a, "dev-sa-7", "sess-sa-7a", approve=False)

        # B tries to bind a brand-new session to that same device_id.
        resp = client.post(
            "/api/authorization/sessions/sess-sa-7b/refresh",
            json={"device_id": "dev-sa-7", "ttl_minutes": 30},
            headers=headers_b,
        )
        assert resp.status_code == 403

    def test_new_user_can_establish_initial_session_for_unowned_device(self, client):
        headers_a, _ = _register(client, "sess_owner_a7_new")
        resp = client.post(
            "/api/authorization/sessions/initial-bootstrap-session/refresh",
            json={"device_id": "bootstrap-device-1", "ttl_minutes": 30},
            headers=headers_a,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["session_id"] == "initial-bootstrap-session"
        assert resp.json()["device_id"] == "bootstrap-device-1"

    def test_admin_can_establish_session_against_another_users_device(self, client):
        headers_a, _ = _register(client, "sess_owner_a8")
        admin_headers, _ = _register(client, "sess_admin8", role="ADMIN")
        _establish_session_and_intent(client, headers_a, "dev-sa-8", "sess-sa-8a", approve=False)

        resp = client.post(
            "/api/authorization/sessions/sess-sa-8b/refresh",
            json={"device_id": "dev-sa-8", "ttl_minutes": 30},
            headers=admin_headers,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------
# 4. Intent ownership
# ---------------------------------------------------------------------

class TestIntentOwnership:
    def test_user_a_can_use_own_intent(self, client):
        headers_a, _ = _register(client, "intent_owner_a")
        intent_id, cid = _establish_session_and_intent(client, headers_a, "dev-ia-1", "sess-ia-1")
        resp = client.post(
            "/api/authorization/state",
            json={"cid": cid, "intent_id": intent_id},
            headers=headers_a,
        )
        assert resp.status_code == 200

    def test_user_b_cannot_use_user_a_intent_for_validation(self, client):
        headers_a, _ = _register(client, "intent_owner_a2")
        headers_b, _ = _register(client, "intent_owner_b2")
        intent_id, cid = _establish_session_and_intent(client, headers_a, "dev-ia-2", "sess-ia-2", approve=False)

        resp = client.post(
            "/api/intent/validate", json={"cid": cid, "intent_id": intent_id}, headers=headers_b
        )
        assert resp.status_code == 403

    def test_user_b_cannot_transition_user_a_intent(self, client):
        headers_a, _ = _register(client, "intent_owner_a3")
        headers_b, _ = _register(client, "intent_owner_b3")
        intent_id, _ = _establish_session_and_intent(client, headers_a, "dev-ia-3", "sess-ia-3", approve=False)

        resp = client.post(
            f"/api/intent/{intent_id}/transition",
            json={"target_state": "approved", "reason": "steal it"},
            headers=headers_b,
        )
        assert resp.status_code == 403

    def test_user_b_cannot_encrypt_under_user_a_intent(self, client):
        headers_a, _ = _register(client, "intent_owner_a4")
        headers_b, _ = _register(client, "intent_owner_b4")
        intent_id, cid = _establish_session_and_intent(client, headers_a, "dev-ia-4", "sess-ia-4")

        client.post("/api/face/enroll", json={"descriptor": [0.1] * 128}, headers=headers_b)
        resp = client.post(
            "/api/encrypt",
            json={
                "intent_id": intent_id,
                "cid": cid,
                "plaintext_base64": "aGVsbG8=",
                "quantum_key_hex": "00" * 32,
                "face_descriptor": [0.1] * 128,
            },
            headers=headers_b,
        )
        assert resp.status_code == 403

    def test_user_b_cannot_inspect_user_a_authorization_state(self, client):
        headers_a, _ = _register(client, "intent_owner_a5")
        headers_b, _ = _register(client, "intent_owner_b5")
        intent_id, cid = _establish_session_and_intent(client, headers_a, "dev-ia-5", "sess-ia-5", approve=False)

        resp = client.post(
            "/api/authorization/state",
            json={"cid": cid, "intent_id": intent_id},
            headers=headers_b,
        )
        assert resp.status_code == 403

    def test_admin_can_transition_user_a_intent(self, client):
        headers_a, _ = _register(client, "intent_owner_a6")
        admin_headers, _ = _register(client, "intent_admin6", role="ADMIN")
        intent_id, _ = _establish_session_and_intent(client, headers_a, "dev-ia-6", "sess-ia-6", approve=False)

        resp = client.post(
            f"/api/intent/{intent_id}/transition",
            json={"target_state": "approved", "reason": "admin approval"},
            headers=admin_headers,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------
# 5. Encryption-record ownership
# ---------------------------------------------------------------------

class TestEncryptionRecordOwnership:
    def _encrypt_as(self, client, headers, device_id, session_id):
        client.post("/api/face/enroll", json={"descriptor": [0.2] * 128}, headers=headers)
        intent_id, cid = _establish_session_and_intent(client, headers, device_id, session_id)
        resp = client.post(
            "/api/encrypt",
            json={
                "intent_id": intent_id,
                "cid": cid,
                "plaintext_base64": "c2VjcmV0",
                "quantum_key_hex": "11" * 32,
                "face_descriptor": [0.2] * 128,
            },
            headers=headers,
        )
        assert resp.status_code == 201, resp.text
        return resp.json()["record_id"], cid

    def test_user_a_can_decrypt_own_record(self, client):
        headers_a, _ = _register(client, "rec_owner_a")
        record_id, cid = self._encrypt_as(client, headers_a, "dev-ra-1", "sess-ra-1")

        resp = client.post(
            "/api/decrypt",
            json={
                "record_id": record_id,
                "cid": cid,
                "quantum_key_hex": "11" * 32,
                "face_descriptor": [0.2] * 128,
            },
            headers=headers_a,
        )
        assert resp.status_code == 200

    def test_user_b_cannot_decrypt_user_a_record(self, client):
        headers_a, _ = _register(client, "rec_owner_a2")
        headers_b, _ = _register(client, "rec_owner_b2")
        record_id, cid = self._encrypt_as(client, headers_a, "dev-ra-2", "sess-ra-2")

        client.post("/api/face/enroll", json={"descriptor": [0.2] * 128}, headers=headers_b)
        resp = client.post(
            "/api/decrypt",
            json={
                "record_id": record_id,
                "cid": cid,
                "quantum_key_hex": "11" * 32,
                "face_descriptor": [0.2] * 128,
            },
            headers=headers_b,
        )
        assert resp.status_code == 403

    def test_unknown_record_id_is_404_not_500(self, client):
        headers_a, _ = _register(client, "rec_owner_a3")
        resp = client.post(
            "/api/decrypt",
            json={
                "record_id": 999999,
                "cid": _cid("dev-x", "sess-x"),
                "quantum_key_hex": "11" * 32,
                "face_descriptor": [0.2] * 128,
            },
            headers=headers_a,
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------
# 6. Monitoring ownership
# ---------------------------------------------------------------------

class TestMonitoringOwnership:
    def _start_monitoring_as(self, client, headers, device_id, session_id):
        client.post(
            f"/api/authorization/sessions/{session_id}/refresh",
            json={"device_id": device_id, "ttl_minutes": 60},
            headers=headers,
        )
        resp = client.post(
            "/api/monitoring/start",
            json={"device_id": device_id, "session_id": session_id, "face_confidence": 0.9},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["monitoring_session_id"]

    def test_user_a_can_heartbeat_own_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a")
        msid = self._start_monitoring_as(client, headers_a, "dev-ma-1", "sess-ma-1")
        resp = client.post(
            "/api/monitoring/heartbeat",
            json={"monitoring_session_id": msid, "face_present": True, "face_match_confidence": 0.9, "liveness": True},
            headers=headers_a,
        )
        assert resp.status_code == 200

    def test_user_b_cannot_heartbeat_user_a_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a2")
        headers_b, _ = _register(client, "mon_owner_b2")
        msid = self._start_monitoring_as(client, headers_a, "dev-ma-2", "sess-ma-2")

        resp = client.post(
            "/api/monitoring/heartbeat",
            json={"monitoring_session_id": msid, "face_present": True, "face_match_confidence": 0.9, "liveness": True},
            headers=headers_b,
        )
        assert resp.status_code == 403

    def test_user_b_cannot_get_status_of_user_a_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a3")
        headers_b, _ = _register(client, "mon_owner_b3")
        msid = self._start_monitoring_as(client, headers_a, "dev-ma-3", "sess-ma-3")

        resp = client.get(f"/api/monitoring/{msid}", headers=headers_b)
        assert resp.status_code == 403

    def test_user_b_cannot_get_events_of_user_a_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a4")
        headers_b, _ = _register(client, "mon_owner_b4")
        msid = self._start_monitoring_as(client, headers_a, "dev-ma-4", "sess-ma-4")

        resp = client.get(f"/api/monitoring/{msid}/events", headers=headers_b)
        assert resp.status_code == 403

    def test_user_a_can_stop_own_monitoring_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a5")
        msid = self._start_monitoring_as(client, headers_a, "dev-ma-5", "sess-ma-5")
        resp = client.post(f"/api/monitoring/{msid}/stop", headers=headers_a)
        assert resp.status_code == 204

    def test_user_b_cannot_stop_user_a_monitoring_session(self, client):
        # This is the endpoint that had NO ownership check at all
        # before this hardening pass — explicitly regression-tested.
        headers_a, _ = _register(client, "mon_owner_a6")
        headers_b, _ = _register(client, "mon_owner_b6")
        msid = self._start_monitoring_as(client, headers_a, "dev-ma-6", "sess-ma-6")

        resp = client.post(f"/api/monitoring/{msid}/stop", headers=headers_b)
        assert resp.status_code == 403

        # And confirm it genuinely wasn't stopped by the rejected call.
        still_running = client.get(f"/api/monitoring/{msid}", headers=headers_a)
        assert still_running.status_code == 200

    def test_unknown_monitoring_session_is_404_not_500(self, client):
        headers_a, _ = _register(client, "mon_owner_a7")
        for path, method in [
            (f"/api/monitoring/does-not-exist", "get"),
            (f"/api/monitoring/does-not-exist/events", "get"),
            (f"/api/monitoring/does-not-exist/stop", "post"),
        ]:
            resp = getattr(client, method)(path, headers=headers_a)
            assert resp.status_code == 404, f"{method.upper()} {path} -> {resp.status_code}"


# ---------------------------------------------------------------------
# 7. Revocation — admin-only, end to end
# ---------------------------------------------------------------------

class TestRevocationAdminOnly:
    def test_unauthorized_user_cannot_revoke_another_users_device(self, client):
        headers_a, _ = _register(client, "revoke_a1")
        headers_b, _ = _register(client, "revoke_b1", role="USER_LEVEL_1")
        _establish_session_and_intent(client, headers_a, "dev-rv-1", "sess-rv-1", approve=False)

        resp = client.post("/api/authorization/devices/dev-rv-1/revoke", headers=headers_b)
        assert resp.status_code == 403

    def test_unauthorized_user_cannot_revoke_another_users_session(self, client):
        headers_a, _ = _register(client, "revoke_a2")
        headers_b, _ = _register(client, "revoke_b2", role="USER_LEVEL_1")
        _establish_session_and_intent(client, headers_a, "dev-rv-2", "sess-rv-2", approve=False)

        resp = client.post("/api/authorization/sessions/sess-rv-2/revoke", headers=headers_b)
        assert resp.status_code == 403

    def test_authorized_administrator_can_revoke_and_unrevoke_device(self, client):
        headers_a, _ = _register(client, "revoke_a3")
        admin_headers, _ = _register(client, "revoke_admin3", role="ADMIN")
        _establish_session_and_intent(client, headers_a, "dev-rv-3", "sess-rv-3", approve=False)

        revoke = client.post("/api/authorization/devices/dev-rv-3/revoke", headers=admin_headers)
        assert revoke.status_code == 200
        assert revoke.json()["revoked"] is True

        unrevoke = client.post("/api/authorization/devices/dev-rv-3/unrevoke", headers=admin_headers)
        assert unrevoke.status_code == 200
        assert unrevoke.json()["revoked"] is False

    def test_revoked_device_blocks_subsequent_encryption(self, client):
        headers_a, _ = _register(client, "revoke_a4")
        admin_headers, _ = _register(client, "revoke_admin4", role="ADMIN")
        client.post("/api/face/enroll", json={"descriptor": [0.3] * 128}, headers=headers_a)
        intent_id, cid = _establish_session_and_intent(client, headers_a, "dev-rv-4", "sess-rv-4", approve=False)

        revoke = client.post("/api/authorization/devices/dev-rv-4/revoke", headers=admin_headers)
        assert revoke.status_code == 200

        # A device revoked before approval blocks approval itself.
        # (Approving as admin_headers rather than the owner, since the
        # owner can never approve their own intent — separation of
        # duties, see api/routers/intent.py::transition_intent.)
        approve = client.post(
            f"/api/intent/{intent_id}/transition",
            json={"target_state": "approved", "reason": "test"},
            headers=admin_headers,
        )
        assert approve.status_code == 409

    def test_revoked_session_blocks_subsequent_decryption(self, client):
        headers_a, _ = _register(client, "revoke_a5")
        admin_headers, _ = _register(client, "revoke_admin5", role="ADMIN")
        client.post("/api/face/enroll", json={"descriptor": [0.4] * 128}, headers=headers_a)
        intent_id, cid = _establish_session_and_intent(client, headers_a, "dev-rv-5", "sess-rv-5")

        enc = client.post(
            "/api/encrypt",
            json={
                "intent_id": intent_id,
                "cid": cid,
                "plaintext_base64": "cGF5bG9hZA==",
                "quantum_key_hex": "22" * 32,
                "face_descriptor": [0.4] * 128,
            },
            headers=headers_a,
        )
        assert enc.status_code == 201
        record_id = enc.json()["record_id"]

        revoke = client.post("/api/authorization/sessions/sess-rv-5/revoke", headers=admin_headers)
        assert revoke.status_code == 200

        dec = client.post(
            "/api/decrypt",
            json={
                "record_id": record_id,
                "cid": cid,
                "quantum_key_hex": "22" * 32,
                "face_descriptor": [0.4] * 128,
            },
            headers=headers_a,
        )
        assert dec.status_code in (401, 403, 409)
        assert dec.status_code != 500


# ---------------------------------------------------------------------
# Do not leak 500s for ordinary authorization failures
# ---------------------------------------------------------------------

class TestNoLeakingInternalServerErrors:
    def test_ownership_violations_are_never_500(self, client):
        headers_a, _ = _register(client, "leak_a1")
        headers_b, _ = _register(client, "leak_b1")
        intent_id, cid = _establish_session_and_intent(client, headers_a, "dev-lk-1", "sess-lk-1", approve=False)

        for resp in [
            client.get("/api/authorization/devices/dev-lk-1", headers=headers_b),
            client.get("/api/authorization/sessions/sess-lk-1", headers=headers_b),
            client.post(
                "/api/intent/validate", json={"cid": cid, "intent_id": intent_id}, headers=headers_b
            ),
        ]:
            assert resp.status_code < 500

    def test_role_violations_are_never_500(self, client):
        headers, _ = _register(client, "leak_role1", role="USER_LEVEL_1")
        resp = client.post(
            "/api/policies",
            json={"name": "p", "rule_type": "max_risk_score", "config": {}, "active": True},
            headers=headers,
        )
        assert resp.status_code == 403
        assert resp.status_code < 500


# ---------------------------------------------------------------------
# 8. Audit log access — role-gated (not resource ownership, since the
# audit trail intentionally spans every user)
# ---------------------------------------------------------------------

class TestAuditLogAccess:
    def test_standard_user_cannot_read_audit_logs(self, client):
        headers, _ = _register(client, "audit_employee1", role="USER_LEVEL_1")
        resp = client.get("/api/audit/logs", headers=headers)
        assert resp.status_code == 403

    def test_standard_user_cannot_read_audit_verify(self, client):
        headers, _ = _register(client, "audit_employee2", role="USER_LEVEL_1")
        resp = client.get("/api/audit/verify", headers=headers)
        assert resp.status_code == 403

    @pytest.mark.parametrize("role", ["ADMIN", "USER_LEVEL_2"])
    def test_privileged_roles_can_read_audit_logs(self, client, role):
        # ADMIN (folding the old SYSTEM_ADMIN/SECURITY_ANALYST) and
        # USER_LEVEL_2 (folding the old DATABASE_ADMIN/AUDITOR/
        # UNIT_MANAGER) both can read the audit trail; only
        # USER_LEVEL_1 cannot (see test_standard_user_cannot_read_audit_logs
        # above).
        headers, _ = _register(client, f"audit_priv_{role.lower()}", role=role)
        resp = client.get("/api/audit/logs", headers=headers)
        assert resp.status_code == 200

    def test_audit_logs_are_not_readable_by_ordinary_users_even_about_their_own_activity(self, client):
        # An ordinary user cannot read the audit trail at all — not
        # even entries about their own actions — since this endpoint
        # returns the whole system's log, not a per-user slice.
        headers_a, _ = _register(client, "audit_own_activity")
        _establish_session_and_intent(client, headers_a, "dev-au-1", "sess-au-1", approve=False)
        resp = client.get("/api/audit/logs", headers=headers_a)
        assert resp.status_code == 403


# ---------------------------------------------------------------------
# PART 14 — monitoring-start ownership (device/session must belong to
# the authenticated caller BEFORE a monitoring session is created)
# ---------------------------------------------------------------------

class TestMonitoringStartOwnership:
    def test_user_can_start_monitoring_for_own_device_and_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a1")
        _establish_session_and_intent(client, headers_a, "mon-dev-a1", "mon-sess-a1", approve=False)

        resp = client.post(
            "/api/monitoring/start",
            json={"device_id": "mon-dev-a1", "session_id": "mon-sess-a1", "face_confidence": 0.95},
            headers=headers_a,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["current_user"]

    def test_user_b_cannot_start_monitoring_using_user_a_device_and_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a2")
        headers_b, _ = _register(client, "mon_owner_b2")
        _establish_session_and_intent(client, headers_a, "mon-dev-a2", "mon-sess-a2", approve=False)

        resp = client.post(
            "/api/monitoring/start",
            json={"device_id": "mon-dev-a2", "session_id": "mon-sess-a2", "face_confidence": 0.95},
            headers=headers_b,
        )
        assert resp.status_code == 403

    def test_cannot_start_monitoring_against_a_session_that_does_not_exist(self, client):
        headers_a, _ = _register(client, "mon_owner_a3")
        resp = client.post(
            "/api/monitoring/start",
            json={"device_id": "ghost-device", "session_id": "ghost-session", "face_confidence": 0.9},
            headers=headers_a,
        )
        assert resp.status_code == 403

    def test_cannot_start_monitoring_with_device_id_mismatched_to_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a4")
        _establish_session_and_intent(client, headers_a, "mon-dev-a4", "mon-sess-a4", approve=False)

        resp = client.post(
            "/api/monitoring/start",
            # session exists and is owned by A, but the device_id given
            # doesn't match the device that session was authorized for.
            json={"device_id": "some-other-device", "session_id": "mon-sess-a4", "face_confidence": 0.9},
            headers=headers_a,
        )
        assert resp.status_code == 403

    def test_admin_can_start_monitoring_for_another_users_device_and_session(self, client):
        headers_a, _ = _register(client, "mon_owner_a5")
        admin_headers, _ = _register(client, "mon_admin5", role="ADMIN")
        _establish_session_and_intent(client, headers_a, "mon-dev-a5", "mon-sess-a5", approve=False)

        resp = client.post(
            "/api/monitoring/start",
            json={"device_id": "mon-dev-a5", "session_id": "mon-sess-a5", "face_confidence": 0.9},
            headers=admin_headers,
        )
        assert resp.status_code == 200, resp.text

    def test_user_b_starting_monitoring_does_not_create_a_leaked_record(self, client):
        # Confirms the rejection happens BEFORE any monitoring record
        # is created/mutated — not "create then discover the
        # violation": B should not even be able to reach a monitoring
        # session tied to A's device/session via any subsequent call.
        headers_a, _ = _register(client, "mon_owner_a6")
        headers_b, _ = _register(client, "mon_owner_b6")
        _establish_session_and_intent(client, headers_a, "mon-dev-a6", "mon-sess-a6", approve=False)

        denied = client.post(
            "/api/monitoring/start",
            json={"device_id": "mon-dev-a6", "session_id": "mon-sess-a6", "face_confidence": 0.95},
            headers=headers_b,
        )
        assert denied.status_code == 403

        # A's own legitimate start still works afterward — B's failed
        # attempt didn't corrupt shared device/session state.
        ok = client.post(
            "/api/monitoring/start",
            json={"device_id": "mon-dev-a6", "session_id": "mon-sess-a6", "face_confidence": 0.95},
            headers=headers_a,
        )
        assert ok.status_code == 200, ok.text
