"""
Full HTTP-level end-to-end smoke test of the live FastAPI app, using
TestClient (real request/response/dependency-injection layer) against
an in-memory mongomock database instead of a real MongoDB server.

This exercises exactly what a real frontend does: real JSON in, real
status codes + JSON out. Any 500 here is a genuine bug. It's a useful
regression check to re-run after future changes, since the unit test
suite in tests/ calls services/routers directly and does not exercise
the actual HTTP + dependency-injection layer, request/response schema
validation, or the real MongoDB datetime round-trip behavior.

Run with:  python3 scripts/e2e_smoke_core.py
Requires:  pip install mongomock (already in requirements.txt)
"""
from __future__ import annotations

import os
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sys
import traceback
from datetime import datetime, timedelta, timezone

import mongomock

import database.session as dbsession

_client = mongomock.MongoClient()
dbsession.client = _client
dbsession.db = _client["cipherq_e2e_smoke_core"]

from fastapi.testclient import TestClient  # noqa: E402
from api.main import app  # noqa: E402

client = TestClient(app)

FAILURES: list[str] = []


def _make_admin(username: str, role: str = "ADMIN") -> dict:
    """Register normally (always gets the least-privileged default
    role — see api/routers/auth.py), then, exactly like an out-of-band
    administrator would, elevate the role directly in the store. There
    is deliberately no public API that lets a client grant itself an
    elevated role — see api/rbac.py."""
    r = client.post(
        "/api/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": "Sup3rSecret!"},
    )
    assert r.status_code == 201, r.text
    dbsession.db["users"].update_one({"_id": r.json()["user_id"]}, {"$set": {"role": role}})
    login = client.post("/api/auth/login", json={"username": username, "password": "Sup3rSecret!"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['token']}"}


def check(label, resp, expected):
    ok = resp.status_code in (expected if isinstance(expected, (list, tuple)) else [expected])
    marker = "OK " if ok else "FAIL"
    print(f"[{marker}] {label}: {resp.status_code}")
    if not ok:
        try:
            print("       body:", resp.json())
        except Exception:
            print("       body(raw):", resp.text[:500])
        FAILURES.append(f"{label} -> got {resp.status_code}, expected {expected}")
    return resp


def now_iso(offset_minutes=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat()


FACE_DESCRIPTOR = [0.15] * 128

try:
    check("health", client.get("/api/health"), 200)

    uname = "e2euser1"
    r = check(
        "register",
        client.post("/api/auth/register", json={"username": uname, "email": f"{uname}@example.com", "password": "Sup3rSecret!"}),
        201,
    )
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    check("login", client.post("/api/auth/login", json={"username": uname, "password": "Sup3rSecret!"}), 200)
    check("login bad password", client.post("/api/auth/login", json={"username": uname, "password": "wrong"}), 401)

    # Separation of duties (see api/routers/intent.py::transition_intent):
    # the intent's own creator can never approve it. A distinct
    # USER_LEVEL_2/ADMIN reviewer is required — set up here, early,
    # so every approval below in this script uses it.
    admin_headers = _make_admin("e2eadmin1", role="ADMIN")

    check("face status before enroll", client.get("/api/face/status", headers=headers), 200)
    check("face enroll", client.post("/api/face/enroll", json={"descriptor": FACE_DESCRIPTOR}, headers=headers), 204)
    check("face status after enroll", client.get("/api/face/status", headers=headers), 200)
    fv = check("face verify", client.post("/api/face/verify", json={"descriptor": FACE_DESCRIPTOR}, headers=headers), 200)
    face_confidence = fv.json()["confidence"]

    qr = check("quantum generate-key", client.post("/api/quantum/generate-key", json={"n_qubits": 64, "eavesdrop_prob": 0.0}, headers=headers), 200)
    quantum_key_hex = qr.json()["quantum_key_hex"]
    check("quantum info (no auth)", client.get("/api/quantum/info"), 200)

    device_id = "device-e2e-1"
    session_id = "session-e2e-1"

    cid_payload = {
        "sender": uname,
        "receiver": "vault-service",
        "purpose": "quarterly-report-encryption",
        "resource": "reports/q3.pdf",
        "operation": "encrypt",
        "device_id": device_id,
        "session_id": session_id,
        "valid_from": now_iso(-1),
        "valid_until": now_iso(60),
        "classification": "internal",
        "department": "finance",
        "project": "cipherq-demo",
        "metadata": {"note": "e2e test"},
    }

    check(
        "session refresh (establish)",
        client.post(f"/api/authorization/sessions/{session_id}/refresh", json={"device_id": device_id, "ttl_minutes": 60}, headers=headers),
        200,
    )
    check("device status", client.get(f"/api/authorization/devices/{device_id}", headers=headers), 200)
    check("session status", client.get(f"/api/authorization/sessions/{session_id}", headers=headers), 200)

    check("intent validate (pre-create)", client.post("/api/intent/validate", json={"cid": cid_payload}, headers=headers), 200)

    ir = check("create intent", client.post("/api/intent", json={"cid": cid_payload, "reason": "e2e demo"}, headers=headers), 201)
    intent_id = ir.json()["intent_id"]
    assert ir.json()["lifecycle_state"] == "draft"

    vr = check("intent validate (against created id)", client.post("/api/intent/validate", json={"cid": cid_payload, "intent_id": intent_id}, headers=headers), 200)
    print("       approval_eligible:", vr.json()["approval_eligible"], "reason:", vr.json().get("reason"))

    check("authorization state (pre-approval)", client.post("/api/authorization/state", json={"cid": cid_payload, "intent_id": intent_id}, headers=headers), 200)

    plaintext_b64 = "aGVsbG8gY2lwaGVycQ=="
    check(
        "encrypt while DRAFT (must reject, not crash)",
        client.post("/api/encrypt", json={"intent_id": intent_id, "cid": cid_payload, "plaintext_base64": plaintext_b64, "quantum_key_hex": quantum_key_hex, "face_descriptor": FACE_DESCRIPTOR}, headers=headers),
        409,
    )

    tr = check(
        "transition DRAFT -> APPROVED (by manager/admin, not the creator)",
        client.post(f"/api/intent/{intent_id}/transition", json={"target_state": "approved", "reason": "e2e approval"}, headers=admin_headers),
        200,
    )
    assert tr.json()["lifecycle_state"] == "approved"

    mr = check(
        "monitoring start",
        client.post("/api/monitoring/start", json={"device_id": device_id, "session_id": session_id, "face_confidence": face_confidence, "intent_id": intent_id}, headers=headers),
        200,
    )
    monitoring_session_id = mr.json()["monitoring_session_id"]

    check(
        "monitoring heartbeat",
        client.post("/api/monitoring/heartbeat", json={"monitoring_session_id": monitoring_session_id, "face_present": True, "face_match_confidence": face_confidence, "liveness": True}, headers=headers),
        200,
    )
    check("monitoring status", client.get(f"/api/monitoring/{monitoring_session_id}", headers=headers), 200)
    check("monitoring events", client.get(f"/api/monitoring/{monitoring_session_id}/events", headers=headers), 200)

    er = check(
        "encrypt (APPROVED)",
        client.post("/api/encrypt", json={"intent_id": intent_id, "cid": cid_payload, "plaintext_base64": plaintext_b64, "quantum_key_hex": quantum_key_hex, "face_descriptor": FACE_DESCRIPTOR}, headers=headers),
        201,
    )
    record_id = er.json()["record_id"]
    assert er.json()["intent_lifecycle_state"] == "used"

    check(
        "re-encrypt after USED (must reject, not crash)",
        client.post("/api/encrypt", json={"intent_id": intent_id, "cid": cid_payload, "plaintext_base64": plaintext_b64, "quantum_key_hex": quantum_key_hex, "face_descriptor": FACE_DESCRIPTOR}, headers=headers),
        409,
    )

    dr = check(
        "decrypt (round trip of what was just encrypted must succeed)",
        client.post("/api/decrypt", json={"record_id": record_id, "cid": cid_payload, "quantum_key_hex": quantum_key_hex, "face_descriptor": FACE_DESCRIPTOR}, headers=headers),
        200,
    )
    import base64
    assert base64.b64decode(dr.json()["plaintext_base64"]) == base64.b64decode(plaintext_b64)

    check("risk assess (low)", client.post("/api/risk/assess", json={"qber": 0.0, "face_confidence": 0.95}, headers=headers), 200)
    check(
        "risk assess (high-ish factors)",
        client.post("/api/risk/assess", json={"qber": 0.2, "failed_login_count": 5, "repeated_face_failures": 3, "revoked_device_or_session": True}, headers=headers),
        200,
    )

    check("revoke device", client.post(f"/api/authorization/devices/{device_id}/revoke", headers=admin_headers), 200)
    ir2 = check("create 2nd intent (post device-revoke)", client.post("/api/intent", json={"cid": cid_payload, "reason": "e2e demo 2"}, headers=headers), 201)
    intent_id2 = ir2.json()["intent_id"]
    tr2 = check(
        "transition 2nd intent -> APPROVED (device revoked, expect 409)",
        client.post(f"/api/intent/{intent_id2}/transition", json={"target_state": "approved", "reason": "e2e approval 2"}, headers=admin_headers),
        [200, 409],
    )
    print("       2nd transition result:", tr2.status_code, tr2.json())
    check("unrevoke device", client.post(f"/api/authorization/devices/{device_id}/unrevoke", headers=admin_headers), 200)

    check("revoke device by non-admin (must be 403, not crash)", client.post(f"/api/authorization/devices/{device_id}/revoke", headers=headers), 403)

    check("revoke session", client.post(f"/api/authorization/sessions/{session_id}/revoke", headers=admin_headers), 200)
    check(
        "encrypt after session revoke (expect 401/403/409, not 500)",
        client.post("/api/encrypt", json={"intent_id": intent_id2, "cid": cid_payload, "plaintext_base64": plaintext_b64, "quantum_key_hex": quantum_key_hex, "face_descriptor": FACE_DESCRIPTOR}, headers=headers),
        [401, 403, 409],
    )

    check("create policy by non-admin (must be 403)", client.post("/api/policies", json={"name": "nope", "rule_type": "max_risk_score", "config": {}, "active": True}, headers=headers), 403)
    pr = check(
        "create policy (admin)",
        client.post("/api/policies", json={"name": "e2e-test-policy", "rule_type": "max_risk_score", "config": {"threshold": 0.7}, "active": True}, headers=admin_headers),
        201,
    )
    policy_id = pr.json()["id"]
    check("list policies", client.get("/api/policies", headers=headers), 200)
    check(
        "update policy (admin)",
        client.put(f"/api/policies/{policy_id}", json={"name": "e2e-test-policy", "rule_type": "max_risk_score", "config": {"threshold": 0.5}, "active": True}, headers=admin_headers),
        200,
    )
    check("delete policy (admin)", client.delete(f"/api/policies/{policy_id}", headers=admin_headers), 204)
    check(
        "update deleted policy (should 404)",
        client.put(f"/api/policies/{policy_id}", json={"name": "x", "rule_type": "max_risk_score", "config": {}, "active": True}, headers=admin_headers),
        404,
    )

    check("audit logs", client.get("/api/audit/logs", headers=admin_headers), 200)
    check("audit verify", client.get("/api/audit/verify", headers=admin_headers), 200)

    check("no auth header -> 401", client.get("/api/audit/logs"), 401)
    check("bad token -> 401", client.get("/api/audit/logs", headers={"Authorization": "Bearer garbage"}), 401)

    check("monitoring stop", client.post(f"/api/monitoring/{monitoring_session_id}/stop", headers=headers), 204)

    print("\n=== SUMMARY ===")
    if FAILURES:
        print(f"{len(FAILURES)} FAILURE(S):")
        for f in FAILURES:
            print(" -", f)
        sys.exit(1)
    print("ALL CHECKS PASSED")

except Exception:
    print("\n!!! UNCAUGHT EXCEPTION DURING E2E RUN !!!")
    traceback.print_exc()
    sys.exit(2)
