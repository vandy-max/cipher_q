"""
HTTP-level smoke test for the two scenarios that most needed
regression coverage:

  1. Audit hash-chain tamper detection: a clean chain must verify as
     valid, and a chain that's been tampered with directly at the
     storage layer must be reported COMPROMISED — not crash, and not
     false-positive on a chain nobody touched.
  2. The full revocation demonstration: NORMAL -> WARNING (repeated
     face failures) -> REAUTH REQUIRED -> REVOKED -> crypto blocked.

Run with:  python3 scripts/e2e_smoke_revocation_and_audit.py
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
dbsession.db = _client["cipherq_e2e_smoke_revocation"]

from fastapi.testclient import TestClient  # noqa: E402
from api.main import app  # noqa: E402

client = TestClient(app)
FAILURES = []


def _make_admin(username: str, role: str = "ADMIN") -> dict:
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
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {resp.status_code}")
    if not ok:
        try:
            print("       body:", resp.json())
        except Exception:
            print("       body(raw):", resp.text[:300])
        FAILURES.append(label)
    return resp


def now_iso(off=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=off)).isoformat()


FACE = [0.2] * 128

try:
    r = check("register", client.post("/api/auth/register", json={"username": "e2euser2", "email": "e2e2@example.com", "password": "Sup3rSecret!"}), 201)
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    admin_headers = _make_admin("e2eadmin2", role="ADMIN")
    client.post("/api/face/enroll", json={"descriptor": FACE}, headers=headers)

    device_id, session_id = "dev-tamper-1", "sess-tamper-1"
    client.post(f"/api/authorization/sessions/{session_id}/refresh", json={"device_id": device_id, "ttl_minutes": 60}, headers=headers)

    cid_payload = {
        "sender": "e2euser2", "receiver": "vault", "purpose": "tamper-demo", "resource": "res/1",
        "operation": "encrypt", "device_id": device_id, "session_id": session_id,
        "valid_from": now_iso(-1), "valid_until": now_iso(60),
    }
    ir = check("create intent", client.post("/api/intent", json={"cid": cid_payload}, headers=headers), 201)
    intent_id = ir.json()["intent_id"]
    check("approve intent (by admin, not the creator)", client.post(f"/api/intent/{intent_id}/transition", json={"target_state": "approved", "reason": "x"}, headers=admin_headers), 200)

    qr = client.post("/api/quantum/generate-key", json={"n_qubits": 32}, headers=headers)
    qk = qr.json()["quantum_key_hex"]

    er = check(
        "encrypt",
        client.post("/api/encrypt", json={"intent_id": intent_id, "cid": cid_payload, "plaintext_base64": "dGVzdA==", "quantum_key_hex": qk, "face_descriptor": FACE}, headers=headers),
        201,
    )
    record_id = er.json()["record_id"]

    check(
        "decrypt after encrypt (round trip must succeed)",
        client.post("/api/decrypt", json={"record_id": record_id, "cid": cid_payload, "quantum_key_hex": qk, "face_descriptor": FACE}, headers=headers),
        200,
    )

    av = check("audit verify (before tamper)", client.get("/api/audit/verify", headers=admin_headers), 200)
    assert av.json()["valid"] is True, av.json()

    # Tamper directly with the underlying audit collection (simulating
    # DB-level tampering / an attacker with direct DB access).
    audit_coll = None
    for n in dbsession.db.list_collection_names():
        if "audit" in n:
            audit_coll = dbsession.db[n]
            break
    assert audit_coll is not None, "could not locate audit collection to tamper with"
    first_doc = audit_coll.find_one(sort=[("_id", 1)])
    audit_coll.update_one({"_id": first_doc["_id"]}, {"$set": {"result": "TAMPERED"}})

    av2 = check("audit verify (after tamper, must report invalid not crash)", client.get("/api/audit/verify", headers=admin_headers), 200)
    print("       tamper result:", av2.json())
    assert av2.json()["valid"] is False
    assert av2.json()["security_state"] == "compromised"

    # ---- Revocation demonstration: NORMAL -> WARNING -> REAUTH -> REVOKED -> CRYPTO BLOCKED ----
    device_id2, session_id2 = "dev-revoke-1", "sess-revoke-1"
    client.post(f"/api/authorization/sessions/{session_id2}/refresh", json={"device_id": device_id2, "ttl_minutes": 60}, headers=headers)
    mr = check(
        "monitoring start (revocation demo)",
        client.post("/api/monitoring/start", json={"device_id": device_id2, "session_id": session_id2, "face_confidence": 0.95}, headers=headers),
        200,
    )
    msid = mr.json()["monitoring_session_id"]

    for i in range(4):
        hb = client.post("/api/monitoring/heartbeat", json={"monitoring_session_id": msid, "face_present": True, "face_match_confidence": 0.2, "liveness": True}, headers=headers)
        check(f"heartbeat #{i+1} (degraded face confidence)", hb, 200)
        print(f"       -> security_state={hb.json()['security_state']} risk={hb.json()['current_risk']} warnings={hb.json()['warnings']}")

    check("revoke session (revocation demo)", client.post(f"/api/authorization/sessions/{session_id2}/revoke", headers=admin_headers), 200)
    hb2 = check("heartbeat after session revoke", client.post("/api/monitoring/heartbeat", json={"monitoring_session_id": msid, "face_present": True, "face_match_confidence": 0.95, "liveness": True}, headers=headers), 200)
    print("       post-revoke security_state:", hb2.json()["security_state"], "warnings:", hb2.json()["warnings"])

    ir2 = client.post("/api/intent", json={"cid": {**cid_payload, "device_id": device_id2, "session_id": session_id2}}, headers=headers).json()
    tr2 = client.post(f"/api/intent/{ir2['intent_id']}/transition", json={"target_state": "approved", "reason": "x"}, headers=admin_headers)
    print("       approval after session revoke:", tr2.status_code, tr2.json())
    if tr2.status_code == 200:
        check(
            "encrypt blocked after session revoke (must not be 201/500)",
            client.post("/api/encrypt", json={"intent_id": ir2["intent_id"], "cid": {**cid_payload, "device_id": device_id2, "session_id": session_id2}, "plaintext_base64": "dGVzdA==", "quantum_key_hex": qk, "face_descriptor": FACE}, headers=headers),
            [401, 403, 409],
        )

    print("\n=== SUMMARY ===")
    if FAILURES:
        print(f"{len(FAILURES)} FAILURE(S):", FAILURES)
        sys.exit(1)
    print("ALL CHECKS PASSED")

except Exception:
    print("\n!!! UNCAUGHT EXCEPTION !!!")
    traceback.print_exc()
    sys.exit(2)
