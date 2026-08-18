"""
Router-level tests for the /api/encrypt lifecycle fix and the
/api/decrypt Draft-rejection path.

Exercises the actual router functions (`api.routers.encryption.encrypt`,
`api.routers.decryption.decrypt`, `api.routers.intent.create_intent`,
`api.routers.intent.transition_intent`) directly against an in-memory
MongoDB (mongomock) — no real MongoDB server required, no HTTP layer,
but the real business logic end to end.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import mongomock
import pytest
from fastapi import HTTPException

import database.session as dbsession

# Point the module-level Mongo handle at an in-memory database before
# any repository call resolves `database.session.db`.
_client = mongomock.MongoClient()
dbsession.client = _client
dbsession.db = _client["cipherq_test"]

from authentication.face_auth import FaceAuthService, InMemoryFaceDescriptorRepository
from authentication.jwt_service import TokenPayload
from audit.events import AuditEvent
from authorization import InMemoryDeviceRepository, InMemorySessionRepository, LifecycleRejectedError
from authorization.service import AuthorizationService
from crypto.service import EncryptionService
from intent.lifecycle import IntentState
from intent.validation import IntentValidationService
from policy.risk import RiskEngine

from api.repositories import EncryptionRecordRepository, IntentRepository, MongoAuditLogRepository
from api.routers.decryption import decrypt as decrypt_route
from api.routers.encryption import encrypt as encrypt_route
from api.routers.intent import create_intent as create_intent_route
from api.routers.intent import transition_intent as transition_intent_route
from audit.service import AuditLogService
from api.schemas import CIDRequest, CreateIntentRequest, DecryptRequest, EncryptRequest, TransitionIntentRequest

FACE_DESCRIPTOR = [0.1] * 128
USER = TokenPayload(user_id=1, username="alice", role="user", expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
# Separation of duties: USER cannot approve its own intent (see
# api/routers/intent.py::transition_intent) — a distinct,
# sufficiently-privileged approver is required for DRAFT -> APPROVED.
APPROVER = TokenPayload(
    user_id=99, username="approver-mallory", role="ADMIN",
    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
)


@pytest.fixture(autouse=True)
def _fresh_db():
    """Every test gets its own empty in-memory database — mongomock
    state must not leak between tests (id counters, prior records).
    """
    dbsession.client = mongomock.MongoClient()
    dbsession.db = dbsession.client["cipherq_test"]
    yield


def _db():
    return dbsession.db


def _services():
    db = _db()
    face_repo = InMemoryFaceDescriptorRepository()
    face_repo.save_enrolled_descriptor(USER.user_id, FACE_DESCRIPTOR)
    return dict(
        db=db,
        encryption_service=EncryptionService(),
        face_auth=FaceAuthService(face_repo),
        authorization_service=AuthorizationService(InMemoryDeviceRepository(), InMemorySessionRepository()),
        audit=AuditLogService(MongoAuditLogRepository(db)),
    )


def _services_with_authz(device_repo, session_repo):
    """Like `_services()`, but with caller-supplied device/session
    repositories so a test can revoke/refresh them directly and see
    the effect on a subsequent encrypt/decrypt call that shares the
    same `AuthorizationService` instance.
    """
    db = _db()
    face_repo = InMemoryFaceDescriptorRepository()
    face_repo.save_enrolled_descriptor(USER.user_id, FACE_DESCRIPTOR)
    return dict(
        db=db,
        encryption_service=EncryptionService(),
        face_auth=FaceAuthService(face_repo),
        authorization_service=AuthorizationService(device_repo, session_repo),
        audit=AuditLogService(MongoAuditLogRepository(db)),
    )


def _decrypt_services():
    services = _services()
    services["risk_engine"] = RiskEngine()
    return services


def _cid_request(**overrides) -> CIDRequest:
    now = datetime.now(timezone.utc)
    kwargs = dict(
        sender="alice",
        receiver="bob",
        purpose="quarterly-report-share",
        resource="reports/q3.pdf",
        operation="decrypt",
        device_id="device-001",
        session_id="session-abc",
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(hours=1),
    )
    kwargs.update(overrides)
    return CIDRequest(**kwargs)


def _create_intent(db, cid_request: CIDRequest):
    audit = AuditLogService(MongoAuditLogRepository(db))
    payload = CreateIntentRequest(cid=cid_request, reason="test")
    return create_intent_route(payload, db=db, user=USER, audit=audit)


def _validation_service() -> IntentValidationService:
    return IntentValidationService(InMemoryDeviceRepository(), InMemorySessionRepository())


def _transition(db, intent_id: int, target: str, validation_service=None, approver=None):
    audit = AuditLogService(MongoAuditLogRepository(db))
    payload = TransitionIntentRequest(target_state=target, reason="test")
    if approver is None:
        approver = APPROVER if target == "approved" else USER
    return transition_intent_route(
        intent_id,
        payload,
        db=db,
        user=approver,
        audit=audit,
        validation_service=validation_service or _validation_service(),
    )


def _encrypt_request(intent_id: int, cid_request: CIDRequest, **overrides) -> EncryptRequest:
    kwargs = dict(
        intent_id=intent_id,
        cid=cid_request,
        plaintext_base64="aGVsbG8=",  # "hello"
        quantum_key_hex=(b"\x01" * 32).hex(),
        face_descriptor=FACE_DESCRIPTOR,
    )
    kwargs.update(overrides)
    return EncryptRequest(**kwargs)


def _record_count(db) -> int:
    return db["encryption_records"].count_documents({})


def _audit_actions(db) -> list[str]:
    return [doc["action"] for doc in db["audit_logs"].find().sort("_id", 1)]


# ---------------------------------------------------------------------
# New intent starts Draft
# ---------------------------------------------------------------------

def test_new_intent_starts_draft():
    db = _db()
    cid_request = _cid_request()
    created = _create_intent(db, cid_request)
    assert created.lifecycle_state == "draft"


# ---------------------------------------------------------------------
# /api/encrypt: Draft is rejected, never touches crypto, no record,
# audit event recorded, lifecycle stays Draft
# ---------------------------------------------------------------------

def test_draft_encryption_rejected_and_never_calls_crypto():
    db = _db()
    cid_request = _cid_request()
    created = _create_intent(db, cid_request)

    services = _services()

    class _ExplodingEncryptionService:
        def encrypt_for_intent(self, *args, **kwargs):  # pragma: no cover - must never run
            raise AssertionError("BB84/HKDF/AES must never run for a Draft intent")

    services["encryption_service"] = _ExplodingEncryptionService()

    payload = _encrypt_request(created.intent_id, cid_request)

    before_records = _record_count(db)
    with pytest.raises(HTTPException) as excinfo:
        encrypt_route(payload, user=USER, **services)
    assert excinfo.value.status_code == 409

    # No encryption record was created.
    assert _record_count(db) == before_records

    # Lifecycle is untouched.
    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.DRAFT

    # A rejection audit event was recorded.
    assert AuditEvent.ENCRYPT_REJECTED in _audit_actions(db)


@pytest.mark.parametrize("target_chain", [["expired"], ["expired", "archived"], ["expired", "archived", "destroyed"]])
def test_ineligible_lifecycle_states_rejected_for_encryption(target_chain):
    db = _db()
    cid_request = _cid_request()
    created = _create_intent(db, cid_request)
    _transition(db, created.intent_id, "approved")
    for target in target_chain:
        _transition(db, created.intent_id, target)

    services = _services()
    payload = _encrypt_request(created.intent_id, cid_request)

    before_records = _record_count(db)
    with pytest.raises(HTTPException) as excinfo:
        encrypt_route(payload, user=USER, **services)
    assert excinfo.value.status_code == 409
    assert _record_count(db) == before_records

    intent_repo = IntentRepository(db)
    final_state = IntentState(target_chain[-1])
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is final_state


# ---------------------------------------------------------------------
# /api/encrypt: Approved succeeds and transitions to Used
# ---------------------------------------------------------------------

def test_approved_encryption_succeeds_and_transitions_to_used():
    db = _db()
    cid_request = _cid_request()
    created = _create_intent(db, cid_request)
    _transition(db, created.intent_id, "approved")

    services = _services()
    payload = _encrypt_request(created.intent_id, cid_request)

    response = encrypt_route(payload, user=USER, **services)

    assert response.intent_lifecycle_state == "used"
    assert _record_count(db) == 1

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.USED
    assert AuditEvent.ENCRYPT_SUCCESS in _audit_actions(db)


# ---------------------------------------------------------------------
# /api/encrypt: a failed encryption leaves lifecycle at Approved
# ---------------------------------------------------------------------

def test_failed_encryption_leaves_lifecycle_approved():
    db = _db()
    cid_request = _cid_request()
    created = _create_intent(db, cid_request)
    _transition(db, created.intent_id, "approved")

    services = _services()

    class _FailingEncryptionService:
        def encrypt_for_intent(self, *args, **kwargs):
            raise RuntimeError("simulated crypto failure")

    services["encryption_service"] = _FailingEncryptionService()
    payload = _encrypt_request(created.intent_id, cid_request)

    with pytest.raises(HTTPException) as excinfo:
        encrypt_route(payload, user=USER, **services)
    assert excinfo.value.status_code == 500

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.APPROVED
    assert _record_count(db) == 0
    assert AuditEvent.ENCRYPT_FAILURE in _audit_actions(db)


# ---------------------------------------------------------------------
# /api/decrypt: Draft is rejected
# ---------------------------------------------------------------------

def test_draft_decryption_rejected():
    db = _db()
    cid_request = _cid_request()
    created = _create_intent(db, cid_request)  # stays Draft

    # Simulate a pre-existing encryption record pointing at this
    # (currently Draft) intent's hash, to exercise the decrypt-side
    # gate independently of the (now-enforced) fact that /api/encrypt
    # itself can never produce such a record for a Draft intent.
    from crypto.aes_gcm import EncryptionEnvelope

    services = _services()
    dummy_envelope = EncryptionEnvelope(
        ciphertext=b"\x00" * 16,
        nonce=b"\x00" * 12,
        auth_tag=b"\x00" * 16,
        intent_hash=IntentRepository(db).get_by_id(created.intent_id).canonical_hash,
        created_at=datetime.now(timezone.utc),
        authorization_state_hash="dummy",
    )
    record_repo = EncryptionRecordRepository(db)
    record = record_repo.save(dummy_envelope, intent_version_id=1, created_by=USER.user_id)

    payload = DecryptRequest(
        record_id=record.id,
        cid=cid_request,
        quantum_key_hex=(b"\x01" * 32).hex(),
        face_descriptor=FACE_DESCRIPTOR,
    )

    with pytest.raises(HTTPException) as excinfo:
        decrypt_route(payload, user=USER, **_decrypt_services())
    assert excinfo.value.status_code == 409
    assert AuditEvent.DECRYPT_REJECTED in _audit_actions(db)


# ---------------------------------------------------------------------
# /api/decrypt: a CID field changed since encryption is rejected before
# any HKDF/AES call, via the intent-hash comparison
# ---------------------------------------------------------------------

def test_decrypt_rejected_when_intent_hash_changed():
    db = _db()
    cid_request = _cid_request()
    created = _create_intent(db, cid_request)
    _transition(db, created.intent_id, "approved")

    device_repo = InMemoryDeviceRepository()
    session_repo = InMemorySessionRepository()
    services = _services_with_authz(device_repo, session_repo)
    encrypt_payload = _encrypt_request(created.intent_id, cid_request)
    encrypt_response = encrypt_route(encrypt_payload, user=USER, **services)

    tampered_cid_request = _cid_request(resource="reports/q4-tampered.pdf")
    decrypt_payload = DecryptRequest(
        record_id=encrypt_response.record_id,
        cid=tampered_cid_request,
        quantum_key_hex=(b"\x01" * 32).hex(),
        face_descriptor=FACE_DESCRIPTOR,
    )

    decrypt_kwargs = dict(services)
    decrypt_kwargs["risk_engine"] = RiskEngine()

    with pytest.raises(HTTPException) as excinfo:
        decrypt_route(decrypt_payload, user=USER, **decrypt_kwargs)
    assert excinfo.value.status_code == 403
    assert AuditEvent.DECRYPT_REJECTED in _audit_actions(db)


# ---------------------------------------------------------------------
# /api/decrypt: the authorization-state hash changing since encryption
# (here, a session re-authorization bumping its version) is rejected
# before any HKDF/AES call, even though the CID itself is unchanged
# ---------------------------------------------------------------------

def test_decrypt_rejected_when_authorization_state_changed():
    db = _db()
    cid_request = _cid_request()
    created = _create_intent(db, cid_request)
    _transition(db, created.intent_id, "approved")

    device_repo = InMemoryDeviceRepository()
    session_repo = InMemorySessionRepository()
    services = _services_with_authz(device_repo, session_repo)
    encrypt_payload = _encrypt_request(created.intent_id, cid_request)
    encrypt_response = encrypt_route(encrypt_payload, user=USER, **services)

    # Re-authorize the session: this bumps its version, which changes
    # the CURRENT authorization-state hash without touching the CID.
    session_repo.refresh(cid_request.session_id, ttl=timedelta(hours=1))

    decrypt_payload = DecryptRequest(
        record_id=encrypt_response.record_id,
        cid=cid_request,
        quantum_key_hex=(b"\x01" * 32).hex(),
        face_descriptor=FACE_DESCRIPTOR,
    )
    decrypt_kwargs = dict(services)
    decrypt_kwargs["risk_engine"] = RiskEngine()

    with pytest.raises(HTTPException) as excinfo:
        decrypt_route(decrypt_payload, user=USER, **decrypt_kwargs)
    assert excinfo.value.status_code == 403
    assert AuditEvent.DECRYPT_REJECTED in _audit_actions(db)


# ---------------------------------------------------------------------
# /api/encrypt: a revoked device blocks crypto entirely, even for an
# Approved intent — never reaches BB84/HKDF/AES
# ---------------------------------------------------------------------

def test_encrypt_rejected_when_device_revoked():
    db = _db()
    cid_request = _cid_request(device_id="device-to-revoke")
    created = _create_intent(db, cid_request)
    _transition(db, created.intent_id, "approved")

    device_repo = InMemoryDeviceRepository()
    device_repo.revoke("device-to-revoke")
    session_repo = InMemorySessionRepository()
    services = _services_with_authz(device_repo, session_repo)

    class _ExplodingEncryptionService:
        def encrypt_for_intent(self, *args, **kwargs):  # pragma: no cover
            raise AssertionError("BB84/HKDF/AES must never run for a revoked device")

    services["encryption_service"] = _ExplodingEncryptionService()
    payload = _encrypt_request(created.intent_id, cid_request)

    with pytest.raises(HTTPException) as excinfo:
        encrypt_route(payload, user=USER, **services)
    assert excinfo.value.status_code == 403
    assert AuditEvent.ENCRYPT_REJECTED in _audit_actions(db)

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.APPROVED


# ---------------------------------------------------------------------
# /api/decrypt: a revoked session blocks crypto entirely
# ---------------------------------------------------------------------

def test_decrypt_rejected_when_session_revoked():
    db = _db()
    cid_request = _cid_request(session_id="session-to-revoke")
    created = _create_intent(db, cid_request)
    _transition(db, created.intent_id, "approved")

    device_repo = InMemoryDeviceRepository()
    session_repo = InMemorySessionRepository()
    services = _services_with_authz(device_repo, session_repo)
    encrypt_payload = _encrypt_request(created.intent_id, cid_request)
    encrypt_response = encrypt_route(encrypt_payload, user=USER, **services)

    session_repo.revoke("session-to-revoke")

    decrypt_payload = DecryptRequest(
        record_id=encrypt_response.record_id,
        cid=cid_request,
        quantum_key_hex=(b"\x01" * 32).hex(),
        face_descriptor=FACE_DESCRIPTOR,
    )
    decrypt_kwargs = dict(services)
    decrypt_kwargs["risk_engine"] = RiskEngine()

    with pytest.raises(HTTPException) as excinfo:
        decrypt_route(decrypt_payload, user=USER, **decrypt_kwargs)
    assert excinfo.value.status_code == 401
    assert AuditEvent.DECRYPT_REJECTED in _audit_actions(db)
