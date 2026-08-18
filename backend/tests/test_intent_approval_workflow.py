"""
Router-level tests for the authorized approval workflow:

    Intent Validation -> Approval -> Cryptography

Specifically, that `/api/intent/{id}/transition` (DRAFT -> APPROVED)
refuses to approve unless the SAME automatic-validation pipeline that
`/api/intent/validate` reports on (`IntentValidationService`) comes
back `approval_eligible=True` for the intent's own recorded CID — and
that `USED` can never be reached by a direct transition request at
all, only as the side effect of a successful `/api/encrypt` call.

Exercises the real router functions directly against an in-memory
MongoDB (mongomock), the same pattern as `test_encryption_flow.py`.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import mongomock
import pytest
from fastapi import HTTPException

import database.session as dbsession

_client = mongomock.MongoClient()
dbsession.client = _client
dbsession.db = _client["cipherq_test"]

from authorization import InMemoryDeviceRepository, InMemorySessionRepository
from authentication.jwt_service import TokenPayload
from audit.events import AuditEvent
from intent.lifecycle import IntentState
from intent.validation import IntentValidationService
from policy.engine import PolicyEngine
from policy.risk import RiskEngine

from api.repositories import IntentRepository, MongoAuditLogRepository
from api.routers.intent import create_intent as create_intent_route
from api.routers.intent import transition_intent as transition_intent_route
from audit.service import AuditLogService
from api.schemas import CIDRequest, CreateIntentRequest, TransitionIntentRequest

USER = TokenPayload(
    user_id=1, username="alice", role="user", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
)

# Separation of duties: approving an intent requires at least
# USER_LEVEL_2, and the approver must not be the intent's own creator
# (unless ADMIN) — see api/routers/intent.py::transition_intent. Tests
# below that exercise DRAFT -> APPROVED use this distinct manager
# identity as the approver; tests for housekeeping transitions
# (expired/archived/destroyed), which carry no such restriction, keep
# using USER (the intent's own owner) as before.
MANAGER = TokenPayload(
    user_id=2, username="manager-mallory", role="USER_LEVEL_2",
    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
)


@pytest.fixture(autouse=True)
def _fresh_db():
    dbsession.client = mongomock.MongoClient()
    dbsession.db = dbsession.client["cipherq_test"]
    yield


def _db():
    return dbsession.db


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


def _transition(
    db, intent_id: int, target: str, *, device_repo=None, session_repo=None, policy_engine=None, approver=None
):
    audit = AuditLogService(MongoAuditLogRepository(db))
    validation_service = IntentValidationService(
        device_repo or InMemoryDeviceRepository(),
        session_repo or InMemorySessionRepository(),
        policy_engine or PolicyEngine(),
        RiskEngine(),
    )
    payload = TransitionIntentRequest(target_state=target, reason="test")
    # Approving (-> APPROVED) is subject to separation-of-duties and
    # defaults to a distinct, sufficiently-privileged approver; every
    # other transition keeps defaulting to the intent's own owner
    # (USER), matching pre-existing behavior.
    if approver is None:
        approver = MANAGER if target == "approved" else USER
    return transition_intent_route(
        intent_id, payload, db=db, user=approver, audit=audit, validation_service=validation_service
    )


def _audit_actions(db) -> list[str]:
    return [doc["action"] for doc in db["audit_logs"].find().sort("_id", 1)]


# ---------------------------------------------------------------------
# Happy path: an eligible Draft intent can be approved
# ---------------------------------------------------------------------

def test_eligible_draft_intent_can_be_approved():
    db = _db()
    created = _create_intent(db, _cid_request())

    updated = _transition(db, created.intent_id, "approved")

    assert updated.lifecycle_state == "approved"
    assert AuditEvent.INTENT_APPROVED in _audit_actions(db)


# ---------------------------------------------------------------------
# A revoked device blocks approval, even though the state-machine edge
# (Draft -> Approved) is otherwise legal
# ---------------------------------------------------------------------

def test_revoked_device_blocks_approval():
    db = _db()
    cid_request = _cid_request(device_id="device-revoked")
    created = _create_intent(db, cid_request)

    device_repo = InMemoryDeviceRepository()
    device_repo.revoke("device-revoked")

    with pytest.raises(HTTPException) as excinfo:
        _transition(db, created.intent_id, "approved", device_repo=device_repo)
    assert excinfo.value.status_code == 409
    assert "not approval-eligible" in str(excinfo.value.detail)

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.DRAFT
    assert AuditEvent.INTENT_REJECTED in _audit_actions(db)


# ---------------------------------------------------------------------
# A revoked session blocks approval
# ---------------------------------------------------------------------

def test_revoked_session_blocks_approval():
    db = _db()
    cid_request = _cid_request(session_id="session-revoked")
    created = _create_intent(db, cid_request)

    session_repo = InMemorySessionRepository()
    session_repo.get_or_create(
        "session-revoked", user_id=USER.user_id, device_id="device-001", ttl=timedelta(hours=1)
    )
    session_repo.revoke("session-revoked")

    with pytest.raises(HTTPException) as excinfo:
        _transition(db, created.intent_id, "approved", session_repo=session_repo)
    assert excinfo.value.status_code == 409

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.DRAFT


# ---------------------------------------------------------------------
# A failing policy rule blocks approval
# ---------------------------------------------------------------------

def test_policy_failure_blocks_approval():
    db = _db()
    cid_request = _cid_request(operation="revoke")
    created = _create_intent(db, cid_request)

    from policy.rules import AllowedOperationRule, PolicyContext

    class _RejectRevokeEngine(PolicyEngine):
        def __init__(self):
            super().__init__(rules=[AllowedOperationRule()])

        def evaluate(self, cid, context: PolicyContext):
            # Force-disallow the "revoke" operation for this test.
            from dataclasses import replace

            restricted_context = replace(context, allowed_operations=frozenset({"encrypt", "decrypt"}))
            return super().evaluate(cid, restricted_context)

    with pytest.raises(HTTPException) as excinfo:
        _transition(db, created.intent_id, "approved", policy_engine=_RejectRevokeEngine())
    assert excinfo.value.status_code == 409

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.DRAFT


# ---------------------------------------------------------------------
# An already-approved intent cannot be "re-approved"
# ---------------------------------------------------------------------

def test_already_approved_intent_cannot_be_reapproved():
    db = _db()
    created = _create_intent(db, _cid_request())
    _transition(db, created.intent_id, "approved")

    with pytest.raises(HTTPException) as excinfo:
        _transition(db, created.intent_id, "approved")
    assert excinfo.value.status_code == 409


# ---------------------------------------------------------------------
# `used` can never be reached by a direct transition request — only as
# the side effect of a successful /api/encrypt call.
# ---------------------------------------------------------------------

def test_used_cannot_be_reached_via_direct_transition():
    db = _db()
    created = _create_intent(db, _cid_request())
    _transition(db, created.intent_id, "approved")

    with pytest.raises(HTTPException) as excinfo:
        _transition(db, created.intent_id, "used")
    assert excinfo.value.status_code == 409
    assert "cannot be requested directly" in str(excinfo.value.detail)

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.APPROVED
    assert AuditEvent.INTENT_REJECTED in _audit_actions(db)


# ---------------------------------------------------------------------
# Housekeeping transitions (Approved -> Expired -> Archived -> Destroyed)
# remain reachable directly — they carry no crypto side effect and are
# not gated by approval-eligibility.
# ---------------------------------------------------------------------

def test_housekeeping_transitions_remain_directly_reachable():
    db = _db()
    created = _create_intent(db, _cid_request())
    _transition(db, created.intent_id, "approved")
    _transition(db, created.intent_id, "expired")
    _transition(db, created.intent_id, "archived")
    updated = _transition(db, created.intent_id, "destroyed")

    assert updated.lifecycle_state == "destroyed"


# ---------------------------------------------------------------------
# Separation of duties: the creator of an intent cannot approve their
# own intent, even if they hold USER_LEVEL_2 privilege.
# ---------------------------------------------------------------------

def test_user_cannot_approve_own_intent():
    db = _db()
    created = _create_intent(db, _cid_request())

    # Alice (the creator, plain "user" role) tries to approve her own
    # DRAFT intent directly.
    with pytest.raises(HTTPException) as excinfo:
        _transition(db, created.intent_id, "approved", approver=USER)
    assert excinfo.value.status_code == 403

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.DRAFT
    assert AuditEvent.INTENT_REJECTED in _audit_actions(db)


def test_same_user_with_elevated_role_still_cannot_approve_own_intent():
    db = _db()
    audit = AuditLogService(MongoAuditLogRepository(db))
    payload = CreateIntentRequest(cid=_cid_request(), reason="test")
    # MANAGER creates and then tries to approve their own intent.
    created = create_intent_route(payload, db=db, user=MANAGER, audit=audit)

    with pytest.raises(HTTPException) as excinfo:
        _transition(db, created.intent_id, "approved", approver=MANAGER)
    assert excinfo.value.status_code == 403

    intent_repo = IntentRepository(db)
    assert intent_repo.get_by_id(created.intent_id).lifecycle_state is IntentState.DRAFT


def test_unprivileged_role_cannot_approve_even_another_users_intent():
    db = _db()
    created = _create_intent(db, _cid_request())

    other_user = TokenPayload(
        user_id=3, username="charlie", role="user",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    with pytest.raises(HTTPException) as excinfo:
        _transition(db, created.intent_id, "approved", approver=other_user)
    assert excinfo.value.status_code == 403


def test_manager_can_approve_another_users_intent():
    db = _db()
    created = _create_intent(db, _cid_request())

    updated = _transition(db, created.intent_id, "approved", approver=MANAGER)
    assert updated.lifecycle_state == "approved"


def test_admin_can_approve_own_intent():
    db = _db()
    audit = AuditLogService(MongoAuditLogRepository(db))
    admin = TokenPayload(
        user_id=4, username="admin-abe", role="ADMIN",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    payload = CreateIntentRequest(cid=_cid_request(), reason="test")
    created = create_intent_route(payload, db=db, user=admin, audit=audit)

    updated = _transition(db, created.intent_id, "approved", approver=admin)
    assert updated.lifecycle_state == "approved"
