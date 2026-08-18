"""
PHASE 4 — Revocation + Continuous Risk + Audit Integrity.

One consolidated suite exercising exactly the scenarios called for in
the brief, end to end, against the SAME services every router uses
(no parallel/duplicate enforcement path):

  * legitimate normal user                          -> NORMAL
  * suspicious behavior increases risk               -> WARNING
  * high risk causes reauthentication/restriction    -> REAUTH_REQUIRED
  * critical risk causes configured revocation        -> REVOKED
  * revoked session blocks encryption
  * revoked device blocks encryption
  * revoked state blocks decryption
  * audit events created
  * audit chain verifies
  * tampered audit chain detected
  * timestamp correctness (tz-aware UTC, not fabricated)

A single demo user (user_id=1) is used throughout, per the brief's
"use ONE user for the demo".
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from audit.events import AuditEvent
from audit.hash_chain import AuditEntry
from audit.service import AuditLogService, InMemoryAuditLogRepository
from authorization import (
    AuthorizationService,
    DeviceRevokedError,
    InMemoryDeviceRepository,
    InMemorySessionRepository,
    SessionInvalidError,
)
from intent.lifecycle import IntentState
from intent.schema import CID
from monitoring.service import InMemoryMonitoringRepository, MonitoringService
from monitoring.state import MonitoringStatus, MonitoringThresholds, SecurityPostureState
from policy.risk import RiskEngine, RiskFactors, RiskLevel

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
USER_ID = 1
DEVICE_ID = "device-demo-001"
SESSION_ID = "session-demo-abc"


def _cid(**overrides) -> CID:
    kwargs = dict(
        sender="alice",
        receiver="bob",
        purpose="quarterly-report-share",
        resource="reports/q3.pdf",
        operation="decrypt",
        device_id=DEVICE_ID,
        session_id=SESSION_ID,
        valid_from=NOW - timedelta(minutes=5),
        valid_until=NOW + timedelta(hours=1),
    )
    kwargs.update(overrides)
    return CID(**kwargs)


def _harness(thresholds: MonitoringThresholds | None = None):
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    sessions.get_or_create(SESSION_ID, user_id=USER_ID, device_id=DEVICE_ID, ttl=timedelta(hours=1), now=NOW)
    monitoring_repo = InMemoryMonitoringRepository()
    audit = AuditLogService(InMemoryAuditLogRepository())
    service = MonitoringService(
        monitoring_repo,
        devices,
        sessions,
        audit_service=audit,
        thresholds=thresholds
        or MonitoringThresholds(
            warning_after=1, risk_increase_after=2, reauth_required_after=3, invalidate_after=6
        ),
    )
    authz = AuthorizationService(devices, sessions)
    return service, devices, sessions, audit, authz


# ---------------------------------------------------------------------
# 1. Legitimate normal user -> NORMAL
# ---------------------------------------------------------------------

def test_legitimate_normal_user_stays_normal():
    service, *_ = _harness()
    started = service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.97, now=NOW)
    assert started.status is MonitoringStatus.ACTIVE
    assert started.security_state is SecurityPostureState.NORMAL
    assert started.current_risk is RiskLevel.LOW
    assert started.current_authorization_state == "valid"

    # a few unremarkable heartbeats change nothing
    ts = NOW
    for i in range(3):
        ts += timedelta(seconds=10)
        snap = service.heartbeat(
            started.monitoring_session_id, face_present=True, face_confidence=0.95, liveness=True, now=ts
        )
        assert snap.status is MonitoringStatus.ACTIVE
        assert snap.security_state is SecurityPostureState.NORMAL


# ---------------------------------------------------------------------
# 2. Suspicious behavior increases risk -> WARNING
# ---------------------------------------------------------------------

def test_suspicious_behavior_increases_risk_to_warning():
    service, *_ = _harness()
    started = service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.95, now=NOW)

    # One transient face-verification failure is exactly the kind of
    # single abnormal event that should escalate to WARNING, but must
    # NOT be treated as compromised/revoked on its own.
    snap = service.heartbeat(
        started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False,
        now=NOW + timedelta(seconds=5),
    )
    assert snap.status is MonitoringStatus.WARNING
    assert snap.security_state is SecurityPostureState.WARNING
    assert snap.current_authorization_state == "valid"  # still usable


def test_single_face_failure_or_low_confidence_alone_is_not_compromised():
    """A single low-confidence face read (not even an outright
    failure) must never, on its own, look like COMPROMISED/REVOKED —
    only repeated/aggregated signals should escalate that far."""
    engine = RiskEngine()
    result = engine.assess(RiskFactors(face_confidence=0.4))
    assert result.level in (RiskLevel.LOW, RiskLevel.MEDIUM)
    assert result.level is not RiskLevel.CRITICAL


# ---------------------------------------------------------------------
# 3. High risk -> REAUTHENTICATION / RESTRICTED
# ---------------------------------------------------------------------

def test_high_risk_causes_reauthentication_required():
    service, *_ = _harness(
        thresholds=MonitoringThresholds(
            warning_after=1, risk_increase_after=2, reauth_required_after=3, invalidate_after=6
        )
    )
    started = service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.95, now=NOW)

    ts = NOW
    snap = None
    for _ in range(3):
        ts += timedelta(seconds=5)
        snap = service.heartbeat(
            started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=ts,
        )
    assert snap.status is MonitoringStatus.REAUTH_REQUIRED
    # PHASE 4: HIGH risk maps to WARNING-posture ("suspicious but
    # authorization remains active") — NOT COMPROMISED and NOT REVOKED.
    assert snap.security_state is SecurityPostureState.WARNING
    assert snap.current_authorization_state == "valid"


def test_high_risk_via_risk_engine_directly_maps_to_reject_action():
    from policy.risk import RiskAction

    engine = RiskEngine()
    result = engine.assess(RiskFactors(qber=0.9, device_mismatch=True))
    assert result.level is RiskLevel.HIGH
    assert result.action is RiskAction.REJECT


# ---------------------------------------------------------------------
# 4. Critical risk -> REVOCATION / CRYPTO BLOCK (configured threshold)
# ---------------------------------------------------------------------

def test_critical_risk_causes_configured_revocation():
    service, devices, sessions, audit, authz = _harness(
        thresholds=MonitoringThresholds(
            warning_after=1, risk_increase_after=2, reauth_required_after=8, invalidate_after=10
        )
    )
    started = service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.95, now=NOW)

    # Feed enough "repeated denied requests" to independently push the
    # risk score to CRITICAL without relying on face-failure streaks
    # or thresholds — proving the *risk-driven* revocation path (not
    # just the pre-existing failure-count path).
    snap = None
    ts = NOW
    for _ in range(6):
        ts += timedelta(seconds=1)
        snap = service.report_denied_request(started.monitoring_session_id, now=ts)
    assert snap.current_risk is RiskLevel.CRITICAL
    assert snap.status is MonitoringStatus.REVOKED
    assert snap.security_state is SecurityPostureState.REVOKED
    assert snap.current_authorization_state == "invalid"

    # The monitoring service actually revoked the underlying session
    # (and, for a CRITICAL score, the device too) rather than just
    # reporting a status.
    assert sessions.get(SESSION_ID).revoked is True
    assert devices.get_status(DEVICE_ID).revoked is True

    entries = audit.list_entries()
    assert any(e.action == AuditEvent.MONITORING_REVOKED for e in entries)
    assert any(e.action == AuditEvent.SESSION_REVOKED for e in entries)
    assert any(e.action == AuditEvent.DEVICE_REVOKED for e in entries)


# ---------------------------------------------------------------------
# 5/6/7. Revoked session/device/state blocks encryption & decryption
# ---------------------------------------------------------------------

def test_revoked_session_blocks_encryption_and_decryption():
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    sessions.get_or_create(SESSION_ID, user_id=USER_ID, device_id=DEVICE_ID, ttl=timedelta(hours=1), now=NOW)
    authz = AuthorizationService(devices, sessions)

    sessions.revoke(SESSION_ID)

    cid = _cid(operation="encrypt")
    with pytest.raises(SessionInvalidError):
        authz.authorize(
            cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=USER_ID, requesting_user_role="user", now=NOW,
        )
    cid = _cid(operation="decrypt")
    with pytest.raises(SessionInvalidError):
        authz.authorize(
            cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=USER_ID, requesting_user_role="user", now=NOW,
        )


def test_revoked_device_blocks_encryption_and_decryption():
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    sessions.get_or_create(SESSION_ID, user_id=USER_ID, device_id=DEVICE_ID, ttl=timedelta(hours=1), now=NOW)
    authz = AuthorizationService(devices, sessions)

    devices.revoke(DEVICE_ID)

    cid = _cid(operation="encrypt")
    with pytest.raises(DeviceRevokedError):
        authz.authorize(
            cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=USER_ID, requesting_user_role="user", now=NOW,
        )
    cid = _cid(operation="decrypt")
    with pytest.raises(DeviceRevokedError):
        authz.authorize(
            cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=USER_ID, requesting_user_role="user", now=NOW,
        )


def test_monitoring_driven_revocation_blocks_subsequent_decrypt():
    """The monitoring session (not just the raw repositories) reaching
    REVOKED must be reflected in the SAME session/device repositories
    `AuthorizationService` checks — i.e. the crypto path really is
    blocked, not just the dashboard status."""
    service, devices, sessions, audit, authz = _harness(
        thresholds=MonitoringThresholds(
            warning_after=1, risk_increase_after=2, reauth_required_after=3, invalidate_after=4
        )
    )
    started = service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.95, now=NOW)

    ts = NOW
    for _ in range(4):
        ts += timedelta(seconds=5)
        snap = service.heartbeat(
            started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=ts,
        )
    assert snap.status is MonitoringStatus.REVOKED

    cid = _cid(operation="decrypt")
    with pytest.raises(SessionInvalidError):
        authz.authorize(
            cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=USER_ID, requesting_user_role="user", now=ts,
        )


# ---------------------------------------------------------------------
# 8/9. Audit events created & audit chain verifies
# ---------------------------------------------------------------------

def test_audit_events_created_across_lifecycle():
    service, devices, sessions, audit, authz = _harness()
    started = service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.95, now=NOW)
    service.heartbeat(
        started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False,
        now=NOW + timedelta(seconds=5),
    )
    service.stop(started.monitoring_session_id, now=NOW + timedelta(seconds=10))

    actions = {e.action for e in audit.list_entries()}
    assert AuditEvent.MONITORING_STARTED in actions
    assert AuditEvent.MONITORING_WARNING in actions
    assert AuditEvent.MONITORING_TERMINATED in actions


def test_audit_chain_verifies_for_untampered_log():
    service, *_ , audit, _ = _harness()
    service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.95, now=NOW)
    audit.record(AuditEvent.DECRYPT_SUCCESS, "success", user_id=USER_ID, session_id=SESSION_ID, device_id=DEVICE_ID)

    result = audit.verify_integrity()
    assert result.valid is True
    assert result.first_invalid_index is None


# ---------------------------------------------------------------------
# 10. Tampered audit chain is detected
# ---------------------------------------------------------------------

def test_tampered_audit_chain_is_detected_and_raises_alert():
    repo = InMemoryAuditLogRepository()
    audit = AuditLogService(repo)
    audit.record(AuditEvent.LOGIN_SUCCESS, "success", user_id=USER_ID)
    audit.record(AuditEvent.INTENT_CREATED, "success", user_id=USER_ID, intent_hash="abc123")
    audit.record(AuditEvent.ENCRYPT_SUCCESS, "success", user_id=USER_ID, intent_hash="abc123")

    # Tamper with the middle entry's result (as an attacker rewriting
    # history in the backing store would) without recomputing hashes.
    entries = list(repo._entries)  # test-only reach-in; InMemory repo is a plain list
    tampered = entries[1]
    entries[1] = AuditEntry(
        timestamp=tampered.timestamp,
        user_id=tampered.user_id,
        action=tampered.action,
        intent_hash="TAMPERED-HASH",
        result=tampered.result,
        prev_log_hash=tampered.prev_log_hash,
        current_log_hash=tampered.current_log_hash,  # stale — no longer matches recomputed hash
        session_id=tampered.session_id,
        device_id=tampered.device_id,
        resource=tampered.resource,
        operation=tampered.operation,
        risk=tampered.risk,
        reason=tampered.reason,
    )
    repo._entries = entries

    result = audit.verify_integrity()
    assert result.valid is False
    assert result.first_invalid_index == 1  # identifies the FIRST invalid event

    # A monitoring evaluation run against this same audit service picks
    # up the tamper as a system-wide COMPROMISED condition and raises
    # exactly one AUDIT_TAMPER_DETECTED alert (not unbounded/recursive
    # re-logging on every subsequent evaluation).
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    sessions.get_or_create(SESSION_ID, user_id=USER_ID, device_id=DEVICE_ID, ttl=timedelta(hours=1), now=NOW)
    monitoring_repo = InMemoryMonitoringRepository()
    service = MonitoringService(monitoring_repo, devices, sessions, audit_service=audit)
    started = service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.95, now=NOW)
    assert started.security_state is SecurityPostureState.COMPROMISED

    ts = NOW
    for _ in range(5):
        ts += timedelta(seconds=1)
        service.heartbeat(
            started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True, now=ts,
        )

    tamper_alerts = [e for e in audit.list_entries() if e.action == AuditEvent.AUDIT_TAMPER_DETECTED]
    assert len(tamper_alerts) == 1  # exactly once, never re-triggered on later heartbeats


# ---------------------------------------------------------------------
# 11. Timestamp correctness
# ---------------------------------------------------------------------

def test_audit_timestamps_are_timezone_aware_utc_and_not_fabricated():
    audit = AuditLogService(InMemoryAuditLogRepository())
    before = datetime.now(timezone.utc)
    entry = audit.record(AuditEvent.LOGIN_SUCCESS, "success", user_id=USER_ID)
    after = datetime.now(timezone.utc)

    assert entry.timestamp.tzinfo is not None
    assert entry.timestamp.utcoffset() == timedelta(0)
    # AuditLogService truncates to millisecond precision before hashing
    # (matching MongoDB's BSON datetime precision, so the hashed value
    # always matches what gets persisted/re-read — see
    # AuditLogService.record). That truncation always rounds down, so
    # allow up to 1ms of leeway on the lower bound.
    assert before - timedelta(milliseconds=1) <= entry.timestamp <= after
    assert entry.timestamp.microsecond % 1000 == 0


def test_monitoring_snapshot_timestamp_matches_the_now_it_was_given():
    service, *_ = _harness()
    ts = NOW + timedelta(minutes=42)
    snapshot = service.start(user_id=USER_ID, device_id=DEVICE_ID, session_id=SESSION_ID, face_confidence=0.9, now=ts)
    assert snapshot.timestamp == ts
    assert snapshot.timestamp.tzinfo is not None
