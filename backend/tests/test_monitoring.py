"""
Tests for `monitoring/` — continuous monitoring + continuous
authorization.

Uses the in-memory reference repositories (no MongoDB required),
mirroring the style of `test_authorization.py`. Covers the Phase 3
requirements end to end: starting a session, heartbeats, tolerating
one transient face failure, escalating through configured thresholds,
detecting externally revoked devices/sessions and re-authorization,
and proving that a REVOKED monitoring session actually blocks future
crypto via the *existing* `AuthorizationService` (not a second,
parallel enforcement path).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from audit.events import AuditEvent
from audit.service import AuditLogService, InMemoryAuditLogRepository
from authorization import (
    AuthorizationService,
    InMemoryDeviceRepository,
    InMemorySessionRepository,
    SessionInvalidError,
)
from intent.lifecycle import IntentState
from intent.schema import CID
from monitoring.service import (
    InMemoryMonitoringRepository,
    MonitoringService,
    MonitoringSessionNotFoundError,
)
from monitoring.state import IdentityCheckState, MonitoringStatus, MonitoringThresholds, derive_identity_state

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)


def _cid(**overrides) -> CID:
    kwargs = dict(
        sender="alice",
        receiver="bob",
        purpose="quarterly-report-share",
        resource="reports/q3.pdf",
        operation="decrypt",
        device_id="device-001",
        session_id="session-abc",
        valid_from=NOW - timedelta(minutes=5),
        valid_until=NOW + timedelta(hours=1),
    )
    kwargs.update(overrides)
    return CID(**kwargs)


def _harness(thresholds: MonitoringThresholds | None = None):
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    monitoring_repo = InMemoryMonitoringRepository()
    audit = AuditLogService(InMemoryAuditLogRepository())
    service = MonitoringService(
        monitoring_repo,
        devices,
        sessions,
        audit_service=audit,
        thresholds=thresholds or MonitoringThresholds(
            warning_after=1, risk_increase_after=2, reauth_required_after=3, invalidate_after=5
        ),
    )
    authz = AuthorizationService(devices, sessions)
    return service, devices, sessions, audit, authz


def _establish_auth_session(sessions, device_id="device-001", session_id="session-abc", user_id=1):
    """Simulate the underlying (device_id, session_id) already having
    been used once so it exists in the session repository, the way it
    would after a real encrypt/decrypt call."""
    sessions.get_or_create(session_id, user_id=user_id, device_id=device_id, ttl=timedelta(hours=1), now=NOW)


# ---------------------------------------------------------------------
# LOGIN -> FACE VERIFIED -> MONITORING SESSION STARTED
# ---------------------------------------------------------------------

def test_monitoring_starts_after_face_verification():
    service, *_ = _harness()
    snapshot = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)

    assert snapshot.status is MonitoringStatus.ACTIVE
    assert snapshot.current_authorization_state == "valid"
    assert snapshot.monitoring_session_id
    assert snapshot.authorization_state_hash


def test_monitoring_session_started_is_audited():
    service, _, _, audit, _ = _harness()
    service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    entries = audit.list_entries()
    assert any(e.action == AuditEvent.MONITORING_STARTED for e in entries)


# ---------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------

def test_heartbeat_works_and_stays_active_when_nominal():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)

    snapshot = service.heartbeat(
        started.monitoring_session_id,
        face_present=True,
        face_confidence=0.93,
        liveness=True,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.status is MonitoringStatus.ACTIVE
    assert snapshot.consecutive_face_failures == 0


def test_heartbeat_unknown_session_raises():
    service, *_ = _harness()
    with pytest.raises(MonitoringSessionNotFoundError):
        service.heartbeat("does-not-exist", face_present=True, face_confidence=0.9, liveness=True)


def test_normal_monitoring_stays_active_across_many_heartbeats():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    ts = NOW
    for _ in range(10):
        ts += timedelta(seconds=5)
        snapshot = service.heartbeat(
            started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True, now=ts
        )
    assert snapshot.status is MonitoringStatus.ACTIVE


# ---------------------------------------------------------------------
# Face failures — configurable thresholds
# ---------------------------------------------------------------------

def test_one_face_failure_does_not_revoke():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)

    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.status is MonitoringStatus.WARNING
    assert snapshot.consecutive_face_failures == 1
    assert snapshot.current_authorization_state == "valid"


def test_face_failure_recovers_and_resets_counter():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    ts = NOW
    ts += timedelta(seconds=5)
    service.heartbeat(started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=ts)
    ts += timedelta(seconds=5)
    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True, now=ts
    )
    assert snapshot.consecutive_face_failures == 0
    assert snapshot.status is MonitoringStatus.ACTIVE


def test_repeated_failures_trigger_reauth_required():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    ts = NOW
    snapshot = None
    for _ in range(3):
        ts += timedelta(seconds=5)
        snapshot = service.heartbeat(
            started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=ts
        )
    assert snapshot.consecutive_face_failures == 3
    assert snapshot.status is MonitoringStatus.REAUTH_REQUIRED
    # Not yet invalidated at this threshold.
    assert snapshot.current_authorization_state == "valid"


def test_repeated_failures_past_configured_threshold_invalidate_authorization():
    service, devices, sessions, audit, authz = _harness()
    _establish_auth_session(sessions)
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)

    ts = NOW
    snapshot = None
    for _ in range(5):
        ts += timedelta(seconds=5)
        snapshot = service.heartbeat(
            started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=ts
        )

    assert snapshot.status is MonitoringStatus.REVOKED
    assert snapshot.current_authorization_state == "invalid"

    # -- audit --
    entries = audit.list_entries()
    assert any(e.action == AuditEvent.MONITORING_REVOKED for e in entries)

    # -- block future crypto: reuses the SAME session repository, so
    # AuthorizationService (which every encrypt/decrypt calls) now
    # rejects this session without any second enforcement path. --
    cid = _cid()
    with pytest.raises(SessionInvalidError):
        authz.authorize(
            cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=1, requesting_user_role="user", now=ts,
        )


def test_custom_thresholds_are_respected():
    service, *_ = _harness(thresholds=MonitoringThresholds(
        warning_after=1, risk_increase_after=1, reauth_required_after=2, invalidate_after=2
    ))
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    ts = NOW
    ts += timedelta(seconds=5)
    snapshot = service.heartbeat(started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=ts)
    assert snapshot.status is MonitoringStatus.WARNING
    ts += timedelta(seconds=5)
    snapshot = service.heartbeat(started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=ts)
    assert snapshot.status is MonitoringStatus.REVOKED


def test_invalid_threshold_ordering_rejected():
    with pytest.raises(ValueError):
        MonitoringThresholds(warning_after=3, risk_increase_after=1, reauth_required_after=2, invalidate_after=4)


# ---------------------------------------------------------------------
# Continuous authorization: external device/session changes detected
# ---------------------------------------------------------------------

def test_revoked_device_detected():
    service, devices, sessions, audit, _ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)

    devices.revoke("device-001")

    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.status is MonitoringStatus.REVOKED
    assert "device revoked" in snapshot.warnings
    assert any(e.action == AuditEvent.MONITORING_REVOKED for e in audit.list_entries())


def test_revoked_session_detected():
    service, devices, sessions, audit, _ = _harness()
    _establish_auth_session(sessions)
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)

    sessions.revoke("session-abc")

    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.status is MonitoringStatus.REVOKED
    assert "session revoked" in snapshot.warnings


def test_authorization_state_change_detected_via_hash():
    """The monitoring-state hash changes when status/authorization
    validity changes — this is what a polling UI diffs against to
    know something changed without re-deriving every field."""
    service, devices, sessions, audit, _ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    hash_before = started.authorization_state_hash

    devices.revoke("device-001")
    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.authorization_state_hash != hash_before


def test_get_status_refresh_detects_admin_side_revoke_without_new_heartbeat():
    """`refresh` (the GET endpoint) re-derives status from current
    device/session state even with no new face reading — so an admin
    revoking a device between heartbeats is caught immediately."""
    service, devices, sessions, audit, _ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    assert service.refresh(started.monitoring_session_id).status is MonitoringStatus.ACTIVE

    devices.revoke("device-001")
    snapshot = service.refresh(started.monitoring_session_id)
    assert snapshot.status is MonitoringStatus.REVOKED


def test_refresh_does_not_perturb_face_failure_counter():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    service.heartbeat(started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=NOW + timedelta(seconds=5))
    refreshed = service.refresh(started.monitoring_session_id, now=NOW + timedelta(seconds=6))
    assert refreshed.consecutive_face_failures == 1
    assert refreshed.status is MonitoringStatus.WARNING


# ---------------------------------------------------------------------
# Events recorded
# ---------------------------------------------------------------------

def test_monitoring_events_recorded():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    service.heartbeat(started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True, now=NOW + timedelta(seconds=5))
    service.heartbeat(started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False, now=NOW + timedelta(seconds=10))
    service.stop(started.monitoring_session_id, now=NOW + timedelta(seconds=15))

    events = service.list_events(started.monitoring_session_id)
    event_types = [e.event_type for e in events]
    assert event_types == ["started", "heartbeat", "heartbeat", "stopped"]
    assert all(e.snapshot.monitoring_session_id == started.monitoring_session_id for e in events)


# ---------------------------------------------------------------------
# Expression telemetry: supporting-only, never a compromise trigger
# ---------------------------------------------------------------------

def test_expression_hint_is_carried_but_never_gates_status():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True,
        expression_hint="neutral", now=NOW + timedelta(seconds=5),
    )
    assert snapshot.expression_hint == "neutral"
    assert snapshot.status is MonitoringStatus.ACTIVE

    # Even an unusual expression, on its own, with a good face match,
    # must not itself flip status away from ACTIVE.
    snapshot2 = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True,
        expression_hint="surprised", now=NOW + timedelta(seconds=10),
    )
    assert snapshot2.status is MonitoringStatus.ACTIVE


# ---------------------------------------------------------------------
# PART 3 — explicit continuous-monitoring identity states
# ---------------------------------------------------------------------

def test_derive_identity_state_confirmed():
    assert derive_identity_state(True, 0.93, True) is IdentityCheckState.IDENTITY_CONFIRMED


def test_derive_identity_state_no_face():
    assert derive_identity_state(False, None, False) is IdentityCheckState.NO_FACE


def test_derive_identity_state_mismatch():
    assert derive_identity_state(True, 0.2, True) is IdentityCheckState.IDENTITY_MISMATCH


def test_derive_identity_state_liveness_uncertain():
    assert derive_identity_state(True, 0.9, False) is IdentityCheckState.LIVENESS_UNCERTAIN


def test_derive_identity_state_camera_unavailable_wins():
    # Even if face_present/confidence were somehow still populated
    # from a stale reading, an unavailable camera must never be
    # silently reported as a successful identity check.
    assert (
        derive_identity_state(True, 0.9, True, camera_available=False)
        is IdentityCheckState.CAMERA_UNAVAILABLE
    )


def test_heartbeat_snapshot_carries_identity_confirmed():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.identity_state is IdentityCheckState.IDENTITY_CONFIRMED


def test_heartbeat_snapshot_carries_identity_mismatch():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.1, liveness=True,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.identity_state is IdentityCheckState.IDENTITY_MISMATCH
    assert "does not match" in " ".join(snapshot.warnings)


def test_heartbeat_snapshot_carries_no_face():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=False, face_confidence=None, liveness=False,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.identity_state is IdentityCheckState.NO_FACE


def test_heartbeat_camera_unavailable_is_treated_as_a_failed_tick():
    service, *_ = _harness()
    started = service.start(user_id=1, device_id="device-001", session_id="session-abc", face_confidence=0.95, now=NOW)
    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.95, liveness=True,
        camera_available=False, now=NOW + timedelta(seconds=5),
    )
    # A stale/fabricated "still present and matching" reading must not
    # be trusted when the client itself says the camera is unavailable.
    assert snapshot.identity_state is IdentityCheckState.CAMERA_UNAVAILABLE
    assert snapshot.consecutive_face_failures == 1
