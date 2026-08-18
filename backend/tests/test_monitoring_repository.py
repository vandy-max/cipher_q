"""
`MongoMonitoringRepository` persistence tests, against an in-memory
MongoDB (mongomock) — the same pattern used by
`test_encryption_flow.py`. Confirms the Mongo-backed repository
round-trips `MonitoringSessionRecord` / `MonitoringEvent` the same
way `InMemoryMonitoringRepository` does, so `MonitoringService`
behaves identically regardless of which repository backs it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import mongomock
import pytest

import database.session as dbsession

_client = mongomock.MongoClient()
dbsession.client = _client
dbsession.db = _client["cipherq_monitoring_test"]

from api.repositories import IntentRepository, MongoDeviceRepository, MongoMonitoringRepository, MongoSessionRepository
from audit.service import AuditLogService, InMemoryAuditLogRepository
from monitoring.service import MonitoringService
from monitoring.state import MonitoringStatus, MonitoringThresholds

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_db():
    for name in list(dbsession.db.list_collection_names()):
        dbsession.db.drop_collection(name)
    yield


def _service():
    db = dbsession.db
    return MonitoringService(
        MongoMonitoringRepository(db),
        MongoDeviceRepository(db),
        MongoSessionRepository(db),
        audit_service=AuditLogService(InMemoryAuditLogRepository()),
        thresholds=MonitoringThresholds(
            warning_after=1, risk_increase_after=2, reauth_required_after=3, invalidate_after=5
        ),
    )


def test_mongo_backed_monitoring_session_persists_across_calls():
    service = _service()
    started = service.start(user_id=7, device_id="dev-1", session_id="sess-1", face_confidence=0.9, now=NOW)

    fresh_service = _service()  # simulates a new request / new DI-resolved service
    snapshot = fresh_service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.status is MonitoringStatus.ACTIVE
    assert snapshot.monitoring_session_id == started.monitoring_session_id


def test_mongo_backed_events_recorded_and_listable():
    service = _service()
    started = service.start(user_id=7, device_id="dev-1", session_id="sess-1", face_confidence=0.9, now=NOW)
    service.heartbeat(started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True, now=NOW + timedelta(seconds=5))

    events = service.list_events(started.monitoring_session_id)
    assert [e.event_type for e in events] == ["started", "heartbeat"]


def test_mongo_backed_device_revocation_detected():
    service = _service()
    devices = MongoDeviceRepository(dbsession.db)
    started = service.start(user_id=7, device_id="dev-1", session_id="sess-1", face_confidence=0.9, now=NOW)

    devices.revoke("dev-1")
    snapshot = service.heartbeat(
        started.monitoring_session_id, face_present=True, face_confidence=0.9, liveness=True,
        now=NOW + timedelta(seconds=5),
    )
    assert snapshot.status is MonitoringStatus.REVOKED
