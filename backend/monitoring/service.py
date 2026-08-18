"""
MonitoringService — turns login + face verification into a *running*
continuous-monitoring session, and turns every subsequent heartbeat
into a re-evaluation of derived security telemetry against
configurable thresholds.

Flow this implements (see docs/architecture-design-document.md and
the Phase 3 brief):

    LOGIN -> FACE VERIFIED -> MONITORING SESSION STARTED
    heartbeat, heartbeat, heartbeat, ... (lightweight polling)
    on repeated face failure / device revoke / session revoke /
    session re-authorization / risk escalation / lifecycle change:
        -> WARNING -> REAUTH_REQUIRED -> REVOKED

Authentication is explicitly NOT treated as permanent authorization
here: this service is the thing that keeps re-checking, for the
lifetime of the session, whether the facts that justified granting
access are still true.

Deliberately reused rather than reinvented:
    - `authorization.devices.DeviceRepository` / `.sessions.SessionRepository`
      — the SAME device/session state `AuthorizationService` checks
      before every encrypt/decrypt. When this service escalates to
      REVOKED it calls `session_repository.revoke(...)`, which means
      `AuthorizationService.authorize(...)` (and therefore every
      future encrypt/decrypt) rejects with `SessionInvalidError`
      automatically — "block future crypto" falls out of the existing
      architecture rather than needing a second enforcement path.
    - `policy.risk.RiskEngine` — the same weighted risk engine used
      by the decrypt route, fed with `face_confidence` from the
      latest heartbeat.
    - `audit.service.AuditLogService` — status *transitions* (not
      every heartbeat) are written to the same tamper-evident,
      hash-chained audit log used everywhere else.

Expression telemetry (if supplied) is carried through as supporting,
informational-only data: see `expression_hint` on `MonitoringSnapshot`.
It never changes `status`, is never treated as proof of anything, and
is never folded into any cryptographic material.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Protocol, Sequence

from audit.events import AuditEvent
from audit.service import AuditLogService
from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository
from policy.risk import RiskEngine, RiskFactors, RiskLevel

from .state import (
    DEFAULT_THRESHOLDS,
    IDENTITY_MATCH_THRESHOLD,
    IdentityCheckState,
    MonitoringSnapshot,
    MonitoringStatus,
    MonitoringThresholds,
    SecurityPostureState,
    compute_monitoring_state_hash,
    derive_identity_state,
    derive_security_posture,
)


class LifecycleLookup(Protocol):
    """Minimal read-only interface onto intent lifecycle state, so this
    module doesn't need to depend on the whole `IntentRepository`."""

    def current_lifecycle_state(self, intent_id: int) -> str | None: ...


@dataclass
class MonitoringSessionRecord:
    """Persisted monitoring-session state."""

    monitoring_session_id: str
    user_id: int
    device_id: str
    session_id: str
    intent_id: int | None
    status: MonitoringStatus
    consecutive_face_failures: int
    thresholds: MonitoringThresholds
    started_at: datetime
    updated_at: datetime
    stopped: bool = False
    # PHASE 4 — behavioral/continuous-risk counters, and idempotency
    # guards so escalation events (revoke, audit-tamper alert) are
    # each only ever acted on / logged once per session, never
    # re-triggered every subsequent heartbeat.
    repeated_denied_requests: int = 0
    device_revoked_by_monitoring: bool = False
    audit_tamper_alerted: bool = False


@dataclass(frozen=True)
class MonitoringEvent:
    """One row in the monitoring event log — "monitoring events
    recorded" per the Phase 3 test requirements."""

    monitoring_session_id: str
    event_type: str  # started | heartbeat | warning | reauth_required | revoked | stopped
    snapshot: MonitoringSnapshot


class MonitoringRepository(Protocol):
    def create(
        self, user_id: int, device_id: str, session_id: str, intent_id: int | None,
        thresholds: MonitoringThresholds, now: datetime,
    ) -> MonitoringSessionRecord: ...

    def get(self, monitoring_session_id: str) -> MonitoringSessionRecord | None: ...

    def update(self, record: MonitoringSessionRecord) -> MonitoringSessionRecord: ...

    def append_event(self, event: MonitoringEvent) -> None: ...

    def list_events(self, monitoring_session_id: str) -> Sequence[MonitoringEvent]: ...


class InMemoryMonitoringRepository:
    """Reference/test implementation only — not for production use."""

    def __init__(self) -> None:
        self._sessions: dict[str, MonitoringSessionRecord] = {}
        self._events: dict[str, list[MonitoringEvent]] = {}

    def create(self, user_id, device_id, session_id, intent_id, thresholds, now):
        monitoring_session_id = uuid.uuid4().hex
        record = MonitoringSessionRecord(
            monitoring_session_id=monitoring_session_id,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            intent_id=intent_id,
            status=MonitoringStatus.ACTIVE,
            consecutive_face_failures=0,
            thresholds=thresholds,
            started_at=now,
            updated_at=now,
        )
        self._sessions[monitoring_session_id] = record
        self._events[monitoring_session_id] = []
        return record

    def get(self, monitoring_session_id: str) -> MonitoringSessionRecord | None:
        return self._sessions.get(monitoring_session_id)

    def update(self, record: MonitoringSessionRecord) -> MonitoringSessionRecord:
        self._sessions[record.monitoring_session_id] = record
        return record

    def append_event(self, event: MonitoringEvent) -> None:
        self._events.setdefault(event.monitoring_session_id, []).append(event)

    def list_events(self, monitoring_session_id: str) -> Sequence[MonitoringEvent]:
        return tuple(self._events.get(monitoring_session_id, ()))


_STATUS_TRANSITION_EVENT = {
    MonitoringStatus.WARNING: AuditEvent.MONITORING_WARNING,
    MonitoringStatus.REAUTH_REQUIRED: AuditEvent.MONITORING_REAUTH_REQUIRED,
    MonitoringStatus.REVOKED: AuditEvent.MONITORING_REVOKED,
}


class MonitoringSessionNotFoundError(Exception):
    def __init__(self, monitoring_session_id: str) -> None:
        self.monitoring_session_id = monitoring_session_id
        super().__init__(f"no monitoring session '{monitoring_session_id}'")


class MonitoringService:
    def __init__(
        self,
        repository: MonitoringRepository,
        device_repository: DeviceRepository,
        session_repository: SessionRepository,
        risk_engine: RiskEngine | None = None,
        audit_service: AuditLogService | None = None,
        lifecycle_lookup: LifecycleLookup | None = None,
        thresholds: MonitoringThresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        self._repository = repository
        self._devices = device_repository
        self._sessions = session_repository
        self._risk_engine = risk_engine or RiskEngine()
        self._audit = audit_service
        self._lifecycle_lookup = lifecycle_lookup
        self._default_thresholds = thresholds

    def get_owner(self, monitoring_session_id: str) -> int | None:
        """Cheap, side-effect-free ownership lookup for routers to use
        before performing a mutating or informational operation (e.g.
        `/stop`, `/events`) — deliberately separate from `refresh()`,
        which re-evaluates risk/decay state and is not meant to be
        called just to check who owns a session."""
        record = self._repository.get(monitoring_session_id)
        return record.user_id if record is not None else None


    # ------------------------------------------------------------------
    # LOGIN -> FACE VERIFIED -> MONITORING SESSION STARTED
    # ------------------------------------------------------------------
    def start(
        self,
        user_id: int,
        device_id: str,
        session_id: str,
        face_confidence: float,
        intent_id: int | None = None,
        now: datetime | None = None,
    ) -> MonitoringSnapshot:
        """Begin a continuous-monitoring session. Callers must have
        already obtained a successful face verification — this method
        does not itself verify identity (that stays in
        `authentication.face_auth`); it only starts *watching*."""
        now = now or datetime.now(timezone.utc)
        record = self._repository.create(
            user_id, device_id, session_id, intent_id, self._default_thresholds, now
        )
        snapshot = self._evaluate(
            record,
            face_present=True,
            face_confidence=face_confidence,
            liveness=True,
            expression_hint=None,
            failure_this_tick=False,
            now=now,
        )
        self._repository.append_event(
            MonitoringEvent(record.monitoring_session_id, "started", snapshot)
        )
        if self._audit is not None:
            self._audit.record(
                AuditEvent.MONITORING_STARTED,
                "success",
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                timestamp=now,
            )
        return snapshot

    # ------------------------------------------------------------------
    # Heartbeat: re-evaluate derived security telemetry
    # ------------------------------------------------------------------
    def heartbeat(
        self,
        monitoring_session_id: str,
        face_present: bool,
        face_confidence: float | None,
        liveness: bool,
        expression_hint: str | None = None,
        camera_available: bool = True,
        now: datetime | None = None,
    ) -> MonitoringSnapshot:
        record = self._repository.get(monitoring_session_id)
        if record is None:
            raise MonitoringSessionNotFoundError(monitoring_session_id)
        now = now or datetime.now(timezone.utc)

        face_ok = (
            camera_available
            and face_present
            and liveness
            and (face_confidence is None or face_confidence >= IDENTITY_MATCH_THRESHOLD)
        )
        snapshot = self._evaluate(
            record,
            face_present=face_present,
            face_confidence=face_confidence,
            liveness=liveness,
            expression_hint=expression_hint,
            failure_this_tick=not face_ok,
            camera_available=camera_available,
            now=now,
        )
        self._repository.append_event(
            MonitoringEvent(monitoring_session_id, "heartbeat", snapshot)
        )
        self._maybe_audit_transition(record, snapshot, now)
        return snapshot

    # ------------------------------------------------------------------
    # Read-only refresh: re-derive status from CURRENT device/session/
    # risk state without a new face reading (e.g. for a plain GET, or
    # for detecting an admin-side revoke between heartbeats).
    # ------------------------------------------------------------------
    def refresh(self, monitoring_session_id: str, now: datetime | None = None) -> MonitoringSnapshot:
        record = self._repository.get(monitoring_session_id)
        if record is None:
            raise MonitoringSessionNotFoundError(monitoring_session_id)
        now = now or datetime.now(timezone.utc)
        return self._evaluate(
            record,
            face_present=True,
            face_confidence=None,
            liveness=True,
            expression_hint=None,
            failure_this_tick=False,
            persist_failure_counter=False,
            now=now,
        )

    def stop(self, monitoring_session_id: str, now: datetime | None = None) -> None:
        record = self._repository.get(monitoring_session_id)
        if record is None:
            raise MonitoringSessionNotFoundError(monitoring_session_id)
        now = now or datetime.now(timezone.utc)
        record.stopped = True
        record.updated_at = now
        self._repository.update(record)
        snapshot = self._evaluate(
            record, face_present=True, face_confidence=None, liveness=True,
            expression_hint=None, failure_this_tick=False, persist_failure_counter=False, now=now,
        )
        self._repository.append_event(MonitoringEvent(monitoring_session_id, "stopped", snapshot))
        if self._audit is not None:
            self._audit.record(
                AuditEvent.MONITORING_TERMINATED,
                "success",
                user_id=record.user_id,
                session_id=record.session_id,
                device_id=record.device_id,
                timestamp=now,
            )

    def list_events(self, monitoring_session_id: str) -> Sequence[MonitoringEvent]:
        return self._repository.list_events(monitoring_session_id)

    # ------------------------------------------------------------------
    # PHASE 4: let other subsystems (policy/decrypt/encrypt routers)
    # report a denied request against this monitoring session, so
    # "repeated denied requests" becomes a real, accumulating risk
    # signal rather than something only this module can see.
    # ------------------------------------------------------------------
    def report_denied_request(
        self, monitoring_session_id: str, now: datetime | None = None
    ) -> MonitoringSnapshot:
        record = self._repository.get(monitoring_session_id)
        if record is None:
            raise MonitoringSessionNotFoundError(monitoring_session_id)
        now = now or datetime.now(timezone.utc)
        record.repeated_denied_requests += 1
        snapshot = self._evaluate(
            record, face_present=True, face_confidence=None, liveness=True,
            expression_hint=None, failure_this_tick=False, now=now,
        )
        self._repository.append_event(
            MonitoringEvent(monitoring_session_id, "denied_request", snapshot)
        )
        self._maybe_audit_transition(record, snapshot, now)
        return snapshot

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------
    def _evaluate(
        self,
        record: MonitoringSessionRecord,
        *,
        face_present: bool,
        face_confidence: float | None,
        liveness: bool,
        expression_hint: str | None,
        failure_this_tick: bool,
        now: datetime,
        persist_failure_counter: bool = True,
        camera_available: bool = True,
    ) -> MonitoringSnapshot:
        thresholds = record.thresholds
        warnings: list[str] = []

        # -- Continuous authorization: device / session / re-auth --
        device_status = self._devices.get_status(record.device_id)
        session_state = self._sessions.get(record.session_id)

        device_revoked = device_status.revoked
        session_revoked = session_state.revoked if session_state is not None else False
        session_expired = (
            session_state is not None and now > session_state.expires_at
        )
        session_version = session_state.version if session_state is not None else 1

        # A fresh re-authorization (session.refresh -> version bump)
        # clears any accumulated face-failure streak: it is exactly
        # the "reauthenticate" step-up this module would otherwise be
        # demanding on its own.
        if persist_failure_counter:
            failures = record.consecutive_face_failures + 1 if failure_this_tick else 0
        else:
            # Read-only refresh (GET / stop): don't perturb the
            # accumulated streak, just re-derive status from it plus
            # whatever changed externally (device/session repos).
            failures = record.consecutive_face_failures

        # -- Lifecycle (optional — only if this monitoring session is
        # scoped to a specific intent) --
        current_lifecycle = None
        if record.intent_id is not None and self._lifecycle_lookup is not None:
            current_lifecycle = self._lifecycle_lookup.current_lifecycle_state(record.intent_id)

        # -- Risk (reuses the existing weighted risk engine). Folds in
        # the "repeated denied requests" counter other routers report
        # via `report_denied_request`, and treats an already-revoked
        # device/session as an outright critical signal. --
        risk = self._risk_engine.assess(
            RiskFactors(
                face_confidence=face_confidence,
                device_mismatch=device_revoked,
                session_expired=session_expired,
                repeated_face_failures=failures,
                repeated_denied_requests=record.repeated_denied_requests,
                revoked_device_or_session=device_revoked or session_revoked,
            )
        )

        # -- Determine status. PHASE 4 mapping:
        #      LOW      -> NORMAL   (MonitoringStatus.ACTIVE)
        #      MEDIUM   -> WARNING
        #      HIGH     -> REAUTHENTICATION / RESTRICTED
        #      CRITICAL -> REVOCATION / CRYPTO BLOCK
        #    Explicit device/session facts (already revoked/expired)
        #    always win outright, ahead of the risk score. --
        already_revoked = record.status is MonitoringStatus.REVOKED
        if device_revoked or session_revoked or session_expired or already_revoked:
            status = MonitoringStatus.REVOKED
            if device_revoked:
                warnings.append("device revoked")
            if session_revoked:
                warnings.append("session revoked")
            if session_expired:
                warnings.append("session expired")
        elif failures >= thresholds.invalidate_after:
            status = MonitoringStatus.REVOKED
            warnings.append(
                f"{failures} consecutive face-verification failures — authorization invalidated"
            )
        elif risk.level is RiskLevel.CRITICAL:
            status = MonitoringStatus.REVOKED
            warnings.append(f"critical risk score ({risk.score}) — authorization revoked")
        elif failures >= thresholds.reauth_required_after:
            status = MonitoringStatus.REAUTH_REQUIRED
            warnings.append(f"{failures} consecutive face-verification failures — reauthentication required")
        elif risk.level is RiskLevel.HIGH:
            status = MonitoringStatus.REAUTH_REQUIRED
            warnings.append(f"elevated risk score ({risk.score}) — reauthentication required")
        elif failures >= thresholds.risk_increase_after:
            status = MonitoringStatus.WARNING
            warnings.append(f"{failures} consecutive face-verification failures — risk increased")
        elif failures >= thresholds.warning_after:
            status = MonitoringStatus.WARNING
            warnings.append("face verification failed once — monitoring closely")
        elif risk.level is RiskLevel.MEDIUM:
            status = MonitoringStatus.WARNING
            warnings.append(f"elevated risk score ({risk.score})")
        else:
            status = MonitoringStatus.ACTIVE

        # -- Enact revocation. Only act (and only audit) the FIRST time
        # a session crosses into REVOKED — everything after that is
        # already revoked and re-acting/re-logging on every subsequent
        # heartbeat would be exactly the "unbounded audit logging"
        # PHASE 4 says to avoid. --
        newly_revoked = status is MonitoringStatus.REVOKED and not already_revoked
        if newly_revoked and persist_failure_counter:
            if not session_revoked:
                try:
                    self._sessions.revoke(record.session_id)
                    if self._audit is not None:
                        self._audit.record(
                            AuditEvent.SESSION_REVOKED,
                            "revoked",
                            user_id=record.user_id,
                            session_id=record.session_id,
                            device_id=record.device_id,
                            risk=risk.level.value,
                            reason="; ".join(warnings) or None,
                            timestamp=now,
                        )
                except KeyError:
                    pass
            # A CRITICAL risk score (as opposed to a plain expired
            # session or repeated face failures) additionally revokes
            # the device itself — the strongest of the "revoked
            # device/session" signals this module can produce on its
            # own, without a human administrator acting.
            if risk.level is RiskLevel.CRITICAL and not device_revoked and not record.device_revoked_by_monitoring:
                self._devices.revoke(record.device_id)
                record.device_revoked_by_monitoring = True
                if self._audit is not None:
                    self._audit.record(
                        AuditEvent.DEVICE_REVOKED,
                        "revoked",
                        user_id=record.user_id,
                        session_id=record.session_id,
                        device_id=record.device_id,
                        risk=risk.level.value,
                        reason="; ".join(warnings) or None,
                        timestamp=now,
                    )

        # -- Audit-chain integrity: a system-wide COMPROMISED signal,
        # independent of this (or any) session's own status. Checked
        # at most once per session per revocation-worthy escalation,
        # and the alert itself is only ever written once per session
        # (`audit_tamper_alerted`) — never re-verified/re-logged every
        # heartbeat, which is what keeps this bounded rather than
        # recursive (the alert entry we write does NOT re-trigger
        # another integrity check on this same call). --
        audit_compromised = False
        if self._audit is not None:
            integrity = self._audit.verify_integrity()
            audit_compromised = not integrity.valid
            if audit_compromised and persist_failure_counter and not record.audit_tamper_alerted:
                record.audit_tamper_alerted = True
                self._audit.record(
                    AuditEvent.AUDIT_TAMPER_DETECTED,
                    "compromised",
                    user_id=record.user_id,
                    session_id=record.session_id,
                    device_id=record.device_id,
                    reason=integrity.reason,
                    timestamp=now,
                )

        security_state = derive_security_posture(status, audit_compromised)

        # Explicit per-tick identity result — computed from the SAME
        # facts (face_present/face_confidence/liveness/camera_available)
        # that decided `failure_this_tick` above, never re-derived from
        # `status` (which is coarser and also reflects device/session/
        # risk facts unrelated to this one identity check).
        identity_state = derive_identity_state(
            face_present=face_present,
            face_match_confidence=face_confidence,
            liveness=liveness,
            camera_available=camera_available,
        )
        if identity_state is IdentityCheckState.IDENTITY_MISMATCH:
            warnings.append("detected face does not match enrolled identity")
        elif identity_state is IdentityCheckState.CAMERA_UNAVAILABLE:
            warnings.append("camera unavailable — identity could not be checked")

        authorization_valid = status not in (MonitoringStatus.REVOKED,)
        current_authorization_state = "valid" if authorization_valid else "invalid"

        state_hash = compute_monitoring_state_hash(
            monitoring_session_id=record.monitoring_session_id,
            current_user=record.user_id,
            current_device=record.device_id,
            current_session=record.session_id,
            status=status,
            current_lifecycle=current_lifecycle,
            current_risk=risk.level,
            current_authorization_state=current_authorization_state,
            session_version=session_version,
        )

        if persist_failure_counter:
            record.consecutive_face_failures = failures
            record.status = status
            record.updated_at = now
            self._repository.update(record)

        return MonitoringSnapshot(
            monitoring_session_id=record.monitoring_session_id,
            current_user=record.user_id,
            current_device=record.device_id,
            current_session=record.session_id,
            status=status,
            face_present=face_present,
            face_match_confidence=face_confidence,
            liveness=liveness,
            current_intent=record.intent_id,
            current_lifecycle=current_lifecycle,
            current_risk=risk.level,
            risk_score=risk.score,
            current_authorization_state=current_authorization_state,
            authorization_state_hash=state_hash,
            consecutive_face_failures=failures,
            warnings=tuple(warnings),
            expression_hint=expression_hint,
            timestamp=now,
            security_state=security_state,
            identity_state=identity_state,
        )

    def _maybe_audit_transition(
        self, record: MonitoringSessionRecord, snapshot: MonitoringSnapshot, now: datetime
    ) -> None:
        if self._audit is None:
            return
        event_name = _STATUS_TRANSITION_EVENT.get(snapshot.status)
        if event_name is None:
            return
        self._audit.record(
            event_name,
            snapshot.status.value,
            user_id=record.user_id,
            session_id=record.session_id,
            device_id=record.device_id,
            risk=snapshot.current_risk.value,
            reason="; ".join(snapshot.warnings) or None,
            timestamp=now,
        )
