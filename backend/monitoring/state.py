"""
Continuous-monitoring state.

This module defines the *live monitoring* snapshot — the thing a
polling client (the UI) reads every heartbeat — as distinct from
`authorization.state.SecurityState`, which is the narrower snapshot
bound into a single encrypt/decrypt cryptographic session for one
specific (CID, intent) pair.

Monitoring is session-wide, not operation-specific: it runs
continuously from the moment face verification succeeds at login
until logout/revocation, independent of whether the user ever
encrypts or decrypts anything in between. So its "authorization state
hash" is a coarser fingerprint of device/session/risk/face status —
useful for the UI to detect *any* change worth re-rendering for — and
is never used as HKDF/AAD material. The actual crypto-binding hash
computed by `authorization.state.compute_authorization_state_hash`
is untouched by this module.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from policy.risk import RiskLevel

_STATE_HASH_ALGORITHM = "sha256"
_MONITORING_PROTOCOL_TAG = "CIPHERQ-MONITORING-STATE-v1"


class MonitoringStatus(str, Enum):
    """Overall status shown by the UI's live monitoring badge."""

    ACTIVE = "active"                # everything nominal
    WARNING = "warning"              # a temporary anomaly (e.g. one face failure)
    REAUTH_REQUIRED = "reauth_required"  # repeated anomalies — step-up needed
    REVOKED = "revoked"              # authorization invalidated; crypto blocked


class IdentityCheckState(str, Enum):
    """Explicit result of one continuous-monitoring identity check.

    This is deliberately separate from — and more granular than —
    `MonitoringStatus`: several different identity-check outcomes can
    map to the same overall monitoring status (e.g. both a single
    `IDENTITY_MISMATCH` and a single `NO_FACE` tick are, on their own,
    still just `MonitoringStatus.WARNING`). Nothing here is silently
    treated as a successful re-authentication.
    """

    IDENTITY_CONFIRMED = "identity_confirmed"    # face detected, matches enrolled identity
    IDENTITY_MISMATCH = "identity_mismatch"       # face detected, does NOT match
    NO_FACE = "no_face"                           # no face detected in frame
    LIVENESS_UNCERTAIN = "liveness_uncertain"      # face matched but liveness/presence unclear
    CAMERA_UNAVAILABLE = "camera_unavailable"      # client reported no camera/frame at all


# Confidence at/above this is treated as a positive identity match.
# Shared by the heartbeat's pass/fail decision and by the derived
# `identity_state` shown to the UI, so the two never disagree.
IDENTITY_MATCH_THRESHOLD = 0.5


def derive_identity_state(
    face_present: bool,
    face_match_confidence: float | None,
    liveness: bool,
    camera_available: bool = True,
) -> IdentityCheckState:
    """Pure decision function — no side effects — turning one tick's
    raw telemetry into an explicit, UI-facing identity state."""
    if not camera_available:
        return IdentityCheckState.CAMERA_UNAVAILABLE
    if not face_present:
        return IdentityCheckState.NO_FACE
    if face_match_confidence is not None and face_match_confidence < IDENTITY_MATCH_THRESHOLD:
        return IdentityCheckState.IDENTITY_MISMATCH
    if not liveness:
        return IdentityCheckState.LIVENESS_UNCERTAIN
    return IdentityCheckState.IDENTITY_CONFIRMED


class SecurityPostureState(str, Enum):
    """PHASE 4 "SECURITY STATE": NORMAL / WARNING / COMPROMISED / REVOKED.

    Deliberately a *separate* enum from `MonitoringStatus` above and
    from `authorization.state.SecurityState` (the narrower, per-crypto
    -session snapshot bound into HKDF/AAD) — this is the coarse,
    system-facing posture the dashboard displays.

        NORMAL:      no significant security issue.
        WARNING:     suspicious but authorization remains active — the
                     session is still usable while it's watched more
                     closely (maps from MonitoringStatus.WARNING /
                     REAUTH_REQUIRED: reauthentication being demanded
                     is a form of "still active, but restricted", not
                     an integrity failure).
        COMPROMISED: a serious security *integrity* condition has been
                     detected — today, specifically, a broken/tampered
                     audit hash chain. This is intentionally NOT set
                     for ordinary per-session risk escalation: a risky
                     session gets REVOKED, not flagged as system-wide
                     COMPROMISED. Do not conflate "abnormal" with
                     "compromised" — most abnormal events resolve to
                     WARNING or REVOKED, never this.
        REVOKED:     this authorization/session/device is no longer
                     allowed; future encrypt/decrypt for it is
                     rejected before any crypto call executes.
    """

    NORMAL = "normal"
    WARNING = "warning"
    COMPROMISED = "compromised"
    REVOKED = "revoked"


_POSTURE_BY_MONITORING_STATUS: dict["MonitoringStatus", "SecurityPostureState"] = {
    MonitoringStatus.ACTIVE: SecurityPostureState.NORMAL,
    MonitoringStatus.WARNING: SecurityPostureState.WARNING,
    MonitoringStatus.REAUTH_REQUIRED: SecurityPostureState.WARNING,
    MonitoringStatus.REVOKED: SecurityPostureState.REVOKED,
}


def derive_security_posture(
    status: "MonitoringStatus", audit_compromised: bool = False
) -> SecurityPostureState:
    """COMPROMISED takes priority over everything else — a broken audit
    chain is a system-integrity fact, independent of what any one
    monitoring session's status currently says."""
    if audit_compromised:
        return SecurityPostureState.COMPROMISED
    return _POSTURE_BY_MONITORING_STATUS[status]


@dataclass(frozen=True)
class MonitoringThresholds:
    """Configurable face-failure thresholds.

    Failures are *consecutive* — any successful face+liveness check
    resets the counter to zero, so one transient failure never by
    itself compromises the session.
    """

    warning_after: int = 1          # >=1 consecutive failure -> WARNING
    risk_increase_after: int = 2    # >=2 consecutive failures -> WARNING + elevated risk
    reauth_required_after: int = 3  # >=3 consecutive failures -> REAUTH_REQUIRED
    invalidate_after: int = 5       # >=5 consecutive failures -> REVOKED (authorization invalidated)

    def __post_init__(self) -> None:
        ordering = (
            self.warning_after,
            self.risk_increase_after,
            self.reauth_required_after,
            self.invalidate_after,
        )
        if list(ordering) != sorted(ordering) or any(v < 1 for v in ordering):
            raise ValueError(
                "MonitoringThresholds must be a non-decreasing sequence of "
                "positive integers: warning_after <= risk_increase_after "
                "<= reauth_required_after <= invalidate_after"
            )


DEFAULT_THRESHOLDS = MonitoringThresholds()


@dataclass(frozen=True)
class MonitoringSnapshot:
    """Everything the continuous-monitoring UI needs to render, every
    heartbeat. Every field here is a coarse status flag or a derived
    identity result — never raw biometric/video data.
    """

    monitoring_session_id: str
    current_user: int
    current_device: str
    current_session: str
    status: MonitoringStatus

    face_present: bool
    face_match_confidence: float | None
    liveness: bool

    current_intent: int | None
    current_lifecycle: str | None

    current_risk: RiskLevel
    risk_score: float

    current_authorization_state: str  # "valid" | "invalid"
    authorization_state_hash: str

    consecutive_face_failures: int
    warnings: tuple[str, ...] = field(default_factory=tuple)
    # Supporting telemetry only (see authentication.face_auth /
    # monitoring.service docstrings) — never gates a decision on its
    # own and never implies malicious intent.
    expression_hint: str | None = None

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # PHASE 4: coarse NORMAL/WARNING/COMPROMISED/REVOKED posture,
    # derived from `status` (plus system-wide audit integrity — see
    # `derive_security_posture`). Defaults to the value implied by
    # `status` alone if the caller doesn't override it.
    security_state: SecurityPostureState = SecurityPostureState.NORMAL

    # Explicit per-tick identity-check result (see `IdentityCheckState`)
    # — never silently folded into `status` alone, so the UI/tests can
    # distinguish "no face" from "wrong face" from "camera unavailable".
    identity_state: IdentityCheckState = IdentityCheckState.NO_FACE

    def as_dict(self) -> dict:
        return {
            "monitoring_session_id": self.monitoring_session_id,
            "current_user": self.current_user,
            "current_device": self.current_device,
            "current_session": self.current_session,
            "status": self.status.value,
            "security_state": self.security_state.value,
            "face_present": self.face_present,
            "face_match_confidence": self.face_match_confidence,
            "liveness": self.liveness,
            "current_intent": self.current_intent,
            "current_lifecycle": self.current_lifecycle,
            "current_risk": self.current_risk.value,
            "risk_score": self.risk_score,
            "current_authorization_state": self.current_authorization_state,
            "authorization_state_hash": self.authorization_state_hash,
            "consecutive_face_failures": self.consecutive_face_failures,
            "warnings": list(self.warnings),
            "expression_hint": self.expression_hint,
            "timestamp": self.timestamp.isoformat(),
            "identity_state": self.identity_state.value,
        }


def compute_monitoring_state_hash(
    *,
    monitoring_session_id: str,
    current_user: int,
    current_device: str,
    current_session: str,
    status: MonitoringStatus,
    current_lifecycle: str | None,
    current_risk: RiskLevel,
    current_authorization_state: str,
    session_version: int,
) -> str:
    """Fingerprint of the coarse monitoring-relevant facts, right now.

    Changing device/session identity, monitoring status, lifecycle,
    risk level, authorization validity, or the underlying auth
    session's version produces a different hash — which is exactly
    what lets the polling UI detect "something about continuous
    authorization changed" without re-deriving or comparing every
    field by hand.
    """
    payload = json.dumps(
        {
            "tag": _MONITORING_PROTOCOL_TAG,
            "monitoring_session_id": monitoring_session_id,
            "current_user": current_user,
            "current_device": current_device,
            "current_session": current_session,
            "status": status.value,
            "current_lifecycle": current_lifecycle,
            "current_risk": current_risk.value,
            "current_authorization_state": current_authorization_state,
            "session_version": session_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.new(_STATE_HASH_ALGORITHM, payload).hexdigest()
