from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel

Operation = Literal["encrypt", "decrypt", "read", "write", "share", "revoke"]


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    # Self-registration may only ever pick between the two ordinary user
    # tiers — never ADMIN. Enforced twice: the Literal below rejects any
    # other value at the wire/validation layer, and api/routers/auth.py
    # re-checks against rbac.SELF_REGISTERABLE_ROLES before it's used, so
    # a future edit to this schema alone can't silently open the door to
    # self-service admin. Admin accounts only ever come from
    # scripts/seed_admin.py or an existing admin's PUT /api/users/{id}/role.
    role: Optional[Literal["USER_LEVEL_1", "USER_LEVEL_2"]] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    token: str
    user_id: int
    username: str
    role: str


class CIDRequest(BaseModel):
    """Wire format for a CID — mirrors intent.schema.CID exactly."""

    sender: str
    receiver: str
    purpose: str
    resource: str
    operation: Operation
    device_id: str
    session_id: str
    valid_from: datetime
    valid_until: datetime
    classification: Optional[str] = None
    department: Optional[str] = None
    project: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class CreateIntentRequest(BaseModel):
    cid: CIDRequest
    reason: str = "initial creation"


class IntentResponse(BaseModel):
    intent_id: int
    version_number: int
    intent_hash: str
    lifecycle_state: str


class IntentSummaryResponse(BaseModel):
    """One row of `GET /api/intent` — a lightweight listing for the
    Intent History / Admin approval-queue views, distinct from
    `IntentResponse` (the create/transition result) since a listing
    doesn't have a single "version_number just changed" to report."""

    intent_id: int
    intent_hash: str
    lifecycle_state: str
    created_by: int
    created_at: Optional[datetime] = None


class TransitionIntentRequest(BaseModel):
    target_state: str
    reason: str


class ValidateIntentRequest(BaseModel):
    cid: CIDRequest
    intent_id: Optional[int] = None


class PolicyOutcomeResponse(BaseModel):
    rule_name: str
    passed: bool
    reason: Optional[str] = None


class IdentityCheckResponse(BaseModel):
    checked: bool
    verified: Optional[bool] = None
    confidence: Optional[float] = None
    reason: Optional[str] = None


class DeviceCheckResponse(BaseModel):
    device_id: str
    revoked: bool


class SessionCheckResponse(BaseModel):
    session_id: str
    known: bool
    valid: bool
    reason: Optional[str] = None


class IntentValidationResponse(BaseModel):
    valid: bool
    canonicalized_intent: dict[str, Any]
    intent_hash: str
    resource: str
    operation: str
    purpose: str
    valid_from: datetime
    valid_until: datetime
    policy_passed: bool
    policy_outcomes: list[PolicyOutcomeResponse]
    risk_score: float
    risk_level: str
    identity: IdentityCheckResponse
    device: DeviceCheckResponse
    session: SessionCheckResponse
    current_lifecycle: str
    approval_eligible: bool
    reason: Optional[str] = None


class EncryptRequest(BaseModel):
    intent_id: int
    cid: CIDRequest
    plaintext_base64: str
    quantum_key_hex: str
    face_descriptor: Optional[list[float]] = None


class EncryptResponse(BaseModel):
    record_id: int
    intent_id: int
    intent_hash: str
    ciphertext_hex: str
    nonce_hex: str
    auth_tag_hex: str
    authorization_state_hash: str
    intent_lifecycle_state: str


class DecryptRequest(BaseModel):
    record_id: int
    cid: CIDRequest
    quantum_key_hex: str
    face_descriptor: Optional[list[float]] = None


class DecryptResponse(BaseModel):
    plaintext_base64: str
    risk_level: str
    risk_score: float
    authorization_state_hash: str
    intent_lifecycle_state: str


class QuantumGenerateKeyRequest(BaseModel):
    n_qubits: int = 256
    eavesdrop_prob: float = 0.0


class QuantumGenerateKeyResponse(BaseModel):
    quantum_key_hex: str
    qber: float
    sifted_bits: int
    session_aborted: bool


class AuditLogEntryResponse(BaseModel):
    timestamp: datetime
    user_id: Optional[int]
    action: str
    intent_hash: Optional[str]
    result: str
    current_log_hash: str
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    resource: Optional[str] = None
    operation: Optional[str] = None
    risk: Optional[str] = None
    reason: Optional[str] = None


class AuditVerifyResponse(BaseModel):
    valid: bool
    first_invalid_index: Optional[int]
    reason: Optional[str]
    security_state: Optional[str] = None


class RiskAssessRequest(BaseModel):
    qber: float = 0.0
    failed_login_count: int = 0
    face_confidence: Optional[float] = None
    device_mismatch: bool = False
    session_expired: bool = False
    rapid_access_attempts: int = 0
    policy_failure_count: int = 0
    # -- Phase 4: continuous risk / behavioral signals --
    unusual_resource_access: bool = False
    unusual_operation: bool = False
    sensitive_resource_access: bool = False
    repeated_denied_requests: int = 0
    repeated_face_failures: int = 0
    device_changed: bool = False
    session_changed: bool = False
    intent_changed: bool = False
    lifecycle_changed: bool = False
    authorization_changed: bool = False
    revoked_device_or_session: bool = False


class MLRiskFactorResponse(BaseModel):
    feature: str
    value: float
    weight: float
    contribution: float


class RiskAssessResponse(BaseModel):
    # -- Deterministic engine (policy.risk.RiskEngine) — this is the
    # verdict that is actually enforced. --
    score: float
    level: str
    action: str
    # -- Advisory-only ML signal (policy.ml_risk.MLRiskModel). Never
    # the sole authority; see that module's docstring. A hand-specified
    # prototype model, not trained on real data. --
    ai_risk_probability: float
    ai_risk_level: str
    ai_top_factors: list[MLRiskFactorResponse]
    ai_model_note: str = (
        "Prototype/demo model: hand-specified logistic regression, not trained on "
        "real historical data. Advisory signal only — the deterministic score/level/"
        "action above is what is actually enforced."
    )


class PolicyRequest(BaseModel):
    name: str
    rule_type: str
    config: dict[str, Any]
    active: bool = True


class PolicyResponse(BaseModel):
    id: int
    name: str
    rule_type: str
    config: dict[str, Any]
    active: bool


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str


class UpdateUserRoleRequest(BaseModel):
    role: str


class FaceEnrollRequest(BaseModel):
    descriptor: list[float]


class FaceVerifyRequest(BaseModel):
    descriptor: list[float]


class FaceVerifyResponse(BaseModel):
    verified: bool
    confidence: float
    distance: float


class FaceStatusResponse(BaseModel):
    enrolled: bool


class DeviceStatusResponse(BaseModel):
    device_id: str
    revoked: bool


class SessionStatusResponse(BaseModel):
    session_id: str
    device_id: str
    revoked: bool
    expires_at: datetime
    version: int


class RefreshSessionRequest(BaseModel):
    device_id: str
    ttl_minutes: int = 60


class MonitoringStartRequest(BaseModel):
    """Begin a continuous-monitoring session. `face_confidence` must
    come from a face verification the caller already performed
    (e.g. `/api/face/verify`) — this endpoint does not itself verify
    identity, it starts watching a session that has already passed
    LOGIN -> FACE VERIFIED."""

    device_id: str
    session_id: str
    face_confidence: float
    intent_id: Optional[int] = None


class MonitoringHeartbeatRequest(BaseModel):
    monitoring_session_id: str
    face_present: bool
    face_match_confidence: Optional[float] = None
    liveness: bool = True
    # False when the client could not obtain a camera frame at all
    # this tick (permission denied, camera disconnected, tab hidden,
    # etc.) — distinct from `face_present=False`, which means the
    # camera worked but no face was found in the frame.
    camera_available: bool = True
    # Supporting telemetry only — see monitoring/service.py. Never
    # gates a decision and never implies malicious behavior.
    expression_hint: Optional[str] = None


class MonitoringSnapshotResponse(BaseModel):
    monitoring_session_id: str
    current_user: int
    current_device: str
    current_session: str
    status: str
    face_present: bool
    face_match_confidence: Optional[float] = None
    liveness: bool
    current_intent: Optional[int] = None
    current_lifecycle: Optional[str] = None
    current_risk: str
    risk_score: float
    current_authorization_state: str
    authorization_state_hash: str
    consecutive_face_failures: int
    warnings: list[str] = []
    expression_hint: Optional[str] = None
    timestamp: datetime
    security_state: str = "normal"
    identity_state: str = "no_face"


class MonitoringEventResponse(BaseModel):
    event_type: str
    snapshot: MonitoringSnapshotResponse


class AuthorizationStateRequest(BaseModel):
    cid: CIDRequest
    intent_id: int


class AuthorizationStateResponse(BaseModel):
    """The CURRENT authorization/security state for a given
    (CID, intent) pair — same fields the crypto layer binds into an
    active session, surfaced for inspection/demo purposes."""

    authorized: bool
    authorization_state_hash: Optional[str] = None
    intent_lifecycle_state: Optional[str] = None
    policy_decision_signature: Optional[str] = None
    session_version: Optional[int] = None
    device_id: str
    session_id: str
    rejection_reason: Optional[str] = None
