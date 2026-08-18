from __future__ import annotations

import base64

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.database import Database

from audit.events import AuditEvent
from audit.service import AuditLogService
from authentication.face_auth import FaceAuthService
from authorization import (
    AuthorizationError,
    AuthorizationService,
    DeviceRevokedError,
    LifecycleRejectedError,
    PolicyRejectedError,
    SessionInvalidError,
)
from crypto.aes_gcm import EncryptionEnvelope
from crypto.service import AuthorizationStateMismatchError, EncryptionService, IntentHashMismatchError
from database.session import get_db
from intent.schema import CID
from policy.risk import FACE_CONFIDENCE_THRESHOLD, RiskAction, RiskEngine, RiskFactors

from ..dependencies import (
    get_audit_service,
    get_authorization_service,
    get_current_user,
    get_encryption_service,
    get_face_auth_service,
    get_risk_engine,
)
from ..rbac import require_owner_or_admin
from ..repositories import EncryptionRecordRepository, IntentRepository
from ..schemas import DecryptRequest, DecryptResponse

router = APIRouter(prefix="/api/decrypt", tags=["decryption"])

_AUTHZ_STATUS = {
    DeviceRevokedError: status.HTTP_403_FORBIDDEN,
    SessionInvalidError: status.HTTP_401_UNAUTHORIZED,
    LifecycleRejectedError: status.HTTP_409_CONFLICT,
    PolicyRejectedError: status.HTTP_403_FORBIDDEN,
}


@router.post("", response_model=DecryptResponse)
def decrypt(
    payload: DecryptRequest,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
    encryption_service: EncryptionService = Depends(get_encryption_service),
    face_auth: FaceAuthService = Depends(get_face_auth_service),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
    audit: AuditLogService = Depends(get_audit_service),
) -> DecryptResponse:
    try:
        cid = CID(**payload.cid.model_dump())
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    record_repo = EncryptionRecordRepository(db)
    record = record_repo.get(payload.record_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "encryption record not found")
    require_owner_or_admin(user, record.created_by, action="decrypt")

    intent_repo = IntentRepository(db)
    intent_row = intent_repo.get_by_hash(record.intent_hash)
    if intent_row is None:
        # Should not happen in practice (every EncryptionRecord is
        # created from an Intent), but fail closed rather than assume.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "intent for this record not found")

    try:
        quantum_key_bytes = bytes.fromhex(payload.quantum_key_hex)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "malformed quantum_key_hex") from exc

    envelope = EncryptionEnvelope(
        ciphertext=record.ciphertext,
        nonce=record.nonce,
        auth_tag=record.auth_tag,
        intent_hash=record.intent_hash,
        created_at=record.created_at,
        authorization_state_hash=record.authorization_state_hash,
    )

    # -- Mandatory face verification gate, ahead of risk assessment.
    # A missing or failed probe stops the request outright, regardless
    # of what risk assessment would otherwise decide. This is
    # additive: the risk engine below is unchanged and still runs its
    # own (stricter, confidence-threshold-based) step-up check. --
    if payload.face_descriptor is None:
        audit.record(
            AuditEvent.FACE_VERIFY_FAILURE,
            "rejected",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
            resource=cid.resource,
            reason="face descriptor missing",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "face verification required")

    face_result = face_auth.verify(user.user_id, payload.face_descriptor)
    if not face_result.verified:
        audit.record(
            AuditEvent.FACE_VERIFY_FAILURE,
            "rejected",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
            resource=cid.resource,
            reason="face verification failed",
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "face verification failed")
    audit.record(
        AuditEvent.FACE_VERIFY_SUCCESS,
        "success",
        user_id=user.user_id,
        intent_hash=record.intent_hash,
        device_id=cid.device_id,
        session_id=cid.session_id,
    )

    # -- Risk assessment runs before the decrypt attempt: a High
    # result rejects regardless of whether the crypto would otherwise
    # succeed. Face auth here is identity confidence only. Risk is
    # deliberately NOT folded into the cryptographic binding below —
    # see authorization/state.py module docstring for why. --
    face_confidence = face_result.confidence
    risk = risk_engine.assess(RiskFactors(face_confidence=face_confidence))

    if risk.action in (RiskAction.REJECT, RiskAction.REVOKE):
        audit.record(
            AuditEvent.RISK_DENIED,
            "rejected",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            risk=risk.level.value,
            reason=f"risk score {risk.score} ({risk.level.value})",
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "request rejected: high risk assessment")

    if risk.action is RiskAction.REQUIRE_FACE_VERIFICATION and (
        face_confidence is None or face_confidence < FACE_CONFIDENCE_THRESHOLD
    ):
        audit.record(
            "decrypt_requires_face_verification",
            "step_up_required",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            risk=risk.level.value,
            reason="face re-verification required (medium risk)",
        )
        raise HTTPException(
            status.HTTP_428_PRECONDITION_REQUIRED, "face re-verification required"
        )

    # -- Explicit continuous-authorization check: device, session,
    # lifecycle, and policy, all evaluated against CURRENT state (not
    # whatever was true when this record was encrypted). --
    try:
        decision = authorization_service.authorize(
            cid,
            intent_id=intent_row.id,
            intent_lifecycle_state=intent_row.lifecycle_state,
            user_id=user.user_id,
            requesting_user_role=user.role,
        )
    except PolicyRejectedError as exc:
        audit.record(
            AuditEvent.POLICY_DENIED,
            "rejected",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            reason=str(exc),
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except AuthorizationError as exc:
        audit.record(
            AuditEvent.DECRYPT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            reason=f"{type(exc).__name__}: {exc}",
        )
        raise HTTPException(_AUTHZ_STATUS.get(type(exc), status.HTTP_403_FORBIDDEN), str(exc)) from exc

    # -- Recreate -> canonicalize -> hash -> compare (intent) ->
    # compare (authorization state) -> HKDF -> decrypt --
    try:
        plaintext = encryption_service.decrypt_for_intent(
            envelope,
            record.intent_hash,
            quantum_key_bytes,
            recreated_cid=cid,
            current_authorization_state_hash=decision.authorization_state_hash,
        )
    except IntentHashMismatchError as exc:
        audit.record(
            AuditEvent.DECRYPT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            reason=f"intent mismatch: {exc}",
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except AuthorizationStateMismatchError as exc:
        audit.record(
            AuditEvent.DECRYPT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            reason=f"authorization state mismatch: {exc}",
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except InvalidTag as exc:
        audit.record(
            AuditEvent.DECRYPT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=record.intent_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            reason="authentication tag mismatch",
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "decryption failed: authentication tag mismatch"
        ) from exc

    audit.record(
        AuditEvent.DECRYPT_SUCCESS,
        "success",
        user_id=user.user_id,
        intent_hash=record.intent_hash,
        device_id=cid.device_id,
        session_id=cid.session_id,
        operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
        resource=cid.resource,
        risk=risk.level.value,
    )

    return DecryptResponse(
        plaintext_base64=base64.b64encode(plaintext).decode("ascii"),
        risk_level=risk.level.value,
        risk_score=risk.score,
        authorization_state_hash=decision.authorization_state_hash,
        intent_lifecycle_state=intent_row.lifecycle_state.value,
    )
