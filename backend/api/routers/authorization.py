from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.database import Database

from audit.events import AuditEvent
from audit.service import AuditLogService
from authorization import AuthorizationError, AuthorizationService
from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository
from database.session import get_db
from intent.schema import CID

from ..dependencies import (
    get_audit_service,
    get_authorization_service,
    get_current_user,
    get_device_repository,
    get_intent_repository,
    get_session_repository,
)
from ..rbac import require_owner_or_admin, require_roles
from ..repositories import IntentRepository, MongoDeviceRepository
from ..schemas import (
    AuthorizationStateRequest,
    AuthorizationStateResponse,
    DeviceStatusResponse,
    RefreshSessionRequest,
    SessionStatusResponse,
)

router = APIRouter(prefix="/api/authorization", tags=["authorization"])


# ---------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------

@router.get("/devices/{device_id}", response_model=DeviceStatusResponse)
def get_device_status(
    device_id: str,
    user=Depends(get_current_user),
    devices: DeviceRepository = Depends(get_device_repository),
    device_owners: MongoDeviceRepository = Depends(get_device_repository),
) -> DeviceStatusResponse:
    owner = device_owners.get_owner(device_id)
    require_owner_or_admin(user, owner, action="view")
    status_row = devices.get_status(device_id)
    return DeviceStatusResponse(device_id=status_row.device_id, revoked=status_row.revoked)


@router.post(
    "/devices/{device_id}/revoke",
    response_model=DeviceStatusResponse,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def revoke_device(
    device_id: str,
    user=Depends(get_current_user),
    devices: DeviceRepository = Depends(get_device_repository),
    audit: AuditLogService = Depends(get_audit_service),
) -> DeviceStatusResponse:
    """Simulates a device being lost, stolen, or deprovisioned.
    Any subsequent encrypt/decrypt attempt from this device is
    rejected by `AuthorizationService` before any crypto call.
    Administrative operation — ADMIN only,
    regardless of who owns the device (see `require_roles` dependency
    above); a normal user can never revoke a device, including their
    own, through this endpoint."""
    status_row = devices.revoke(device_id)
    audit.record(
        AuditEvent.DEVICE_REVOKED, "revoked", user_id=user.user_id, device_id=device_id
    )
    return DeviceStatusResponse(device_id=status_row.device_id, revoked=status_row.revoked)


@router.post(
    "/devices/{device_id}/unrevoke",
    response_model=DeviceStatusResponse,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def unrevoke_device(
    device_id: str,
    user=Depends(get_current_user),
    devices: DeviceRepository = Depends(get_device_repository),
    audit: AuditLogService = Depends(get_audit_service),
) -> DeviceStatusResponse:
    status_row = devices.unrevoke(device_id)
    audit.record(
        AuditEvent.DEVICE_UNREVOKED, "unrevoked", user_id=user.user_id, device_id=device_id
    )
    return DeviceStatusResponse(device_id=status_row.device_id, revoked=status_row.revoked)


# ---------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------

@router.get("/sessions/{session_id}", response_model=SessionStatusResponse)
def get_session_status(
    session_id: str,
    user=Depends(get_current_user),
    sessions: SessionRepository = Depends(get_session_repository),
) -> SessionStatusResponse:
    session = sessions.get(session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    require_owner_or_admin(user, session.user_id, action="view")
    return SessionStatusResponse(
        session_id=session.session_id,
        device_id=session.device_id,
        revoked=session.revoked,
        expires_at=session.expires_at,
        version=session.version,
    )


@router.post(
    "/sessions/{session_id}/revoke",
    response_model=SessionStatusResponse,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def revoke_session(
    session_id: str,
    user=Depends(get_current_user),
    sessions: SessionRepository = Depends(get_session_repository),
    audit: AuditLogService = Depends(get_audit_service),
) -> SessionStatusResponse:
    """Simulates a session being logged out or terminated by an
    administrator. Any subsequent encrypt/decrypt using this session
    is rejected before any crypto call. Administrative operation —
    ADMIN only; a normal user cannot revoke
    even their own session through this endpoint (they simply stop
    using it / let it expire, or an administrator revokes it)."""
    try:
        session = sessions.revoke(session_id)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found") from exc
    audit.record(
        AuditEvent.SESSION_REVOKED,
        "revoked",
        user_id=user.user_id,
        session_id=session_id,
        device_id=session.device_id,
    )
    return SessionStatusResponse(
        session_id=session.session_id,
        device_id=session.device_id,
        revoked=session.revoked,
        expires_at=session.expires_at,
        version=session.version,
    )


@router.post("/sessions/{session_id}/refresh", response_model=SessionStatusResponse)
def refresh_session(
    session_id: str,
    payload: RefreshSessionRequest,
    user=Depends(get_current_user),
    sessions: SessionRepository = Depends(get_session_repository),
    audit: AuditLogService = Depends(get_audit_service),
    device_owners: MongoDeviceRepository = Depends(get_device_repository),
) -> SessionStatusResponse:
    """Establishes a fresh authorized session: un-revokes, extends
    expiry, and bumps the session's `version`. Because `version` is
    folded into the authorization state hash, this immediately
    invalidates any cryptographic session bound to the previous
    version — a fresh derivation is required going forward. If the
    session does not exist yet, it is created (and owned by the
    caller). A normal user may only refresh their own session; an
    admin role may refresh (re-authorize) any user's session."""
    existing = sessions.get(session_id)
    if existing is not None:
        require_owner_or_admin(user, existing.user_id, action="refresh")
        session = sessions.refresh(session_id, ttl=timedelta(minutes=payload.ttl_minutes))
    else:
        # A brand-new session must not be established against a device
        # that's already owned by a *different* user — otherwise user
        # B could bind a fresh session to user A's device_id and then
        # operate through it (the core authorization check only looks
        # at `device.revoked`, not who owns it, so an unrevoked device
        # with a mismatched owner would otherwise pass every
        # downstream crypto check). An admin may still do this
        # deliberately (e.g. provisioning a session on a shared/kiosk
        # device on a user's behalf).
        existing_device_owner = device_owners.get_owner(payload.device_id)
        if existing_device_owner is not None:
            require_owner_or_admin(
                user, existing_device_owner, action="establish a session against this device"
            )
        # A brand-new session is always created as owned by the
        # authenticated caller — never by a `user_id` supplied in the
        # request body (there isn't one; `user.user_id` here comes
        # from the JWT).
        session = sessions.get_or_create(
            session_id,
            user_id=user.user_id,
            device_id=payload.device_id,
            ttl=timedelta(minutes=payload.ttl_minutes),
        )

    # The device this session is being established/refreshed against
    # becomes owned by whoever owns the session, the first time it's
    # seen — this is what lets device ownership (section 2) be
    # enforced without requiring a separate device-registration step.
    device_owners.claim_owner(session.device_id, session.user_id)

    audit.record(
        AuditEvent.SESSION_REFRESHED,
        "success",
        user_id=user.user_id,
        session_id=session_id,
        device_id=session.device_id,
    )
    return SessionStatusResponse(
        session_id=session.session_id,
        device_id=session.device_id,
        revoked=session.revoked,
        expires_at=session.expires_at,
        version=session.version,
    )


# ---------------------------------------------------------------------
# Current authorization/security state (inspection, for the demo)
# ---------------------------------------------------------------------

@router.post("/state", response_model=AuthorizationStateResponse)
def get_authorization_state(
    payload: AuthorizationStateRequest,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
    intent_repo: IntentRepository = Depends(get_intent_repository),
) -> AuthorizationStateResponse:
    """Evaluates and returns the CURRENT authorization/security state
    for a (CID, intent) pair -- the same evaluation `encrypt`/`decrypt`
    perform internally -- without attempting any cryptographic
    operation. Useful for the demo step "show the current
    authorization/security state" and for clients that want to check
    eligibility before assembling an encrypt/decrypt request."""
    try:
        cid = CID(**payload.cid.model_dump())
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    intent_row = intent_repo.get_by_id(payload.intent_id)
    if intent_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "intent not found")
    require_owner_or_admin(user, intent_row.created_by, action="inspect")

    try:
        decision = authorization_service.authorize(
            cid,
            intent_id=intent_row.id,
            intent_lifecycle_state=intent_row.lifecycle_state,
            user_id=user.user_id,
            requesting_user_role=user.role,
        )
    except AuthorizationError as exc:
        return AuthorizationStateResponse(
            authorized=False,
            device_id=cid.device_id,
            session_id=cid.session_id,
            rejection_reason=str(exc),
        )

    return AuthorizationStateResponse(
        authorized=True,
        authorization_state_hash=decision.authorization_state_hash,
        intent_lifecycle_state=decision.security_state.intent_lifecycle_state.value,
        policy_decision_signature=decision.security_state.policy_decision_signature,
        session_version=decision.security_state.session_version,
        device_id=cid.device_id,
        session_id=cid.session_id,
    )
