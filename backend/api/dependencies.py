from __future__ import annotations

import os
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pymongo.database import Database

from audit.service import AuditLogService
from authentication.face_auth import FaceAuthService
from authentication.jwt_service import InvalidTokenError, JWTService, TokenExpiredError, TokenPayload
from authentication.service import AuthenticationService
from authorization.service import AuthorizationService
from crypto.service import EncryptionService
from database.session import get_db
from intent.validation import IntentValidationService
from monitoring.service import MonitoringService
from policy.engine import PolicyEngine
from policy.risk import RiskEngine
from quantum.service import QuantumKeyExchangeService

from .repositories import (
    IntentLifecycleLookup,
    IntentRepository,
    MongoAuditLogRepository,
    MongoDeviceRepository,
    MongoFaceDescriptorRepository,
    MongoMonitoringRepository,
    MongoSessionRepository,
    MongoUserRepository,
    PolicyRepository,
)

_bearer_scheme = HTTPBearer(auto_error=False)

_DEV_JWT_SECRET_FALLBACK = "dev-secret-change-me"


def resolve_jwt_secret(app_env: str, secret_env: str | None) -> str:
    """Pure decision logic, factored out so it can be unit-tested
    directly (see tests/test_production_hardening.py) without needing
    to spin up a whole app/process per APP_ENV value. `get_jwt_service`
    below is the only real caller."""
    app_env = (app_env or "development").strip().lower()
    if secret_env:
        return secret_env
    if app_env == "production":
        raise RuntimeError(
            "JWT_SECRET is not set. Refusing to start with APP_ENV=production "
            "and no JWT_SECRET — set the JWT_SECRET environment variable before "
            "starting the application. (A development fallback secret is only "
            "permitted when APP_ENV is not 'production'.)"
        )
    return _DEV_JWT_SECRET_FALLBACK


@lru_cache
def get_jwt_service() -> JWTService:
    secret = resolve_jwt_secret(os.environ.get("APP_ENV", "development"), os.environ.get("JWT_SECRET"))
    ttl_hours = int(os.environ.get("JWT_TTL_HOURS", "24"))
    return JWTService(secret=secret, ttl_hours=ttl_hours)


def get_auth_service(
    db: Database = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> AuthenticationService:
    return AuthenticationService(MongoUserRepository(db), jwt_service)


def get_audit_service(db: Database = Depends(get_db)) -> AuditLogService:
    return AuditLogService(MongoAuditLogRepository(db))


def get_face_auth_service(db: Database = Depends(get_db)) -> FaceAuthService:
    return FaceAuthService(MongoFaceDescriptorRepository(db))


def get_encryption_service() -> EncryptionService:
    return EncryptionService()


def get_policy_engine() -> PolicyEngine:
    return PolicyEngine()


def get_policy_config_repository(db: Database = Depends(get_db)) -> PolicyRepository:
    return PolicyRepository(db)


def get_risk_engine() -> RiskEngine:
    return RiskEngine()


def get_quantum_service() -> QuantumKeyExchangeService:
    return QuantumKeyExchangeService()


def get_intent_repository(db: Database = Depends(get_db)) -> IntentRepository:
    return IntentRepository(db)


def get_device_repository(db: Database = Depends(get_db)) -> MongoDeviceRepository:
    return MongoDeviceRepository(db)


def get_session_repository(db: Database = Depends(get_db)) -> MongoSessionRepository:
    return MongoSessionRepository(db)


def get_authorization_service(
    device_repo: MongoDeviceRepository = Depends(get_device_repository),
    session_repo: MongoSessionRepository = Depends(get_session_repository),
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    policy_config_repo: PolicyRepository = Depends(get_policy_config_repository),
) -> AuthorizationService:
    return AuthorizationService(device_repo, session_repo, policy_engine, policy_config_repo)


def get_intent_validation_service(
    device_repo: MongoDeviceRepository = Depends(get_device_repository),
    session_repo: MongoSessionRepository = Depends(get_session_repository),
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    policy_config_repo: PolicyRepository = Depends(get_policy_config_repository),
) -> IntentValidationService:
    return IntentValidationService(
        device_repo, session_repo, policy_engine, risk_engine, policy_config_repo
    )


def get_monitoring_repository(db: Database = Depends(get_db)) -> MongoMonitoringRepository:
    return MongoMonitoringRepository(db)


def get_monitoring_service(
    monitoring_repo: MongoMonitoringRepository = Depends(get_monitoring_repository),
    device_repo: MongoDeviceRepository = Depends(get_device_repository),
    session_repo: MongoSessionRepository = Depends(get_session_repository),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    audit_service: AuditLogService = Depends(get_audit_service),
    intent_repo: IntentRepository = Depends(get_intent_repository),
) -> MonitoringService:
    return MonitoringService(
        monitoring_repo,
        device_repo,
        session_repo,
        risk_engine=risk_engine,
        audit_service=audit_service,
        lifecycle_lookup=IntentLifecycleLookup(intent_repo),
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> TokenPayload:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing Authorization header")
    try:
        return jwt_service.decode_token(credentials.credentials)
    except TokenExpiredError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired") from exc
    except InvalidTokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc
