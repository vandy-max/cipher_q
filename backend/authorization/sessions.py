"""
Session validity + versioning state.

Extends the existing `session_id` concept (already a required CID
field, already used as the HKDF salt) with an explicit, trackable
status: expiry, revocation, and a monotonic `version`.

`version` is what gives CipherQ replay protection for the *session*
without inventing new cryptography: every time a session is freshly
(re-)authorized via `refresh`, the version increments. `version` is
folded into `SecurityState` (see `state.py`), so a cryptographic
session derived under an old version can never be reproduced by
recomputing the *current* authorization state hash — the old
(session_id, version) pair is simply no longer "current" once a fresh
authorization has happened, regardless of whether the session_id
string itself was reused.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol


@dataclass
class SessionState:
    session_id: str
    user_id: int
    device_id: str
    expires_at: datetime
    revoked: bool = False
    version: int = 1


class SessionRepository(Protocol):
    def get_or_create(
        self,
        session_id: str,
        user_id: int,
        device_id: str,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> SessionState: ...

    def get(self, session_id: str) -> SessionState | None: ...
    def revoke(self, session_id: str) -> SessionState: ...
    def refresh(self, session_id: str, ttl: timedelta, now: datetime | None = None) -> SessionState: ...


def is_session_valid(session: SessionState, now: datetime) -> tuple[bool, str | None]:
    if session.revoked:
        return False, "revoked"
    expires_at = session.expires_at
    # Defensive normalization: a naive `expires_at` (e.g. round-tripped
    # through BSON without the caller normalizing it first) is always
    # UTC in this codebase — see api/repositories.py::_to_session_state.
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if now > expires_at:
        return False, "expired"
    return True, None


class InMemorySessionRepository:
    """Reference/test implementation only — not for production use."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}

    def get_or_create(
        self,
        session_id: str,
        user_id: int,
        device_id: str,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> SessionState:
        existing = self._sessions.get(session_id)
        if existing is not None:
            return existing
        session = SessionState(
            session_id=session_id,
            user_id=user_id,
            device_id=device_id,
            expires_at=(now or datetime.now(timezone.utc)) + ttl,
        )
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> SessionState | None:
        return self._sessions.get(session_id)

    def revoke(self, session_id: str) -> SessionState:
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"no session '{session_id}'")
        session.revoked = True
        return session

    def refresh(self, session_id: str, ttl: timedelta, now: datetime | None = None) -> SessionState:
        """Establish a fresh authorized session: extends expiry,
        un-revokes, and bumps `version` (invalidating any crypto
        session bound to the previous version)."""
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"no session '{session_id}'")
        session.revoked = False
        session.expires_at = (now or datetime.now(timezone.utc)) + ttl
        session.version += 1
        return session
