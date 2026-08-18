import pytest

from authentication.jwt_service import JWTService
from authentication.service import (
    AuthenticationService,
    InMemoryUserRepository,
    InvalidCredentialsError,
    UsernameTakenError,
)


def _service() -> AuthenticationService:
    return AuthenticationService(InMemoryUserRepository(), JWTService(secret="test-secret"))


def test_register_then_login():
    service = _service()
    reg = service.register("alice", "alice@example.com", "correct-horse-battery")
    assert reg.username == "alice"
    assert reg.token

    login = service.login("alice", "correct-horse-battery")
    assert login.user_id == reg.user_id


def test_duplicate_username_rejected():
    service = _service()
    service.register("alice", "a@example.com", "correct-horse-battery")
    with pytest.raises(UsernameTakenError):
        service.register("alice", "other@example.com", "another-password")


def test_login_with_wrong_password_rejected():
    service = _service()
    service.register("alice", "a@example.com", "correct-horse-battery")
    with pytest.raises(InvalidCredentialsError):
        service.login("alice", "wrong-password")


def test_login_with_unknown_username_rejected():
    service = _service()
    with pytest.raises(InvalidCredentialsError):
        service.login("nobody", "whatever-password")


def test_short_password_rejected():
    service = _service()
    with pytest.raises(ValueError):
        service.register("alice", "a@example.com", "short")
