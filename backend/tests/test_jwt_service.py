import time

import pytest

from authentication.jwt_service import InvalidTokenError, JWTService, TokenExpiredError


def test_create_and_decode_round_trip():
    service = JWTService(secret="test-secret", ttl_hours=1)
    token = service.create_token(user_id=42, username="alice", role="analyst")
    payload = service.decode_token(token)
    assert payload.user_id == 42
    assert payload.username == "alice"
    assert payload.role == "analyst"


def test_expired_token_raises():
    service = JWTService(secret="test-secret", ttl_hours=-1)  # already expired
    token = service.create_token(user_id=1, username="bob", role="user")
    with pytest.raises(TokenExpiredError):
        service.decode_token(token)


def test_wrong_secret_raises_invalid_token():
    service_a = JWTService(secret="secret-a")
    service_b = JWTService(secret="secret-b")
    token = service_a.create_token(user_id=1, username="bob", role="user")
    with pytest.raises(InvalidTokenError):
        service_b.decode_token(token)


def test_tampered_token_raises_invalid_token():
    service = JWTService(secret="test-secret")
    token = service.create_token(user_id=1, username="bob", role="user")
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    with pytest.raises(InvalidTokenError):
        service.decode_token(tampered)


def test_empty_secret_rejected():
    with pytest.raises(ValueError):
        JWTService(secret="")
