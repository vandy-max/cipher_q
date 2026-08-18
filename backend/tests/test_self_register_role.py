"""
Tests for role selection at `/api/auth/register`.

Ordinary self-registration may pick between the two user tiers
(USER_LEVEL_1 / USER_LEVEL_2), but can never obtain ADMIN — that stays
fixed/out-of-band (see backend/scripts/seed_admin.py) or admin-granted
(see tests/test_users_admin.py).
"""
from __future__ import annotations

import mongomock
import pytest
from fastapi.testclient import TestClient

import database.session as dbsession


@pytest.fixture()
def db():
    test_client = mongomock.MongoClient()
    test_db = test_client["cipherq_self_register_test"]
    dbsession.client = test_client
    dbsession.db = test_db
    yield test_db


@pytest.fixture()
def client(db):
    from api.main import app

    return TestClient(app)


def _register(client: TestClient, username: str, role: str | None = None):
    body = {"username": username, "email": f"{username}@example.com", "password": "Sup3rSecret!"}
    if role is not None:
        body["role"] = role
    return client.post("/api/auth/register", json=body)


def test_register_with_no_role_defaults_to_user_level_1(client):
    r = _register(client, "no_role_user")
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "USER_LEVEL_1"


def test_register_can_opt_into_user_level_2(client):
    r = _register(client, "level2_user", role="USER_LEVEL_2")
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "USER_LEVEL_2"


def test_register_cannot_request_admin(client):
    r = _register(client, "would_be_admin", role="ADMIN")
    # Rejected at the schema layer (invalid Literal value) — never
    # silently created and never created as ADMIN.
    assert r.status_code == 422, r.text


def test_register_rejects_arbitrary_role_string(client):
    r = _register(client, "junk_role_user", role="SUPER_USER")
    assert r.status_code == 422, r.text
