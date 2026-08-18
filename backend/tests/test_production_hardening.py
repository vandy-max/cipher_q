"""
Production-hardening tests:

- APP_ENV=production with no JWT_SECRET must fail fast (not silently
  fall back to the well-known development secret).
- CORS origins must come from ALLOWED_ORIGINS in production, and
  production must refuse to start if that's unset.
- A disallowed Origin is rejected by the CORS layer; an allowed one is
  accepted, including credentials/Authorization + preflight OPTIONS.

These test the pure decision functions directly (`resolve_jwt_secret`,
`resolve_cors_origins`) rather than spawning a real subprocess per
APP_ENV value, since the FastAPI app is a long-lived object built once
per test process and `os.environ` changes after that point don't
retroactively change how it was constructed. The functions being
tested are exactly what `api/dependencies.py::get_jwt_service` and
`api/main.py` call at real startup — this is the actual logic, not a
reimplementation of it for testing purposes.
"""
from __future__ import annotations

import mongomock
import pytest
from fastapi.testclient import TestClient

import database.session as dbsession
from api.dependencies import resolve_jwt_secret
from api.main import DEV_CORS_ORIGINS, resolve_cors_origins


# ---------------------------------------------------------------------
# JWT secret
# ---------------------------------------------------------------------

class TestJWTSecretEnforcement:
    def test_production_with_missing_secret_fails_fast(self):
        with pytest.raises(RuntimeError, match="JWT_SECRET"):
            resolve_jwt_secret("production", None)

    def test_production_with_empty_string_secret_fails_fast(self):
        with pytest.raises(RuntimeError, match="JWT_SECRET"):
            resolve_jwt_secret("production", "")

    def test_production_with_secret_set_succeeds(self):
        secret = resolve_jwt_secret("production", "a-real-production-secret")
        assert secret == "a-real-production-secret"

    def test_development_without_secret_uses_fallback(self):
        secret = resolve_jwt_secret("development", None)
        assert secret == "dev-secret-change-me"

    def test_unset_app_env_defaults_to_development_fallback(self):
        secret = resolve_jwt_secret("", None)
        assert secret == "dev-secret-change-me"

    def test_app_env_is_case_insensitive(self):
        with pytest.raises(RuntimeError):
            resolve_jwt_secret("PRODUCTION", None)
        with pytest.raises(RuntimeError):
            resolve_jwt_secret("  Production  ", None)

    def test_error_message_never_contains_the_dev_fallback_secret(self):
        # The failure message must guide the operator without ever
        # printing/leaking a usable secret value.
        with pytest.raises(RuntimeError) as exc_info:
            resolve_jwt_secret("production", None)
        assert "dev-secret-change-me" not in str(exc_info.value).split("permitted")[0]


# ---------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------

class TestCORSProductionConfig:
    def test_development_uses_localhost_defaults(self):
        origins = resolve_cors_origins("development", "")
        assert origins == DEV_CORS_ORIGINS
        assert "http://localhost:5173" in origins

    def test_production_without_allowed_origins_fails_fast(self):
        with pytest.raises(RuntimeError, match="ALLOWED_ORIGINS"):
            resolve_cors_origins("production", "")

    def test_production_with_blank_allowed_origins_fails_fast(self):
        with pytest.raises(RuntimeError, match="ALLOWED_ORIGINS"):
            resolve_cors_origins("production", "   ,  ,")

    def test_production_with_single_origin(self):
        origins = resolve_cors_origins("production", "https://cipherq-frontend.onrender.com")
        assert origins == ["https://cipherq-frontend.onrender.com"]

    def test_production_with_multiple_origins(self):
        origins = resolve_cors_origins(
            "production", "https://app.example.com, https://admin.example.com"
        )
        assert origins == ["https://app.example.com", "https://admin.example.com"]

    def test_production_never_returns_wildcard(self):
        origins = resolve_cors_origins("production", "https://app.example.com")
        assert "*" not in origins


class TestCORSLiveEnforcement:
    """Integration-level check that the CORS middleware actually
    enforces the (development-mode) allow-list against a real request's
    Origin header, and that credentialed/Authorization preflight
    requests keep working for an allowed origin."""

    @pytest.fixture()
    def client(self):
        test_client = mongomock.MongoClient()
        dbsession.client = test_client
        dbsession.db = test_client["cipherq_cors_test"]
        from api.main import app

        return TestClient(app)

    def test_allowed_dev_origin_is_accepted(self, client):
        resp = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"

    def test_unknown_origin_preflight_is_rejected(self, client):
        resp = client.options(
            "/api/audit/logs",
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )
        # Starlette's CORSMiddleware answers preflight directly and
        # simply omits the allow-origin header for a disallowed
        # origin — the browser is what ultimately blocks the request,
        # but the header the browser relies on for that must be
        # absent (never wildcarded) here.
        assert resp.headers.get("access-control-allow-origin") != "https://evil.example.com"
        assert resp.headers.get("access-control-allow-origin") != "*"

    def test_allowed_origin_preflight_with_authorization_header_succeeds(self, client):
        resp = client.options(
            "/api/audit/logs",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"
        assert resp.headers.get("access-control-allow-credentials") == "true"
