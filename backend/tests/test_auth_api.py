"""API integration tests for authentication, registration, rate limiting, and audit logs."""

from app.config import get_settings
from app.core.rate_limit import login_limiter
from app.models.audit import AuditLog


def test_register_success_and_audit(client, db_session):
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "newuser@example.com", "password": "Password123!"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "newuser@example.com"
    assert data["role"] == "user"
    assert "password" not in data
    assert "password_hash" not in data

    # Verify audit row created
    audit = db_session.query(AuditLog).filter(AuditLog.action == "user.register").first()
    assert audit is not None
    assert audit.details["email"] == "newuser@example.com"


def test_register_duplicate_email(client, regular_user):
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": regular_user.email, "password": "Password123!"},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"] == "An account with this email already exists."


def test_register_weak_password_rejected(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "user2@example.com", "password": "weak"},
    )
    assert resp.status_code == 400


def test_register_disabled_returns_403(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", False)

    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "blocked@example.com", "password": "Password123!"},
    )
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()


def test_login_and_me_flow(client, regular_user):
    # Successful login
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": regular_user.email, "password": "ValidPass123!"},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    token = token_data["access_token"]

    # Access /auth/me with bearer token
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == regular_user.email


def test_login_uniform_401_for_unknown_and_wrong_password(client, regular_user):
    # 1. Wrong password for existing user
    resp_wrong = client.post(
        "/api/v1/auth/login",
        json={"email": regular_user.email, "password": "WrongPassword999!"},
    )
    assert resp_wrong.status_code == 401
    detail_wrong = resp_wrong.json()["detail"]

    # 2. Non-existent email
    resp_unknown = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@example.com", "password": "AnyPassword123!"},
    )
    assert resp_unknown.status_code == 401
    detail_unknown = resp_unknown.json()["detail"]

    # Error messages must be strictly identical to prevent user enumeration
    assert detail_wrong == detail_unknown == "Invalid email or password."


def test_login_rate_limiting(client, regular_user):
    # Clear rate limiter state for clean test run
    login_limiter._events.clear()

    # 5 failed login attempts
    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            json={"email": regular_user.email, "password": "WrongPassword123!"},
        )

    # 6th attempt should be blocked with 429
    resp_blocked = client.post(
        "/api/v1/auth/login",
        json={"email": regular_user.email, "password": "ValidPass123!"},
    )
    assert resp_blocked.status_code == 429
    assert "Retry-After" in resp_blocked.headers
