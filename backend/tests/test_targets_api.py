"""API tests for targets, account encryption, verification, and lab mode."""

import pytest
from app.config import get_settings
from app.models.target import TargetAccount
from aegis_scanner.net_guard import SafeResponse


def test_target_crud(client, user_auth_headers):
    # 1. Create target
    resp = client.post(
        "/api/v1/targets",
        headers=user_auth_headers,
        json={"name": "Production App", "base_url": "https://example.com"},
    )
    assert resp.status_code == 201
    target = resp.json()
    assert target["name"] == "Production App"
    assert target["ownership_status"] == "unverified"
    assert len(target["ownership_token"]) == 32
    target_id = target["id"]

    # 2. Get target
    get_resp = client.get(f"/api/v1/targets/{target_id}", headers=user_auth_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Production App"

    # 3. List targets
    list_resp = client.get("/api/v1/targets", headers=user_auth_headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    # 4. Delete target
    del_resp = client.delete(f"/api/v1/targets/{target_id}", headers=user_auth_headers)
    assert del_resp.status_code == 204

    # 5. Confirm gone
    get_again = client.get(f"/api/v1/targets/{target_id}", headers=user_auth_headers)
    assert get_again.status_code == 404


def test_account_creation_encrypts_password_and_never_leaks(client, user_auth_headers, db_session):
    # Create target
    target = client.post(
        "/api/v1/targets",
        headers=user_auth_headers,
        json={"name": "Test App", "base_url": "http://127.0.0.1:8080"},
    ).json()
    target_id = target["id"]

    plain_pass = "SuperSecretPassword123!"
    acc_resp = client.post(
        f"/api/v1/targets/{target_id}/accounts",
        headers=user_auth_headers,
        json={
            "role_label": "analyst",
            "privilege_level": 50,
            "login_url": "http://127.0.0.1:8080/login",
            "username": "analyst_user",
            "password": plain_pass,
            "username_selector": "#u",
            "password_selector": "#p",
            "submit_selector": "#btn",
        },
    )
    assert acc_resp.status_code == 201
    acc_data = acc_resp.json()

    # Password MUST NOT exist in response schema
    assert "password" not in acc_data
    assert "password_encrypted" not in acc_data
    assert plain_pass not in str(acc_data)

    # Check database: password is encrypted and not equal to plaintext
    db_acc = db_session.query(TargetAccount).filter(TargetAccount.id == acc_data["id"]).first()
    assert db_acc is not None
    assert db_acc.password_encrypted != plain_pass
    assert plain_pass not in db_acc.password_encrypted


def test_reserved_role_label_anonymous_and_invalid_labels(client, user_auth_headers):
    target = client.post(
        "/api/v1/targets",
        headers=user_auth_headers,
        json={"name": "Test App", "base_url": "http://127.0.0.1:8080"},
    ).json()
    target_id = target["id"]

    # Reserved anonymous rejected
    resp_anon = client.post(
        f"/api/v1/targets/{target_id}/accounts",
        headers=user_auth_headers,
        json={
            "role_label": "anonymous",
            "privilege_level": 1,
            "login_url": "http://127.0.0.1:8080/login",
            "username": "u",
            "password": "p",
            "username_selector": "#u",
            "password_selector": "#p",
            "submit_selector": "#btn",
        },
    )
    assert resp_anon.status_code == 422 or resp_anon.status_code == 400

    # Invalid characters in label (spaces, symbols)
    resp_inv = client.post(
        f"/api/v1/targets/{target_id}/accounts",
        headers=user_auth_headers,
        json={
            "role_label": "invalid label!",
            "privilege_level": 1,
            "login_url": "http://127.0.0.1:8080/login",
            "username": "u",
            "password": "p",
            "username_selector": "#u",
            "password_selector": "#p",
            "submit_selector": "#btn",
        },
    )
    assert resp_inv.status_code == 422 or resp_inv.status_code == 400


def test_mark_lab_authorization_and_environment(client, user_auth_headers, admin_auth_headers, monkeypatch):
    target = client.post(
        "/api/v1/targets",
        headers=user_auth_headers,
        json={"name": "Lab Target", "base_url": "http://127.0.0.1:5001"},
    ).json()
    target_id = target["id"]

    # 1. Non-admin forbidden
    resp_user = client.post(f"/api/v1/targets/{target_id}/mark-lab", headers=user_auth_headers)
    assert resp_user.status_code == 403

    # 2. Admin allowed when ENABLE_LAB_MODE=true
    resp_admin = client.post(f"/api/v1/targets/{target_id}/mark-lab", headers=admin_auth_headers)
    assert resp_admin.status_code == 200
    assert resp_admin.json()["ownership_status"] == "lab"

    # 3. Forbidden when ENABLE_LAB_MODE=false
    settings = get_settings()
    monkeypatch.setattr(settings, "ENABLE_LAB_MODE", False)
    resp_disabled = client.post(f"/api/v1/targets/{target_id}/mark-lab", headers=admin_auth_headers)
    assert resp_disabled.status_code == 403


def test_verify_target_ownership(client, user_auth_headers, monkeypatch):
    target = client.post(
        "/api/v1/targets",
        headers=user_auth_headers,
        json={"name": "Remote Target", "base_url": "https://remote.example.com"},
    ).json()
    target_id = target["id"]
    token = target["ownership_token"]

    # 1. Failed verification (wrong token)
    def mock_safe_get_fail(*args, **kwargs):
        return SafeResponse(status_code=200, headers={}, text="WRONG_TOKEN", content=b"WRONG_TOKEN")

    monkeypatch.setattr("app.core.ownership.safe_get", mock_safe_get_fail)
    resp_fail = client.post(f"/api/v1/targets/{target_id}/verify", headers=user_auth_headers)
    assert resp_fail.status_code == 200
    assert resp_fail.json()["verified"] is False

    # Check status remains unverified
    assert client.get(f"/api/v1/targets/{target_id}", headers=user_auth_headers).json()["ownership_status"] == "unverified"

    # 2. Successful verification (matching token)
    def mock_safe_get_success(*args, **kwargs):
        return SafeResponse(status_code=200, headers={}, text=token, content=token.encode())

    monkeypatch.setattr("app.core.ownership.safe_get", mock_safe_get_success)
    resp_success = client.post(f"/api/v1/targets/{target_id}/verify", headers=user_auth_headers)
    assert resp_success.status_code == 200
    assert resp_success.json()["verified"] is True

    # Check status updated to verified
    assert client.get(f"/api/v1/targets/{target_id}", headers=user_auth_headers).json()["ownership_status"] == "verified"
