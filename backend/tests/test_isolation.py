"""Comprehensive cross-tenant data isolation tests."""

import pytest
from app.core.security import create_access_token, hash_password
from app.models.finding import Finding
from app.models.scan import Scan, ScanEvent, Endpoint
from app.models.target import Target, TargetAccount
from app.models.user import User


@pytest.fixture
def user_b(db_session):
    """Secondary test user for multi-tenant isolation testing."""
    user = User(
        email="user_b@example.com",
        password_hash=hash_password("UserBPass123!"),
        role="user",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def user_b_headers(user_b):
    token = create_access_token(user_id=user_b.id, role=user_b.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def user_a_resources(db_session, regular_user):
    """Seed a full hierarchy of resources belonging to regular_user (User A)."""
    # 1. Target
    target = Target(
        owner_id=regular_user.id,
        name="User A Target",
        base_url="https://app.example.com",
        scope_hosts=["app.example.com"],
        ownership_status="verified",
        ownership_token="a" * 32,
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)

    # 2. Account
    account = TargetAccount(
        target_id=target.id,
        role_label="user_a_role",
        privilege_level=10,
        login_url="https://app.example.com/login",
        username="alice",
        password_encrypted="dummy_encrypted",
        username_selector="#u",
        password_selector="#p",
        submit_selector="#s",
        dismiss_selectors=[],
        identifiers=[],
    )
    db_session.add(account)

    # 3. Scan
    scan = Scan(
        owner_id=regular_user.id,
        target_id=target.id,
        status="completed",
        options={},
        summary={},
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    # 4. ScanEvent
    event = ScanEvent(
        scan_id=scan.id,
        level="info",
        stage="recording",
        message="Recorded page",
        percent=25,
    )
    db_session.add(event)

    # 5. Endpoint
    endpoint = Endpoint(
        scan_id=scan.id,
        account_label="user_a_role",
        method="GET",
        url="https://app.example.com/orders/1",
        signature="GET /orders/{id}",
        resource_type="document",
        status_code=200,
    )
    db_session.add(endpoint)

    # 6. Finding
    finding = Finding(
        scan_id=scan.id,
        fingerprint="0123456789abcdef",
        type="HORIZONTAL_ACCESS",
        title="IDOR Violation",
        severity="High",
        confidence=90,
        cvss_score=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-639",
        owasp="A01:2021",
        method="GET",
        url="https://app.example.com/orders/1",
        signature="GET /orders/{id}",
        source_role="user_a_role",
        tested_role="bob",
        description="Access violation",
        remediation="Check ownership",
        evidence={},
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    return {
        "target": target,
        "account": account,
        "scan": scan,
        "event": event,
        "endpoint": endpoint,
        "finding": finding,
    }


def test_user_b_cannot_access_user_a_objects(client, user_b_headers, user_a_resources):
    res = user_a_resources
    tid = res["target"].id
    aid = res["account"].id
    sid = res["scan"].id
    fid = res["finding"].id

    # 1. Target access -> 404
    assert client.get(f"/api/v1/targets/{tid}", headers=user_b_headers).status_code == 404
    assert client.delete(f"/api/v1/targets/{tid}", headers=user_b_headers).status_code == 404
    assert client.post(f"/api/v1/targets/{tid}/verify", headers=user_b_headers).status_code == 404

    # 2. Account access on User A's target -> 404
    assert client.get(f"/api/v1/targets/{tid}/accounts", headers=user_b_headers).status_code == 404
    assert (
        client.post(
            f"/api/v1/targets/{tid}/accounts",
            headers=user_b_headers,
            json={
                "role_label": "intruder",
                "privilege_level": 1,
                "login_url": "http://x",
                "username": "u",
                "password": "p",
                "username_selector": "#u",
                "password_selector": "#p",
                "submit_selector": "#s",
            },
        ).status_code
        == 404
    )
    assert client.delete(f"/api/v1/targets/{tid}/accounts/{aid}", headers=user_b_headers).status_code == 404

    # 3. Scan and sub-resources -> 404
    assert client.get(f"/api/v1/scans/{sid}", headers=user_b_headers).status_code == 404
    assert client.post(f"/api/v1/scans/{sid}/cancel", headers=user_b_headers).status_code == 404
    assert client.get(f"/api/v1/scans/{sid}/events", headers=user_b_headers).status_code == 404
    assert client.get(f"/api/v1/scans/{sid}/endpoints", headers=user_b_headers).status_code == 404
    assert client.get(f"/api/v1/scans/{sid}/findings", headers=user_b_headers).status_code == 404
    assert client.get(f"/api/v1/scans/{sid}/compare/{sid}", headers=user_b_headers).status_code == 404
    assert client.get(f"/api/v1/scans/{sid}/report.md", headers=user_b_headers).status_code == 404
    assert client.get(f"/api/v1/scans/{sid}/report.json", headers=user_b_headers).status_code == 404

    # 4. Finding access -> 404
    assert client.get(f"/api/v1/findings/{fid}", headers=user_b_headers).status_code == 404
    assert (
        client.patch(
            f"/api/v1/findings/{fid}",
            headers=user_b_headers,
            json={"status": "accepted"},
        ).status_code
        == 404
    )


def test_admin_cannot_access_user_scans(client, admin_auth_headers, user_a_resources):
    sid = user_a_resources["scan"].id
    # Admin must NOT read another user's scan; return 404
    assert client.get(f"/api/v1/scans/{sid}", headers=admin_auth_headers).status_code == 404


def test_audit_log_access_restrictions(client, user_b_headers, admin_auth_headers):
    # Regular users cannot access audit log (403)
    resp_user = client.get("/api/v1/admin/audit-log", headers=user_b_headers)
    assert resp_user.status_code == 403

    # Administrators can access audit log (200)
    resp_admin = client.get("/api/v1/admin/audit-log", headers=admin_auth_headers)
    assert resp_admin.status_code == 200
    assert isinstance(resp_admin.json(), list)
