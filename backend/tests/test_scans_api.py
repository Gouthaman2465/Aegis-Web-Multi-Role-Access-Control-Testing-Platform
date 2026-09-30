"""Tests for Scans API, events, reports, and finding triage."""

from datetime import datetime, timezone
import pytest
from app.core.crypto import encrypt_secret
from app.models.finding import Finding
from app.models.scan import Scan, ScanEvent
from app.models.target import Target, TargetAccount


def _create_target_with_accounts(db, user, status="verified", num_accounts=2):
    target = Target(
        owner_id=user.id,
        name="[Injected Markdown](http://evil.com)",
        base_url="http://127.0.0.1:8000",
        scope_hosts=["127.0.0.1"],
        ownership_status=status,
        ownership_token="testtoken123",
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    roles = [("admin", 100), ("alice", 10), ("bob", 10)]
    for i in range(num_accounts):
        role_label, priv = roles[i]
        acc = TargetAccount(
            target_id=target.id,
            role_label=role_label,
            privilege_level=priv,
            login_url="http://127.0.0.1:8000/login",
            username=f"user_{role_label}",
            password_encrypted=encrypt_secret("SecretPass123!"),
            username_selector="#username",
            password_selector="#password",
            submit_selector="#submit",
            dismiss_selectors=[],
            identifiers=[f"ident_{role_label}"],
        )
        db.add(acc)
    db.commit()
    return target


def test_create_scan_validation_and_requirements(client, db_session, regular_user, user_auth_headers):
    # 1. Target unverified -> 400
    t_unverified = _create_target_with_accounts(db_session, regular_user, status="unverified", num_accounts=2)
    resp = client.post(
        "/api/v1/scans",
        json={"target_id": t_unverified.id},
        headers=user_auth_headers,
    )
    assert resp.status_code == 400
    assert "ownership must be verified" in resp.json()["detail"]

    # 2. Target verified but < 2 accounts -> 400
    t_single_acc = _create_target_with_accounts(db_session, regular_user, status="verified", num_accounts=1)
    resp = client.post(
        "/api/v1/scans",
        json={"target_id": t_single_acc.id},
        headers=user_auth_headers,
    )
    assert resp.status_code == 400
    assert "At least 2 target accounts are required" in resp.json()["detail"]

    # 3. Target verified with 2 accounts -> 202 Accepted
    t_valid = _create_target_with_accounts(db_session, regular_user, status="verified", num_accounts=2)
    resp = client.post(
        "/api/v1/scans",
        json={"target_id": t_valid.id},
        headers=user_auth_headers,
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "queued"
    assert data["target_id"] == t_valid.id
    assert data["progress_stage"] == "queued"


def test_scan_options_bounds_validation(client, db_session, regular_user, user_auth_headers):
    target = _create_target_with_accounts(db_session, regular_user, status="verified", num_accounts=2)

    # max_pages out of bounds
    resp = client.post(
        "/api/v1/scans",
        json={"target_id": target.id, "options": {"max_pages": 101}},
        headers=user_auth_headers,
    )
    assert resp.status_code == 422

    # max_depth out of bounds
    resp = client.post(
        "/api/v1/scans",
        json={"target_id": target.id, "options": {"max_depth": 6}},
        headers=user_auth_headers,
    )
    assert resp.status_code == 422

    # seed_paths not starting with /
    resp = client.post(
        "/api/v1/scans",
        json={"target_id": target.id, "options": {"seed_paths": ["api/v1/profile"]}},
        headers=user_auth_headers,
    )
    assert resp.status_code == 422

    # valid options
    resp = client.post(
        "/api/v1/scans",
        json={
            "target_id": target.id,
            "options": {
                "max_pages": 25,
                "max_depth": 2,
                "request_delay_ms": 100,
                "seed_paths": ["/api/v1/profile"],
            },
        },
        headers=user_auth_headers,
    )
    assert resp.status_code == 202
    assert resp.json()["options"]["max_pages"] == 25


def test_cancel_queued_scan(client, db_session, regular_user, user_auth_headers):
    target = _create_target_with_accounts(db_session, regular_user, status="verified", num_accounts=2)
    resp = client.post(
        "/api/v1/scans",
        json={"target_id": target.id},
        headers=user_auth_headers,
    )
    scan_id = resp.json()["id"]

    cancel_resp = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=user_auth_headers)
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "cancelled"

    # Fetch scan directly to verify
    get_resp = client.get(f"/api/v1/scans/{scan_id}", headers=user_auth_headers)
    assert get_resp.json()["status"] == "cancelled"


def test_events_endpoint_honors_after(client, db_session, regular_user, user_auth_headers):
    target = _create_target_with_accounts(db_session, regular_user, status="verified", num_accounts=2)
    scan = Scan(
        owner_id=regular_user.id,
        target_id=target.id,
        status="running",
        options={},
    )
    db_session.add(scan)
    db_session.commit()

    # Add 3 events
    ev1 = ScanEvent(scan_id=scan.id, level="info", stage="starting", message="Event 1", percent=10)
    ev2 = ScanEvent(scan_id=scan.id, level="info", stage="crawling", message="Event 2", percent=30)
    ev3 = ScanEvent(scan_id=scan.id, level="info", stage="replaying", message="Event 3", percent=70)
    db_session.add_all([ev1, ev2, ev3])
    db_session.commit()

    resp_all = client.get(f"/api/v1/scans/{scan.id}/events", headers=user_auth_headers)
    assert resp_all.status_code == 200
    assert len(resp_all.json()) == 3

    resp_after = client.get(f"/api/v1/scans/{scan.id}/events?after={ev1.id}", headers=user_auth_headers)
    assert resp_after.status_code == 200
    events = resp_after.json()
    assert len(events) == 2
    assert events[0]["id"] == ev2.id
    assert events[1]["id"] == ev3.id


def test_finding_patch_status_validation(client, db_session, regular_user, user_auth_headers):
    target = _create_target_with_accounts(db_session, regular_user, status="verified", num_accounts=2)
    scan = Scan(owner_id=regular_user.id, target_id=target.id, status="completed", options={})
    db_session.add(scan)
    db_session.commit()

    finding = Finding(
        scan_id=scan.id,
        fingerprint="fp1234567890abcd",
        type="HORIZONTAL_ACCESS",
        title="IDOR vulnerability",
        severity="High",
        confidence=95,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-639",
        owasp="A01:2021",
        method="GET",
        url="http://127.0.0.1:8000/orders/1",
        signature="GET /orders/{id}",
        source_role="alice",
        tested_role="bob",
        description="IDOR test description",
        remediation="Verify user ownership on order object.",
        status="open",
        evidence={},
    )
    db_session.add(finding)
    db_session.commit()

    # Valid status update
    patch_resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"status": "false_positive", "note": "Verified manual rule"},
        headers=user_auth_headers,
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "false_positive"
    assert patch_resp.json()["note"] == "Verified manual rule"

    # Invalid status -> 422
    bad_patch = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"status": "not_a_valid_status"},
        headers=user_auth_headers,
    )
    assert bad_patch.status_code == 422


def test_report_no_evidence_bodies_and_markdown_escaped(client, db_session, regular_user, user_auth_headers):
    target = _create_target_with_accounts(db_session, regular_user, status="verified", num_accounts=2)
    scan = Scan(owner_id=regular_user.id, target_id=target.id, status="completed", options={})
    db_session.add(scan)
    db_session.commit()

    secret_raw_body = "SENSITIVE_INTERNAL_DATABASE_LEAK_SECRET_123"
    finding = Finding(
        scan_id=scan.id,
        fingerprint="fp1234567890abcd",
        type="HORIZONTAL_ACCESS",
        title="IDOR on [Orders Page](http://evil.com/leak)",
        severity="High",
        confidence=90,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-639",
        owasp="A01:2021",
        method="GET",
        url="http://127.0.0.1:8000/orders/1",
        signature="GET /orders/{id}",
        source_role="alice",
        tested_role="bob",
        description="Detailed description",
        remediation="Ensure authorization",
        status="open",
        evidence={
            "original": {"status": 200, "body_preview": secret_raw_body},
            "replay": {"status": 200, "body_preview": secret_raw_body},
            "similarity": 1.0,
        },
    )
    db_session.add(finding)
    db_session.commit()

    report_resp = client.get(f"/api/v1/scans/{scan.id}/report.md", headers=user_auth_headers)
    assert report_resp.status_code == 200
    report_text = report_resp.text

    # Assert raw body is NEVER included in Markdown report
    assert secret_raw_body not in report_text

    # Assert unescaped Markdown links from target or title are NOT injected
    assert "[Injected Markdown](http://evil.com)" not in report_text
    assert "[Orders Page](http://evil.com/leak)" not in report_text
