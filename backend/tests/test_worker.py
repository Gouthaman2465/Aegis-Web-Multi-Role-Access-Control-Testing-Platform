"""Unit and integration tests for background scan worker runner."""

import time
from datetime import datetime, timedelta, timezone
import pytest

from aegis_scanner.models import FindingResult, RecordedRequest, ScanResult
from app.config import get_settings
from app.core.crypto import encrypt_secret
from app.core.fingerprint import compute_fingerprint
from app.models.finding import Finding
from app.models.scan import Endpoint, Scan, ScanEvent
from app.models.target import Target, TargetAccount
from app.worker.runner import claim_next_job, process_one_job, recover_stale_jobs


def _setup_target_and_accounts(db, user):
    target = Target(
        owner_id=user.id,
        name="Lab App",
        base_url="http://127.0.0.1:8000",
        scope_hosts=["127.0.0.1"],
        ownership_status="lab",
        ownership_token="token_lab",
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    acc1 = TargetAccount(
        target_id=target.id,
        role_label="alice",
        privilege_level=10,
        login_url="http://127.0.0.1:8000/login",
        username="alice",
        password_encrypted=encrypt_secret("AlicePass123!"),
        username_selector="#user",
        password_selector="#pass",
        submit_selector="#btn",
        dismiss_selectors=[],
        identifiers=["alice_id_1"],
    )
    acc2 = TargetAccount(
        target_id=target.id,
        role_label="bob",
        privilege_level=10,
        login_url="http://127.0.0.1:8000/login",
        username="bob",
        password_encrypted=encrypt_secret("BobPass123!"),
        username_selector="#user",
        password_selector="#pass",
        submit_selector="#btn",
        dismiss_selectors=[],
        identifiers=["bob_id_2"],
    )
    db.add_all([acc1, acc2])
    db.commit()
    return target


def test_process_one_job_happy_path(monkeypatch, db_session, session_factory, regular_user):
    import app.worker.runner as runner_module

    target = _setup_target_and_accounts(db_session, regular_user)
    scan = Scan(
        owner_id=regular_user.id,
        target_id=target.id,
        status="queued",
        options={},
    )
    db_session.add(scan)
    db_session.commit()
    scan_id = scan.id

    expected_fp = compute_fingerprint("HORIZONTAL_ACCESS", "GET", "GET /orders/{id}", "alice", "bob")

    def mock_run_scan(config, report, should_cancel):
        # Report an event with Alice's password to verify log sanitization
        report("recording", 25, "Crawling with password AlicePass123! logged in", "info")
        rec = RecordedRequest(
            account_label="alice",
            method="GET",
            url="http://127.0.0.1:8000/orders/1",
            headers={"Authorization": "Bearer secret_token_123"},
            body=None,
            resource_type="document",
            status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="Order #1 details",
            content_type="text/html",
            signature="GET /orders/{id}",
        )
        finding = FindingResult(
            type="HORIZONTAL_ACCESS",
            title="Horizontal IDOR Vulnerability",
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
            description="Alice's order was accessible by Bob.",
            remediation="Enforce object-level access control.",
            evidence={
                "original": {"status": 200, "headers": {"Authorization": "Bearer tok"}},
                "replay": {"status": 200, "headers": {"Authorization": "Bearer tok"}},
                "similarity": 1.0,
            },
        )
        return ScanResult(
            endpoints=[rec],
            findings=[finding],
            stats={"replays_sent": 12, "discarded_low_confidence": 3},
        )

    monkeypatch.setattr(runner_module, "run_access_control_scan", mock_run_scan)

    processed = process_one_job(session_factory)
    assert processed is True

    # Verify updated scan
    db_session.expire_all()
    updated_scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert updated_scan.status == "completed"
    assert updated_scan.progress_percent == 100
    assert updated_scan.finished_at is not None
    assert updated_scan.summary["requests_recorded"] == 1
    assert updated_scan.summary["replays_sent"] == 12
    assert updated_scan.summary["discarded_low_confidence"] == 3
    assert updated_scan.summary["findings_by_severity"]["High"] == 1

    # Verify endpoint
    endpoints = db_session.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    assert len(endpoints) == 1
    assert endpoints[0].signature == "GET /orders/{id}"

    # Verify finding & fingerprint
    findings = db_session.query(Finding).filter(Finding.scan_id == scan_id).all()
    assert len(findings) == 1
    assert findings[0].fingerprint == expected_fp

    # Verify passwords NEVER appear in scan events
    events = db_session.query(ScanEvent).filter(ScanEvent.scan_id == scan_id).all()
    assert len(events) >= 1
    for ev in events:
        assert "AlicePass123!" not in ev.message
        assert "BobPass123!" not in ev.message


def test_process_one_job_failure_path(monkeypatch, db_session, session_factory, regular_user):
    import app.worker.runner as runner_module

    target = _setup_target_and_accounts(db_session, regular_user)
    scan = Scan(
        owner_id=regular_user.id,
        target_id=target.id,
        status="queued",
        options={},
    )
    db_session.add(scan)
    db_session.commit()
    scan_id = scan.id

    def mock_fail_scan(config, report, should_cancel):
        raise RuntimeError("Simulated crash with secret AlicePass123! in text")

    monkeypatch.setattr(runner_module, "run_access_control_scan", mock_fail_scan)

    processed = process_one_job(session_factory)
    assert processed is True

    db_session.expire_all()
    updated_scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert updated_scan.status == "failed"
    assert updated_scan.error_message is not None
    assert "AlicePass123!" not in updated_scan.error_message
    assert "[REDACTED]" in updated_scan.error_message
    assert "\nTraceback" not in updated_scan.error_message


def test_process_one_job_cancel_path(monkeypatch, db_session, session_factory, regular_user):
    import app.worker.runner as runner_module

    target = _setup_target_and_accounts(db_session, regular_user)
    scan = Scan(
        owner_id=regular_user.id,
        target_id=target.id,
        status="queued",
        options={},
    )
    db_session.add(scan)
    db_session.commit()
    scan_id = scan.id

    def mock_cancel_scan(config, report, should_cancel):
        # Set cancel_requested in DB while scanner is "running"
        with session_factory() as db:
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            s.cancel_requested = True
            db.commit()

        # Scanner checks cancel
        assert should_cancel() is True
        return ScanResult(endpoints=[], findings=[], stats={})

    monkeypatch.setattr(runner_module, "run_access_control_scan", mock_cancel_scan)

    processed = process_one_job(session_factory)
    assert processed is True

    db_session.expire_all()
    updated_scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert updated_scan.status == "cancelled"


def test_recover_stale_jobs(db_session, regular_user):
    target = _setup_target_and_accounts(db_session, regular_user)
    settings = get_settings()

    # Old job running past timeout
    old_time = datetime.now(timezone.utc) - timedelta(seconds=settings.SCAN_TIMEOUT_SECONDS + 60)
    stale_scan = Scan(
        owner_id=regular_user.id,
        target_id=target.id,
        status="running",
        started_at=old_time,
        options={},
    )
    # Fresh job running within timeout
    fresh_time = datetime.now(timezone.utc) - timedelta(seconds=10)
    fresh_scan = Scan(
        owner_id=regular_user.id,
        target_id=target.id,
        status="running",
        started_at=fresh_time,
        options={},
    )
    db_session.add_all([stale_scan, fresh_scan])
    db_session.commit()

    recovered = recover_stale_jobs(db_session)
    assert recovered == 1

    db_session.expire_all()
    s1 = db_session.query(Scan).filter(Scan.id == stale_scan.id).first()
    s2 = db_session.query(Scan).filter(Scan.id == fresh_scan.id).first()

    assert s1.status == "failed"
    assert s1.error_message == "Worker restarted"
    assert s2.status == "running"


def test_process_one_job_timeout_path(monkeypatch, db_session, session_factory, regular_user):
    import app.worker.runner as runner_module

    target = _setup_target_and_accounts(db_session, regular_user)
    scan = Scan(
        owner_id=regular_user.id,
        target_id=target.id,
        status="queued",
        options={},
    )
    db_session.add(scan)
    db_session.commit()
    scan_id = scan.id

    # Simulate timeout by having settings.SCAN_TIMEOUT_SECONDS = 0
    settings = get_settings()
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 0)

    def mock_timeout_scan(config, report, should_cancel):
        assert should_cancel() is True
        return ScanResult(endpoints=[], findings=[], stats={})

    monkeypatch.setattr(runner_module, "run_access_control_scan", mock_timeout_scan)

    processed = process_one_job(session_factory)
    assert processed is True

    db_session.expire_all()
    updated_scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert updated_scan.status == "failed"
    assert updated_scan.error_message == "Scan timed out"
