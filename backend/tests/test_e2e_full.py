"""Full End-to-End integration test covering Target setup, Lab mode, Account onboarding,
Scan execution through the background worker, and API verification of ground-truth findings.
"""

import json
import socket
import threading
import time
from pathlib import Path
import pytest
from werkzeug.serving import make_server

from app.worker.runner import process_one_job
from labs.vulnerable_app.app import create_app


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def lab_server():
    port = find_free_port()
    flask_app = create_app()
    server = make_server("127.0.0.1", port, flask_app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)

    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.mark.e2e
def test_full_platform_e2e_scan(
    client,
    session_factory,
    regular_user,
    admin_user,
    user_auth_headers,
    admin_auth_headers,
    lab_server,
):
    base_url = lab_server

    # Load ground truth oracle
    repo_root = Path(__file__).resolve().parents[2]
    gt_path = repo_root / "labs" / "vulnerable_app" / "ground_truth.json"
    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    must_find = ground_truth["must_find"]
    must_not_flag = set(ground_truth["must_not_flag"])

    # 1. User registers new target
    target_resp = client.post(
        "/api/v1/targets",
        json={
            "name": "Local Vulnerable Lab",
            "base_url": base_url,
            "scope_hosts": ["127.0.0.1", "localhost"],
        },
        headers=user_auth_headers,
    )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]

    # 2. Admin marks target as lab
    mark_resp = client.post(
        f"/api/v1/targets/{target_id}/mark-lab",
        headers=admin_auth_headers,
    )
    assert mark_resp.status_code == 200
    assert mark_resp.json()["ownership_status"] == "lab"

    # 3. User registers the 3 test accounts
    accounts_to_add = [
        {
            "role_label": "admin",
            "privilege_level": 100,
            "login_url": f"{base_url}/login",
            "username": "admin",
            "password": "admin-pass",
            "username_selector": "input[name=username]",
            "password_selector": "input[name=password]",
            "submit_selector": "button[type=submit]",
            "dismiss_selectors": [],
            "success_url_contains": "/dashboard",
            "identifiers": ["admin@example.com"],
        },
        {
            "role_label": "alice",
            "privilege_level": 10,
            "login_url": f"{base_url}/login",
            "username": "alice",
            "password": "alice-pass",
            "username_selector": "input[name=username]",
            "password_selector": "input[name=password]",
            "submit_selector": "button[type=submit]",
            "dismiss_selectors": [],
            "success_url_contains": "/dashboard",
            "identifiers": ["alice@example.com"],
        },
        {
            "role_label": "bob",
            "privilege_level": 10,
            "login_url": f"{base_url}/login",
            "username": "bob",
            "password": "bob-pass",
            "username_selector": "input[name=username]",
            "password_selector": "input[name=password]",
            "submit_selector": "button[type=submit]",
            "dismiss_selectors": [],
            "success_url_contains": "/dashboard",
            "identifiers": ["bob@example.com"],
        },
    ]

    for acc in accounts_to_add:
        acc_resp = client.post(
            f"/api/v1/targets/{target_id}/accounts",
            json=acc,
            headers=user_auth_headers,
        )
        assert acc_resp.status_code == 201

    # 4. User enqueues scan job via API
    scan_req = {
        "target_id": target_id,
        "options": {
            "seed_paths": ["/dashboard"],
            "max_pages": 20,
            "max_depth": 3,
            "request_delay_ms": 50,
        },
    }
    scan_resp = client.post("/api/v1/scans", json=scan_req, headers=user_auth_headers)
    assert scan_resp.status_code == 202
    scan_id = scan_resp.json()["id"]
    assert scan_resp.json()["status"] == "queued"

    # 5. Worker processes job in-process
    processed = process_one_job(session_factory)
    assert processed is True

    # 6. Verify scan completed successfully via API
    scan_detail_resp = client.get(f"/api/v1/scans/{scan_id}", headers=user_auth_headers)
    assert scan_detail_resp.status_code == 200
    scan_data = scan_detail_resp.json()
    assert scan_data["status"] == "completed"
    assert scan_data["progress_percent"] == 100

    # 7. Verify endpoints recorded
    endpoints_resp = client.get(f"/api/v1/scans/{scan_id}/endpoints", headers=user_auth_headers)
    assert endpoints_resp.status_code == 200
    endpoints = endpoints_resp.json()
    assert len(endpoints) > 0

    # 8. Verify findings match Ground Truth Oracle
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings", headers=user_auth_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()

    for item in must_find:
        exp_type = item["type"]
        exp_sig = item["signature"]
        found = any(f["type"] == exp_type and f["signature"] == exp_sig for f in findings)
        assert found, f"Must find missing: {exp_type} on {exp_sig}"

    for blocked_sig in must_not_flag:
        for f in findings:
            assert f["signature"] != blocked_sig, f"Must not flag violated: {blocked_sig}"

    # 9. Verify Markdown report exports properly
    report_resp = client.get(f"/api/v1/scans/{scan_id}/report.md", headers=user_auth_headers)
    assert report_resp.status_code == 200
    assert "Aegis-Web Security Assessment Report" in report_resp.text
