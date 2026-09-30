"""End-to-end access control detection test with ground-truth oracle verification."""

import json
import socket
import threading
import time
from pathlib import Path
import pytest
from werkzeug.serving import make_server

from aegis_scanner.models import AccountConfig, ScanConfig
from aegis_scanner.modules.access_control import run_access_control_scan
from labs.vulnerable_app.app import create_app, USER_TOKENS


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def lab_app_server():
    port = find_free_port()
    app = create_app()
    server = make_server("127.0.0.1", port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)

    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.mark.e2e
def test_access_control_scan_e2e(lab_app_server):
    base_url = lab_app_server

    repo_root = Path(__file__).resolve().parents[2]
    gt_path = repo_root / "labs" / "vulnerable_app" / "ground_truth.json"
    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    must_find = ground_truth["must_find"]
    must_not_flag = set(ground_truth["must_not_flag"])

    accounts = [
        AccountConfig(
            label="admin",
            privilege_level=100,
            login_url=f"{base_url}/login",
            username="admin",
            password="admin-pass",
            username_selector="input[name=username]",
            password_selector="input[name=password]",
            submit_selector="button[type=submit]",
            success_url_contains="/dashboard",
        ),
        AccountConfig(
            label="alice",
            privilege_level=10,
            login_url=f"{base_url}/login",
            username="alice",
            password="alice-pass",
            username_selector="input[name=username]",
            password_selector="input[name=password]",
            submit_selector="button[type=submit]",
            success_url_contains="/dashboard",
        ),
        AccountConfig(
            label="bob",
            privilege_level=10,
            login_url=f"{base_url}/login",
            username="bob",
            password="bob-pass",
            username_selector="input[name=username]",
            password_selector="input[name=password]",
            submit_selector="button[type=submit]",
            success_url_contains="/dashboard",
        ),
    ]

    config = ScanConfig(
        base_url=base_url,
        scope_hosts=["127.0.0.1", "localhost"],
        accounts=accounts,
        seed_paths=["/dashboard"],
        max_pages=20,
        max_depth=3,
        request_delay_ms=50,
        allow_private=True,
    )

    result = run_access_control_scan(
        config=config,
        report=lambda st, pct, msg, lvl: None,
        should_cancel=lambda: False,
    )

    # 1. Assert every must_find in ground_truth is detected
    for expected in must_find:
        exp_type = expected["type"]
        exp_sig = expected["signature"]
        found = any(f.type == exp_type and f.signature == exp_sig for f in result.findings)
        assert found, f"Expected finding missing: {exp_type} on {exp_sig}"

    # 2. Assert no findings on must_not_flag signatures (zero false positives)
    for f in result.findings:
        assert f.signature not in must_not_flag, (
            f"False positive finding detected on safe route: {f.type} on {f.signature}"
        )

    # 3. Assert evidence redaction: no passwords or bearer token values present
    prohibited_strings = ["alice-pass", "bob-pass", "admin-pass"]
    prohibited_strings.extend(USER_TOKENS.values())

    for f in result.findings:
        evidence_str = json.dumps(f.evidence)
        for secret in prohibited_strings:
            assert secret not in evidence_str, f"Credential leaked in evidence: {secret}"
