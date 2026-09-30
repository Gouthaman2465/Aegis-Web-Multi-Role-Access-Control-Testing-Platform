"""End-to-end verification test for Playwright recorder against the lab application."""

import socket
import threading
import time
import pytest
from playwright.sync_api import sync_playwright

from aegis_scanner.models import AccountConfig, ScanConfig
from aegis_scanner.recorder.crawler import record_account
from labs.vulnerable_app.app import create_app


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def lab_server():
    port = find_free_port()
    app = create_app()
    from werkzeug.serving import make_server

    server = make_server("127.0.0.1", port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)

    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.mark.e2e
def test_recorder_captures_expected_traffic(lab_server):
    base_url = lab_server

    accounts = [
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
    ]

    config = ScanConfig(
        base_url=base_url,
        scope_hosts=["127.0.0.1", "localhost"],
        accounts=accounts,
        max_pages=15,
        max_depth=3,
        request_delay_ms=50,
        seed_paths=["/dashboard"],
        allow_private=True,
    )

    all_recorded = []
    auth_states = {}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for acc in accounts:
            recorded, auth_state = record_account(
                browser=browser,
                account=acc,
                config=config,
                report=lambda st, pct, msg, lvl: None,
                should_cancel=lambda: False,
            )
            all_recorded.extend(recorded)
            auth_states[acc.label] = auth_state
        browser.close()

    # 1. Assert logout was never requested
    for req in all_recorded:
        assert "logout" not in req.url.lower(), f"Logout URL was recorded: {req.url}"

    # 2. Check signatures captured
    signatures = {req.signature for req in all_recorded}
    assert "GET /orders/{id}" in signatures, f"GET /orders/{{id}} missing in {signatures}"
    assert "GET /api/profile/{id}" in signatures, f"GET /api/profile/{{id}} missing in {signatures}"

    # 3. Assert GET /api/profile/{id} carried a Bearer Authorization header
    profile_reqs = [r for r in all_recorded if r.signature == "GET /api/profile/{id}"]
    has_bearer = any(
        "authorization" in {k.lower(): v for k, v in r.headers.items()} and
        "bearer" in {k.lower(): v for k, v in r.headers.items()}["authorization"].lower()
        for r in profile_reqs
    )
    assert has_bearer, "Expected Bearer Authorization header on /api/profile/{id}"

    # 4. Check AuthState for each user
    for label in ("alice", "bob", "admin"):
        state = auth_states[label]
        assert state.cookies, f"No cookies captured for {label}"
        # Assert cookie_header_for returns sid cookie
        cookie_header = state.cookie_header_for(base_url)
        assert cookie_header and "sid=" in cookie_header
        # Assert auth header contains Authorization with Bearer token
        assert "Authorization" in state.headers or "authorization" in {k.lower() for k in state.headers}
