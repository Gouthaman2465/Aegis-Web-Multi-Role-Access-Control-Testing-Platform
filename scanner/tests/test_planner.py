"""Unit tests for the replay planner."""

from aegis_scanner.diff.normalize import normalize_body
from aegis_scanner.models import AccountConfig, RecordedRequest, ScanConfig
from aegis_scanner.replay.planner import build_replay_plan


def _make_req(
    account_label="alice",
    method="GET",
    url="http://example.com/orders/1",
    status=200,
    resource_type="document",
    body="<html><body><h1>Order 1 content here</h1></body></html>",
    signature="GET /orders/{id}",
):
    return RecordedRequest(
        account_label=account_label,
        method=method,
        url=url,
        headers={},
        body=None,
        resource_type=resource_type,
        status=status,
        response_headers={},
        response_body=body,
        content_type="text/html",
        signature=signature,
    )


def test_planner_role_filtering():
    accounts = [
        AccountConfig(
            label="admin",
            privilege_level=100,
            login_url="",
            username="admin",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
        AccountConfig(
            label="alice",
            privilege_level=10,
            login_url="",
            username="alice",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
        AccountConfig(
            label="bob",
            privilege_level=10,
            login_url="",
            username="bob",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
    ]
    config = ScanConfig(base_url="http://example.com", scope_hosts=["example.com"], accounts=accounts)

    # Alice (priv 10) request: tested by peer Bob (priv 10) and anonymous (None).
    # Higher role Admin (priv 100) must NOT be planned to test Alice.
    req_alice = _make_req(account_label="alice", url="http://example.com/orders/1")
    plan_alice = build_replay_plan([req_alice], accounts, config)

    tested_roles = {t.tested for t in plan_alice}
    assert tested_roles == {"bob", None}
    assert "admin" not in tested_roles

    # Admin (priv 100) request: tested by Alice (10), Bob (10), and anonymous (None).
    req_admin = _make_req(account_label="admin", url="http://example.com/admin/users")
    plan_admin = build_replay_plan([req_admin], accounts, config)
    tested_roles_admin = {t.tested for t in plan_admin}
    assert tested_roles_admin == {"alice", "bob", None}


def test_planner_skips_invalid_requests():
    accounts = [
        AccountConfig(
            label="user1",
            privilege_level=10,
            login_url="",
            username="u1",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
        AccountConfig(
            label="user2",
            privilege_level=10,
            login_url="",
            username="u2",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
    ]
    config = ScanConfig(base_url="http://example.com", scope_hosts=["example.com"], accounts=accounts)

    # 1. Non-GET (POST)
    req_post = _make_req(method="POST")
    # 2. Non-2xx (404)
    req_404 = _make_req(status=404)
    # 3. Script resource type
    req_script = _make_req(resource_type="script")
    # 4. Empty/short body
    req_short = _make_req(body="short")
    # 5. Static file
    req_static = _make_req(url="http://example.com/style.css")
    # 6. Logout URL
    req_logout = _make_req(url="http://example.com/api/logout")
    # 7. Password form in original
    req_login = _make_req(body='<form><input type="password" name="p" /></form>')

    requests = [req_post, req_404, req_script, req_short, req_static, req_logout, req_login]
    plan = build_replay_plan(requests, accounts, config)
    assert len(plan) == 0


def test_planner_skips_app_shell():
    accounts = [
        AccountConfig(
            label="u1",
            privilege_level=10,
            login_url="",
            username="u1",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
        AccountConfig(
            label="u2",
            privilege_level=10,
            login_url="",
            username="u2",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
    ]
    config = ScanConfig(base_url="http://example.com", scope_hosts=["example.com"], accounts=accounts)

    shell_html = "<html><head><title>SPA</title></head><body><div id='root'></div></body></html>"
    app_shell = normalize_body(shell_html, "text/html")

    req_shell = _make_req(body=shell_html)
    plan = build_replay_plan([req_shell], accounts, config, app_shell_fingerprint=app_shell)
    assert len(plan) == 0


def test_planner_caps():
    accounts = [
        AccountConfig(
            label="u1",
            privilege_level=10,
            login_url="",
            username="u1",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
        AccountConfig(
            label="u2",
            privilege_level=10,
            login_url="",
            username="u2",
            password="",
            username_selector="",
            password_selector="",
            submit_selector="",
        ),
    ]
    # Max replays cap: 4
    config = ScanConfig(
        base_url="http://example.com",
        scope_hosts=["example.com"],
        accounts=accounts,
        max_replays=4,
    )

    # 10 distinct URLs with the same signature GET /orders/{id}
    requests = [
        _make_req(
            account_label="u1",
            url=f"http://example.com/orders/{i}",
            signature="GET /orders/{id}",
        )
        for i in range(10)
    ]
    # Per-signature cap allows max 5 distinct URLs.
    # Each URL generates 2 tasks (peer user2 + anonymous None).
    # 5 * 2 = 10 tasks, capped at max_replays = 4.
    plan = build_replay_plan(requests, accounts, config)
    assert len(plan) == 4
