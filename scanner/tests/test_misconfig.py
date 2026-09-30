"""Unit tests for web misconfiguration checks (Phase 11)."""

import pytest
from unittest.mock import MagicMock, patch

from aegis_scanner.models import AccountConfig, RecordedRequest, ReplayResult, ScanConfig
from aegis_scanner.modules.misconfig import (
    check_cors,
    check_exposed_files,
    check_open_redirect,
    check_cookie_flags,
    run_misconfig_checks,
)


def test_cors_reflection_with_credentials():
    config = ScanConfig(
        base_url="http://target.test",
        scope_hosts=["target.test"],
        accounts=[],
        allow_private=True,
    )
    req = RecordedRequest(
        account_label="alice",
        method="GET",
        url="http://target.test/api/cors-reflect",
        headers={"Authorization": "Bearer token"},
        body=None,
        resource_type="fetch",
        status=200,
        response_headers={},
        response_body='{"status": "ok"}',
        content_type="application/json",
        signature="GET /api/cors-reflect",
    )

    mock_replayer = MagicMock()
    mock_replayer.send.return_value = ReplayResult(
        status=200,
        headers={
            "access-control-allow-origin": "https://evil.example",
            "access-control-allow-credentials": "true",
        },
        body='{"status": "ok"}',
    )

    findings = check_cors([req], config, mock_replayer)
    assert len(findings) == 1
    assert findings[0].type == "CORS_MISCONFIGURATION"
    assert findings[0].severity == "High"
    assert findings[0].signature == "GET /api/cors-reflect"


def test_cors_null_origin_with_credentials():
    config = ScanConfig(
        base_url="http://target.test",
        scope_hosts=["target.test"],
        accounts=[],
        allow_private=True,
    )
    req = RecordedRequest(
        account_label="alice",
        method="GET",
        url="http://target.test/api/data",
        headers={},
        body=None,
        resource_type="fetch",
        status=200,
        response_headers={},
        response_body='{}',
        content_type="application/json",
        signature="GET /api/data",
    )

    # First call (evil.example) returns nothing, second call (null) returns null origin + creds
    res_evil = ReplayResult(status=200, headers={}, body='{}')
    res_null = ReplayResult(
        status=200,
        headers={"access-control-allow-origin": "null", "access-control-allow-credentials": "true"},
        body='{}',
    )
    mock_replayer = MagicMock()
    mock_replayer.send.side_effect = [res_evil, res_null]

    findings = check_cors([req], config, mock_replayer)
    assert len(findings) == 1
    assert findings[0].severity == "Medium"
    assert "Null Origin" in findings[0].title


def test_exposed_files_soft_404_ignored():
    config = ScanConfig(
        base_url="http://target.test",
        scope_hosts=["target.test"],
        accounts=[],
        allow_private=True,
    )
    # The baseline soft 404 page
    baseline_body = "<html><body><h1>Page Not Found</h1><p>The requested URL was not found.</p></body></html>"
    baseline_res = ReplayResult(status=200, headers={"content-type": "text/html"}, body=baseline_body)

    # A server serving the same soft 404 for /.git/HEAD
    git_soft_404 = ReplayResult(status=200, headers={"content-type": "text/html"}, body=baseline_body)

    mock_replayer = MagicMock()
    # Baseline 404 call, then git/HEAD probe, then remaining probes
    mock_replayer.send.side_effect = [baseline_res, git_soft_404] + [
        ReplayResult(status=404, headers={}, body="not found") for _ in range(10)
    ]

    findings = check_exposed_files(config, mock_replayer)
    # Should ignore /.git/HEAD because similarity with baseline is 1.0
    assert len(findings) == 0


def test_exposed_files_real_git_and_env():
    config = ScanConfig(
        base_url="http://target.test",
        scope_hosts=["target.test"],
        accounts=[],
        allow_private=True,
    )
    baseline_res = ReplayResult(status=404, headers={"content-type": "text/plain"}, body="Not Found")
    git_res = ReplayResult(
        status=200,
        headers={"content-type": "text/plain"},
        body="ref: refs/heads/main\n",
    )
    env_res = ReplayResult(
        status=200,
        headers={"content-type": "text/plain"},
        body="APP_KEY=secret-token-value\nDB_PASS=mypassword\n",
    )

    mock_replayer = MagicMock()
    # Baseline, git/HEAD, .env, and 404 for the rest
    mock_replayer.send.side_effect = [baseline_res, git_res, env_res] + [
        ReplayResult(status=404, headers={}, body="not found") for _ in range(10)
    ]

    findings = check_exposed_files(config, mock_replayer)
    assert len(findings) == 2
    paths = {f.evidence["path"] for f in findings}
    assert "/.git/HEAD" in paths
    assert "/.env" in paths
    for f in findings:
        assert f.type == "EXPOSED_FILE"
        assert f.severity == "High"


def test_open_redirect():
    config = ScanConfig(
        base_url="http://target.test",
        scope_hosts=["target.test"],
        accounts=[],
        allow_private=True,
    )
    req = RecordedRequest(
        account_label="alice",
        method="GET",
        url="http://target.test/redirect?next=/dashboard",
        headers={},
        body=None,
        resource_type="document",
        status=302,
        response_headers={"location": "/dashboard"},
        response_body="",
        content_type="text/html",
        signature="GET /redirect?next",
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"location": "https://example.org/aegis-probe"}

    with patch("aegis_scanner.modules.misconfig.validate_url", return_value=True), \
         patch("httpx.Client.get", return_value=mock_resp):
        findings = check_open_redirect([req], config)
        assert len(findings) == 1
        assert findings[0].type == "OPEN_REDIRECT"
        assert findings[0].severity == "Medium"
        assert findings[0].evidence["parameter"] == "next"


def test_cookie_flags_audit():
    # 1. HTTP site with missing HttpOnly and missing SameSite
    config_http = ScanConfig(
        base_url="http://target.test",
        scope_hosts=["target.test"],
        accounts=[],
        allow_private=True,
    )
    req = RecordedRequest(
        account_label="alice",
        method="POST",
        url="http://target.test/login",
        headers={},
        body="",
        resource_type="document",
        status=302,
        response_headers={"set-cookie": "sid=123456; Path=/"},
        response_body="",
        content_type="text/html",
        signature="POST /login",
    )
    findings = check_cookie_flags([req], config_http)
    assert len(findings) == 2  # Missing HttpOnly, Missing SameSite (Secure NOT flagged because http)
    titles = [f.title for f in findings]
    assert any("HttpOnly" in t for t in titles)
    assert any("SameSite" in t for t in titles)
    assert not any("Secure" in t for t in titles)

    # 2. HTTPS site missing Secure flag
    config_https = ScanConfig(
        base_url="https://target.test",
        scope_hosts=["target.test"],
        accounts=[],
        allow_private=True,
    )
    findings_https = check_cookie_flags([req], config_https)
    assert len(findings_https) == 3  # HttpOnly, SameSite, Secure
    assert any("Secure" in f.title for f in findings_https)
