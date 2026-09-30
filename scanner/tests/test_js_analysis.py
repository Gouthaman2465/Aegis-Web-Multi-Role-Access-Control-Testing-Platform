"""Unit tests for JavaScript analysis module (Phase 10)."""

import pytest
from unittest.mock import MagicMock, patch

from aegis_scanner.models import AccountConfig, RecordedRequest, ReplayResult, ScanConfig
from aegis_scanner.modules.js_analysis import (
    shannon_entropy,
    mask_secret,
    extract_secrets,
    extract_endpoints,
    check_source_map,
    run_js_analysis,
)


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("AAAAAAAAAAAA") == 0.0
    # Simple low-entropy patterns
    low_ent = shannon_entropy("1234123412341234")
    assert low_ent < 3.0
    # High-entropy random strings
    high_ent = shannon_entropy("f9a2b8c7d6e501234abcde")
    assert high_ent >= 3.5


def test_mask_secret():
    # Long secrets: preserve first 4 and last 2
    raw = "AKIAIOSFODNN7EXAMPLE"
    masked = mask_secret(raw)
    assert masked.startswith("AKIA")
    assert masked.endswith("LE")
    assert "OSFODNN7EXAMP" not in masked

    # 16-char secret
    raw16 = "d8f7a6e5b4c3210f"
    masked16 = mask_secret(raw16)
    assert masked16.startswith("d8f7")
    assert masked16.endswith("0f")

    # Short secret edge cases
    assert mask_secret("123") == "***"
    assert mask_secret("12345") == "***"


def test_extract_secrets_aws_and_google():
    content = """
    // Config file
    const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    const GOOGLE_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu";
    const OTHER_STR = "Hello World";
    """
    secrets = extract_secrets(content, script_url="http://target.test/static/app.js")
    assert len(secrets) == 2

    types = {s["secret_type"] for s in secrets}
    assert "AWS Access Key ID" in types
    assert "Google API Key" in types

    for s in secrets:
        assert s["script_url"] == "http://target.test/static/app.js"
        assert "AKIAIOSFODNN7EXAMPLE" not in s["masked_secret"]
        assert s["masked_secret"].startswith("AKIA") or s["masked_secret"].startswith("AIza")


def test_extract_secrets_private_keys():
    content = """
    const key = `-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA...
    -----END RSA PRIVATE KEY-----`;
    """
    secrets = extract_secrets(content, script_url="http://target.test/app.js")
    assert len(secrets) == 1
    assert secrets[0]["secret_type"] == "Private Key"
    assert secrets[0]["masked_secret"] == "-----BEGIN...KEY-----"


def test_extract_secrets_generic_with_entropy():
    content = """
    // High-entropy token
    const apiKey = "d8f7a6e5b4c3210f9a8b7c6d5e4f3a2b";
    // Low-entropy false positives
    const dummyKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const exampleKey = "EXAMPLE_KEY_12345678901234567890";
    """
    secrets = extract_secrets(content, script_url="http://target.test/app.js")
    assert len(secrets) == 1
    assert secrets[0]["secret_type"] == "Generic Secret/Token"
    assert secrets[0]["masked_secret"].startswith("d8f7")
    assert secrets[0]["masked_secret"].endswith("2b")


def test_extract_endpoints():
    base_url = "http://target.test"
    content = """
    fetch('/api/v1/users');
    const legacy = "/api/legacy/export";
    const admin = "/admin/settings";
    const gql = "http://target.test/graphql";
    const rest = '/rest/items';
    // Out of scope / external origin
    const ext = "https://evil.example/api/steal";
    // Not API endpoints
    const css = "/static/style.css";
    const banner = "Welcome to /admin page";
    """
    eps = extract_endpoints(content, base_url)
    assert "http://target.test/api/v1/users" in eps
    assert "http://target.test/api/legacy/export" in eps
    assert "http://target.test/admin/settings" in eps
    assert "http://target.test/graphql" in eps
    assert "http://target.test/rest/items" in eps

    assert "https://evil.example/api/steal" not in eps
    assert "http://target.test/static/style.css" not in eps


def test_check_source_map():
    config = ScanConfig(
        base_url="http://target.test",
        scope_hosts=["target.test"],
        accounts=[],
        allow_private=True,
    )
    content = "function test() {}\n//# sourceMappingURL=app.js.map"

    # Mock successful source map retrieval
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"version": 3, "sources": ["src/index.js", "src/auth.js"]}

    with patch("aegis_scanner.modules.js_analysis.validate_url", return_value=True), \
         patch("httpx.Client.get", return_value=mock_resp):
        res = check_source_map(content, "http://target.test/app.js", config)
        assert res is not None
        assert res["map_url"] == "http://target.test/app.js.map"
        assert res["source_count"] == 2


def test_run_js_analysis_full_flow():
    base_url = "http://target.test"
    acc = AccountConfig(
        label="admin",
        privilege_level=100,
        login_url="http://target.test/login",
        username="admin",
        password="secret",
        username_selector="u",
        password_selector="p",
        submit_selector="s",
    )
    config = ScanConfig(
        base_url=base_url,
        scope_hosts=["target.test"],
        accounts=[acc],
        allow_private=True,
        modules=["access_control", "js_analysis"],
    )

    script_body = """
    const KEY = "AKIAIOSFODNN7EXAMPLE";
    const EXPORT = "/api/legacy/export";
    """
    script_req = RecordedRequest(
        account_label="admin",
        method="GET",
        url="http://target.test/static/app.js",
        headers={},
        body=None,
        resource_type="script",
        status=200,
        response_headers={},
        response_body=script_body,
        content_type="application/javascript",
        signature="GET /static/app.js",
    )

    mock_replayer = MagicMock()
    mock_replayer.send.return_value = ReplayResult(
        status=200,
        headers={"content-type": "application/json"},
        body='{"users": [{"id": 1, "name": "admin"}]}',
    )

    findings, synthetic_reqs = run_js_analysis(
        recorded_scripts=[script_req],
        config=config,
        replayer=mock_replayer,
        report=lambda st, pct, msg, lvl: None,
    )

    assert len(findings) == 1
    assert findings[0].type == "HARDCODED_SECRET"
    assert findings[0].severity == "Medium"
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].evidence["masked_secret"]

    assert len(synthetic_reqs) == 1
    assert synthetic_reqs[0].url == "http://target.test/api/legacy/export"
    assert synthetic_reqs[0].account_label == "admin"
    assert synthetic_reqs[0].signature == "GET /api/legacy/export"
