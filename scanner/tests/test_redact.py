"""Unit tests for header and body redaction."""

import json
from aegis_scanner.redact import redact_headers, redact_body


def test_redact_headers_case_insensitivity():
    headers = {
        "Authorization": "Bearer secret_jwt_token",
        "cookie": "sid=xyz123; session=abc",
        "SET-COOKIE": "sid=xyz123",
        "X-Auth-Token": "topsecret",
        "X-Api-Key": "my-api-key",
        "Content-Type": "application/json",
        "Accept": "text/html",
    }
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["cookie"] == "[REDACTED]"
    assert redacted["SET-COOKIE"] == "[REDACTED]"
    assert redacted["X-Auth-Token"] == "[REDACTED]"
    assert redacted["X-Api-Key"] == "[REDACTED]"
    assert redacted["Content-Type"] == "application/json"
    assert redacted["Accept"] == "text/html"


def test_redact_json_nested():
    data = {
        "user": {
            "name": "Alice",
            "password": "alicepassword123",
            "metadata": {
                "secret_key": "hidden",
                "api_key": "12345",
                "nested_token": "tokenvalue",
            },
        },
        "orders": [{"id": 1, "token": "secret"}],
    }
    redacted_str = redact_body(json.dumps(data), content_type="application/json")
    parsed = json.loads(redacted_str)

    assert parsed["user"]["name"] == "Alice"
    assert parsed["user"]["password"] == "[REDACTED]"
    assert parsed["user"]["metadata"]["secret_key"] == "[REDACTED]"
    assert parsed["user"]["metadata"]["api_key"] == "[REDACTED]"
    assert parsed["user"]["metadata"]["nested_token"] == "[REDACTED]"
    assert parsed["orders"][0]["token"] == "[REDACTED]"
    assert parsed["orders"][0]["id"] == 1


def test_redact_plain_text():
    text = "Error encountered: password=mysecretpassword with token: abcdef12345"
    redacted = redact_body(text, content_type="text/plain")
    assert "password=[REDACTED]" in redacted
    assert "token: [REDACTED]" in redacted
    assert "mysecretpassword" not in redacted
    assert "abcdef12345" not in redacted
