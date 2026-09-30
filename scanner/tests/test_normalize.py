"""Unit tests for response body normalization."""

from aegis_scanner.diff.normalize import normalize_body


def test_normalize_json_volatile_keys_and_timestamps():
    json_text = """
    {
        "id": 42,
        "username": "alice",
        "created_at": "2026-05-12T14:32:10Z",
        "timestamp": 1715524330,
        "csrf": "csrf-secret-nonce-12345",
        "nested": {
            "token": "volatile_token",
            "date": "2026-05-12 14:32:10",
            "value": "actual_data"
        }
    }
    """
    norm = normalize_body(json_text, content_type="application/json")
    assert norm.kind == "json"
    assert norm.flat is not None

    # Volatile keys removed
    assert "timestamp" not in norm.flat
    assert "csrf" not in norm.flat
    assert "nested.token" not in norm.flat
    assert "created_at" not in norm.flat
    assert "nested.date" not in norm.flat

    # Persistent keys kept
    assert norm.flat["id"] == "42"
    assert norm.flat["username"] == "alice"
    assert norm.flat["nested.value"] == "actual_data"


def test_normalize_html_removes_noise():
    html_text = """
    <html>
        <head>
            <script>console.log("noisy tracking script");</script>
            <style>body { color: red; }</style>
        </head>
        <body>
            <!-- Secret developer comment -->
            <form action="/login">
                <input type="hidden" name="csrf" value="9876543210fedcba9876543210fedcba" />
                <input type="hidden" name="_csrf" value="12345" />
                <h1>Welcome Back User!</h1>
                <p>Generated at: 2026-05-12T14:32:10Z with session 0123456789abcdef0123456789abcdef</p>
            </form>
        </body>
    </html>
    """
    norm = normalize_body(html_text, content_type="text/html")
    assert norm.kind == "text"

    # Lowercased visible text
    assert "welcome back user!" in norm.text

    # Script, style, comment, and csrf inputs removed
    assert "noisy tracking script" not in norm.text
    assert "color: red" not in norm.text
    assert "secret developer comment" not in norm.text
    assert "9876543210fedcba9876543210fedcba" not in norm.text
    assert "2026-05-12t14:32:10z" not in norm.text
    assert "0123456789abcdef0123456789abcdef" not in norm.text
