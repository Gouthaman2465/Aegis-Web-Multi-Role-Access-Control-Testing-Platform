"""Header and body redaction utilities to prevent leaking secrets in logs/evidence."""

import json
import re
from typing import Any

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-auth-token",
    "x-api-key",
    "x-access-token",
    "token",
}

JSON_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key)", re.IGNORECASE
)

NON_JSON_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key)(\s*[=:]\s*)\S+"
)


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Return a copy of headers with sensitive credential headers replaced by [REDACTED]."""
    if not headers:
        return {}
    redacted: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def _redact_json_obj(obj: Any) -> Any:
    """Recursively redact dictionary keys matching sensitive patterns."""
    if isinstance(obj, dict):
        new_dict = {}
        for k, v in obj.items():
            if JSON_SECRET_KEY_RE.search(str(k)):
                new_dict[k] = "[REDACTED]"
            else:
                new_dict[k] = _redact_json_obj(v)
        return new_dict
    elif isinstance(obj, list):
        return [_redact_json_obj(item) for item in obj]
    return obj


def redact_body(text: str | None, content_type: str | None = None) -> str:
    """Redact sensitive fields from JSON or plain text HTTP body strings."""
    if text is None:
        return ""
    if not text.strip():
        return text

    is_json = bool(content_type and "json" in content_type.lower()) or text.strip().startswith(("{", "["))
    if is_json:
        try:
            parsed = json.loads(text)
            redacted = _redact_json_obj(parsed)
            return json.dumps(redacted)
        except Exception:
            pass

    # Non-JSON fallback: regex replace key=value or key: value
    return NON_JSON_SECRET_RE.sub(r"\1\2[REDACTED]", text)
