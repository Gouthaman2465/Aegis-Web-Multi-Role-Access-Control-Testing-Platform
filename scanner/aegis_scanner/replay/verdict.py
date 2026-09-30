"""Response classification to determine if a replayed request was denied, allowed, or errored."""

import json
import re
from aegis_scanner.models import RecordedRequest, ReplayResult

SOFT_DENIAL_RE = re.compile(
    r"(?i)access denied|not authori[sz]ed|unauthori[sz]ed|forbidden|permission|"
    r"please (log|sign) ?in|login required|invalid token|session expired"
)

PASSWORD_INPUT_RE = re.compile(r'<input[^>]*type=["\']password["\']', re.IGNORECASE)

ERROR_KEY_SET = {"error", "message", "status", "code", "detail"}
ERROR_VAL_RE = re.compile(
    r"(?i)error|fail|denied|unauthori[sz]ed|forbidden|invalid|expired|not allowed"
)


def classify_response(
    result: ReplayResult,
    original: RecordedRequest,
    login_url_hint: str = "",
) -> str:
    """Classify the replay outcome as 'denied', 'allowed', or 'error'."""
    if result.error or result.status == 0 or result.status >= 500:
        return "error"

    # Explicit HTTP denial or missing resource
    if result.status in (401, 403, 404, 410):
        return "denied"

    # Redirects away from resource (e.g. 302 to login)
    if 300 <= result.status < 400:
        return "denied"

    # 2xx responses (must inspect for soft denials)
    if 200 <= result.status < 300:
        body = result.body or ""
        orig_body = original.response_body or ""

        # (c) Replay returned a login form (password input) where original had none
        if PASSWORD_INPUT_RE.search(body) and not PASSWORD_INPUT_RE.search(orig_body):
            return "denied"

        # (a) Small body with explicit access-denied keywords
        if len(body) < 1500 and SOFT_DENIAL_RE.search(body):
            return "denied"

        # (b) JSON error response with error/status keys
        if body.strip().startswith("{"):
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict) and parsed:
                    keys = {str(k).lower() for k in parsed.keys()}
                    if keys.issubset(ERROR_KEY_SET):
                        for val in parsed.values():
                            if isinstance(val, (int, float)) and int(val) in (401, 403, 404, 400):
                                return "denied"
                            if isinstance(val, str) and ERROR_VAL_RE.search(val):
                                return "denied"
                            if isinstance(val, bool) and not val:  # e.g. success: false
                                return "denied"
            except Exception:
                pass

        return "allowed"

    return "denied"
