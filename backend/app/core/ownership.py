"""Target domain ownership verification token generation and HTTP validation."""

import hmac
import secrets
from urllib.parse import urljoin
from aegis_scanner.net_guard import safe_get
from app.models.target import Target


def new_ownership_token() -> str:
    """Generate a random 32-character hexadecimal ownership verification token."""
    return secrets.token_hex(16)


def verify_ownership(target: Target) -> bool:
    """Verify ownership of target by requesting /.well-known/aegis-verification.txt via safe_get."""
    verification_url = urljoin(target.base_url.rstrip("/") + "/", ".well-known/aegis-verification.txt")

    try:
        # Strict outbound SSRF check: allow_private=False (lab mode targets bypass verification)
        resp = safe_get(verification_url, allow_private=False, max_bytes=4096)
        if resp.status_code != 200:
            return False

        received_token = resp.text.strip()
        expected_token = target.ownership_token.strip()

        return hmac.compare_digest(received_token, expected_token)
    except Exception:
        return False
