"""Session and authentication state capture (cookies and inferred tokens)."""

from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Sequence

from aegis_scanner.models import RecordedRequest

AUTH_HEADER_NAMES = {
    "authorization",
    "x-auth-token",
    "x-access-token",
    "x-api-key",
    "token",
}


@dataclass
class AuthState:
    """Authentication artifacts captured for an account during recording."""
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    def cookie_header_for(self, url: str) -> str | None:
        """Construct a Cookie header value matching the destination domain, path, and scheme."""
        if not self.cookies:
            return None

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        is_https = parsed.scheme.lower() == "https"

        matching = []
        for c in self.cookies:
            c_domain = (c.get("domain") or "").lstrip(".").lower()
            c_path = c.get("path") or "/"
            c_secure = bool(c.get("secure", False))

            if c_secure and not is_https:
                continue

            # Check domain matching
            if c_domain:
                if host != c_domain and not host.endswith("." + c_domain):
                    continue

            # Check path prefix matching
            if not path.startswith(c_path):
                continue

            matching.append(f"{c['name']}={c['value']}")

        return "; ".join(matching) if matching else None


def build_auth_state(cookies: list[dict], recorded: Sequence[RecordedRequest]) -> AuthState:
    """Build an AuthState by extracting cookies and inferring frequent auth headers."""
    header_candidates: dict[str, list[str]] = {name: [] for name in AUTH_HEADER_NAMES}

    for req in recorded:
        for k, v in req.headers.items():
            k_lower = k.lower()
            if k_lower in header_candidates and v:
                header_candidates[k_lower].append((k, v))

    inferred_headers: dict[str, str] = {}
    for k_lower, instances in header_candidates.items():
        if instances:
            # Count values to choose the dominant authenticated credential
            values = [v for _, v in instances]
            most_common_val = Counter(values).most_common(1)[0][0]
            # Use original casing of the header name from the first occurrence
            orig_name = next(k for k, v in instances if v == most_common_val)
            inferred_headers[orig_name] = most_common_val

    return AuthState(cookies=list(cookies), headers=inferred_headers)
