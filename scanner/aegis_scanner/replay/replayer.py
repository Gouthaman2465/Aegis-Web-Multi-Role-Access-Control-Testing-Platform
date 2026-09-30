"""Synchronous HTTP request replayer using httpx with auth injection and security guards."""

import time
from aegis_scanner.models import RecordedRequest, ReplayResult, ScanConfig
from aegis_scanner.net_guard import validate_url, BlockedTargetError
from aegis_scanner.recorder.auth_state import AuthState
import httpx

# Headers stripped from recorded requests before replaying
STRIP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "cookie",
    "authorization",
    "x-auth-token",
    "x-access-token",
    "x-api-key",
    "token",
    "transfer-encoding",
    "keep-alive",
}


class Replayer:
    """Sends recorded HTTP requests under different role identities or anonymously."""

    def __init__(self, config: ScanConfig, auth_states: dict[str, AuthState]):
        self.config = config
        self.auth_states = auth_states

    def send(self, request: RecordedRequest, as_label: str | None) -> ReplayResult:
        """Replay a recorded request using the credentials of as_label (or anonymously if None)."""
        # Validate target destination host against SSRF rules
        try:
            validate_url(request.url, allow_private=self.config.allow_private)
        except BlockedTargetError as e:
            return ReplayResult(status=0, headers={}, body="", error=f"SSRF guard blocked: {e}")

        # Filter out hop-by-hop and auth headers from original request
        headers = {}
        for k, v in request.headers.items():
            if k.lower() not in STRIP_HEADERS:
                headers[k] = v

        # Inject credentials for tested role
        if as_label is not None and as_label in self.auth_states:
            auth_state = self.auth_states[as_label]
            # Add inferred auth headers (e.g. Authorization: Bearer ...)
            for hk, hv in auth_state.headers.items():
                headers[hk] = hv

            # Add cookies matching domain/path
            cookie_val = auth_state.cookie_header_for(request.url)
            if cookie_val:
                headers["Cookie"] = cookie_val

        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=httpx.Timeout(15.0, connect=5.0),
                verify=False if self.config.allow_private else True,
            ) as client:
                with client.stream(
                    request.method,
                    request.url,
                    headers=headers,
                ) as resp:
                    body_bytes = bytearray()
                    max_bytes = 2097152  # 2 MB hard cap
                    for chunk in resp.iter_bytes():
                        body_bytes.extend(chunk)
                        if len(body_bytes) >= max_bytes:
                            body_bytes = body_bytes[:max_bytes]
                            break

                    decoded_body = bytes(body_bytes).decode("utf-8", errors="replace")
                    result = ReplayResult(
                        status=resp.status_code,
                        headers=dict(resp.headers),
                        body=decoded_body,
                    )
        except Exception as e:
            result = ReplayResult(
                status=0,
                headers={},
                body="",
                error=str(e),
            )

        if self.config.request_delay_ms > 0:
            time.sleep(self.config.request_delay_ms / 1000.0)

        return result
