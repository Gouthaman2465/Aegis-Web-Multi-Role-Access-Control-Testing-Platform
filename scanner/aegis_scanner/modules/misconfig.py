"""Stage 2 Module: Web Security Misconfiguration Checks.

Implements active and passive checks for:
- CORS misconfigurations (arbitrary origin reflection with/without credentials, null origin)
- Exposed sensitive files (/.git/HEAD, /.env, etc.) with soft-404 baseline diffing
- Open redirects via URL query parameters
- Missing cookie security flags (HttpOnly, SameSite, Secure)
"""

from http.cookies import SimpleCookie
import re
import secrets
from typing import Callable, Optional
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse

import httpx

from aegis_scanner.cvss import base_score, severity_from_score
from aegis_scanner.diff.compare import similarity
from aegis_scanner.diff.normalize import normalize_body
from aegis_scanner.models import (
    FindingResult,
    RecordedRequest,
    ReplayResult,
    ScanConfig,
)
from aegis_scanner.net_guard import host_in_scope, validate_url
from aegis_scanner.redact import redact_body, redact_headers
from aegis_scanner.replay.replayer import Replayer
from aegis_scanner.signature import make_signature


# ---------------------------------------------------------------------------
# Constants & Regexes
# ---------------------------------------------------------------------------

REDIRECT_PARAM_RE = re.compile(
    r"^(redirect|url|next|return|returnurl|redirect_uri|continue|dest)$",
    re.IGNORECASE,
)

SESSION_COOKIE_RE = re.compile(
    r"^(sid|session|sess|sessionid|sessid|phpsessid|jsessionid|token|jwt|auth)$",
    re.IGNORECASE,
)

ENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*", re.MULTILINE)

EXPOSED_FILE_PROBES = [
    ("/.git/HEAD", "git"),
    ("/.env", "env"),
    ("/.DS_Store", "ds_store"),
    ("/backup.zip", "zip"),
    ("/config.json", "json"),
    ("/phpinfo.php", "phpinfo"),
    ("/server-status", "apache"),
]


# ---------------------------------------------------------------------------
# Individual Check Functions
# ---------------------------------------------------------------------------

def check_cors(
    recorded_requests: list[RecordedRequest],
    config: ScanConfig,
    replayer: Replayer,
) -> list[FindingResult]:
    """Test authenticated endpoints for permissive CORS reflection configurations."""
    findings: list[FindingResult] = []
    seen_signatures: set[str] = set()

    # Select up to 20 authenticated GET requests
    auth_reqs: list[RecordedRequest] = []
    for r in recorded_requests:
        if r.method.upper() != "GET" or r.account_label in ("", "anonymous"):
            continue
        if r.signature not in seen_signatures:
            seen_signatures.add(r.signature)
            auth_reqs.append(r)
            if len(auth_reqs) >= 20:
                break

    evil_origin = "https://evil.example"

    for req in auth_reqs:
        # Probe 1: Arbitrary evil origin
        probe_headers = {"Origin": evil_origin}
        dummy = RecordedRequest(
            account_label=req.account_label,
            method="GET",
            url=req.url,
            headers=probe_headers,
            body=None,
            resource_type="xhr",
            status=200,
            response_headers={},
            response_body=None,
            content_type=None,
            signature=req.signature,
        )
        res = replayer.send(dummy, as_label=req.account_label)
        allow_origin = res.headers.get("access-control-allow-origin", "").strip()
        allow_creds = res.headers.get("access-control-allow-credentials", "").strip().lower() == "true"

        if allow_origin == evil_origin and allow_creds:
            findings.append(
                FindingResult(
                    type="CORS_MISCONFIGURATION",
                    title=f"CORS Misconfiguration: Arbitrary Origin with Credentials on {req.signature}",
                    severity="High",
                    confidence=95,
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    cwe="CWE-942",
                    owasp="A01:2021 - Broken Access Control",
                    method="GET",
                    url=req.url,
                    signature=req.signature,
                    source_role=req.account_label,
                    tested_role="anonymous",
                    description=(
                        f"The endpoint at '{req.url}' reflected an untrusted Origin header "
                        f"('{evil_origin}') and enabled Access-Control-Allow-Credentials: true. "
                        "This permits malicious websites to read sensitive authenticated responses."
                    ),
                    remediation="Specify explicit, trusted origins in Access-Control-Allow-Origin and never reflect request origins when credentials are enabled.",
                    evidence={
                        "tested_origin": evil_origin,
                        "allow_origin": allow_origin,
                        "allow_credentials": "true",
                        "status": res.status,
                    },
                )
            )
            continue
        elif allow_origin == evil_origin and not allow_creds:
            findings.append(
                FindingResult(
                    type="CORS_MISCONFIGURATION",
                    title=f"CORS Misconfiguration: Arbitrary Origin Reflected on {req.signature}",
                    severity="Low",
                    confidence=85,
                    cvss_score=4.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cwe="CWE-942",
                    owasp="A01:2021 - Broken Access Control",
                    method="GET",
                    url=req.url,
                    signature=req.signature,
                    source_role=req.account_label,
                    tested_role="anonymous",
                    description=(
                        f"The endpoint at '{req.url}' reflected an untrusted Origin header "
                        f"('{evil_origin}') without credentials."
                    ),
                    remediation="Maintain a strict whitelist of permitted origins.",
                    evidence={"tested_origin": evil_origin, "allow_origin": allow_origin, "status": res.status},
                )
            )
            continue

        # Probe 2: Null origin with credentials
        dummy_null = RecordedRequest(
            account_label=req.account_label,
            method="GET",
            url=req.url,
            headers={"Origin": "null"},
            body=None,
            resource_type="xhr",
            status=200,
            response_headers={},
            response_body=None,
            content_type=None,
            signature=req.signature,
        )
        res_null = replayer.send(dummy_null, as_label=req.account_label)
        allow_origin_null = res_null.headers.get("access-control-allow-origin", "").strip()
        allow_creds_null = res_null.headers.get("access-control-allow-credentials", "").strip().lower() == "true"

        if allow_origin_null.lower() == "null" and allow_creds_null:
            findings.append(
                FindingResult(
                    type="CORS_MISCONFIGURATION",
                    title=f"CORS Misconfiguration: Null Origin with Credentials on {req.signature}",
                    severity="Medium",
                    confidence=90,
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    cwe="CWE-942",
                    owasp="A01:2021 - Broken Access Control",
                    method="GET",
                    url=req.url,
                    signature=req.signature,
                    source_role=req.account_label,
                    tested_role="anonymous",
                    description=(
                        f"The endpoint at '{req.url}' permits the 'null' Origin with credentials. "
                        "Sandboxed iframes and local file contexts execute with a null origin and can access this resource."
                    ),
                    remediation="Do not trust the 'null' origin.",
                    evidence={"tested_origin": "null", "allow_origin": "null", "allow_credentials": "true", "status": res_null.status},
                )
            )

    return findings


def check_exposed_files(
    config: ScanConfig,
    replayer: Replayer,
) -> list[FindingResult]:
    """Probe for exposed sensitive files, diffing against a dynamic soft-404 baseline."""
    findings: list[FindingResult] = []

    # 1. Establish soft-404 baseline
    rand_suffix = secrets.token_hex(8)
    soft404_url = urljoin(config.base_url, f"/_aegis_baseline_404_{rand_suffix}")
    soft404_req = RecordedRequest(
        account_label="anonymous",
        method="GET",
        url=soft404_url,
        headers={"Accept": "*/*"},
        body=None,
        resource_type="document",
        status=404,
        response_headers={},
        response_body=None,
        content_type="text/html",
        signature=make_signature("GET", soft404_url),
    )
    baseline_res = replayer.send(soft404_req, as_label=None)
    norm_baseline = normalize_body(baseline_res.body or "", baseline_res.headers.get("content-type"))

    # 2. Probe candidate sensitive files
    for path, probe_type in EXPOSED_FILE_PROBES:
        probe_url = urljoin(config.base_url, path)
        probe_req = RecordedRequest(
            account_label="anonymous",
            method="GET",
            url=probe_url,
            headers={"Accept": "*/*"},
            body=None,
            resource_type="document",
            status=200,
            response_headers={},
            response_body=None,
            content_type=None,
            signature=make_signature("GET", probe_url),
        )
        res = replayer.send(probe_req, as_label=None)

        if not (200 <= res.status < 300) or not res.body:
            continue

        # Soft-404 similarity filter: if similar >= 0.9 to baseline 404, it's a custom 404 page
        norm_probe = normalize_body(res.body, res.headers.get("content-type"))
        sim = similarity(norm_probe, norm_baseline)
        if sim >= 0.9:
            continue

        # Content validation
        body_text = res.body
        body_lower = body_text.lower()
        is_valid = False

        if probe_type == "git":
            is_valid = body_text.startswith("ref:") or "ref: refs/" in body_text
        elif probe_type == "env":
            # Must not be HTML, must have KEY=value format
            not_html = ("<html" not in body_lower) and ("<!doctype" not in body_lower)
            has_env_lines = bool(ENV_LINE_RE.search(body_text))
            is_valid = not_html and has_env_lines
        elif probe_type == "ds_store":
            is_valid = "Bud1" in body_text or "\x00\x00\x00\x01Bud1" in body_text
        elif probe_type == "zip":
            is_valid = body_text.startswith("PK\x03\x04")
        elif probe_type == "json":
            is_valid = "{" in body_text and any(k in body_lower for k in ("secret", "password", "env", "database"))
        elif probe_type == "phpinfo":
            is_valid = "php version" in body_lower or "phpinfo()" in body_lower
        elif probe_type == "apache":
            is_valid = "apache server status" in body_lower

        if is_valid:
            sev = "High" if path in ("/.git/HEAD", "/.env") else "Medium"
            score = 7.5 if sev == "High" else 5.3
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if sev == "High" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

            findings.append(
                FindingResult(
                    type="EXPOSED_FILE",
                    title=f"Sensitive file exposed: {path}",
                    severity=sev,
                    confidence=95,
                    cvss_score=score,
                    cvss_vector=vector,
                    cwe="CWE-538",
                    owasp="A05:2021 - Security Misconfiguration",
                    method="GET",
                    url=probe_url,
                    signature=make_signature("GET", probe_url),
                    source_role="scanner",
                    tested_role="anonymous",
                    description=(
                        f"Sensitive file '{path}' is publicly accessible at '{probe_url}'. "
                        "The response was validated against custom 404 baselines and contained genuine file indicators."
                    ),
                    remediation=f"Block public access to '{path}' in your web server configuration or remove it from the web root.",
                    evidence={
                        "path": path,
                        "url": probe_url,
                        "status": res.status,
                        "content_preview": redact_body(body_text[:500]),
                        "soft_404_similarity": round(sim, 3),
                    },
                )
            )

    return findings


def check_open_redirect(
    recorded_requests: list[RecordedRequest],
    config: ScanConfig,
) -> list[FindingResult]:
    """Test query parameters matching redirect parameter names for open redirect vulnerabilities."""
    findings: list[FindingResult] = []
    seen_endpoints: set[str] = set()

    probe_destination = "https://example.org/aegis-probe"

    for req in recorded_requests:
        parsed = urlparse(req.url)
        if not parsed.query:
            continue

        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        for param_name, orig_val in qsl:
            if not REDIRECT_PARAM_RE.match(param_name):
                continue

            test_sig = f"{req.signature}:{param_name}"
            if test_sig in seen_endpoints:
                continue
            seen_endpoints.add(test_sig)

            # Build probe URL with parameter replaced
            new_qsl = [(k, probe_destination if k == param_name else v) for k, v in qsl]
            new_query = urlencode(new_qsl)
            probe_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))

            try:
                validate_url(probe_url, allow_private=config.allow_private)
                with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=False) as client:
                    resp = client.get(probe_url)
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location", "").strip()
                        if loc.startswith(probe_destination):
                            findings.append(
                                FindingResult(
                                    type="OPEN_REDIRECT",
                                    title=f"Open Redirect on {make_signature('GET', req.url)}",
                                    severity="Medium",
                                    confidence=95,
                                    cvss_score=6.1,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    cwe="CWE-601",
                                    owasp="A01:2021 - Broken Access Control",
                                    method="GET",
                                    url=req.url,
                                    signature=make_signature("GET", req.url),
                                    source_role="scanner",
                                    tested_role="anonymous",
                                    description=(
                                        f"The parameter '{param_name}' at '{req.url}' redirected the user to "
                                        f"an arbitrary external URL ('{loc}') with status {resp.status_code}. "
                                        "Attackers can leverage open redirects in phishing attacks to bypass security filters."
                                    ),
                                    remediation="Validate redirect destinations against a strict domain whitelist or use relative path redirects only.",
                                    evidence={
                                        "parameter": param_name,
                                        "probe_url": probe_url,
                                        "location": loc,
                                        "status_code": resp.status_code,
                                    },
                                )
                            )
            except Exception:
                pass

    return findings


def check_cookie_flags(
    recorded_requests: list[RecordedRequest],
    config: ScanConfig,
) -> list[FindingResult]:
    """Audit recorded Set-Cookie headers for missing security flags."""
    findings: list[FindingResult] = []
    audited_cookies: set[str] = set()

    is_https = config.base_url.lower().startswith("https://")

    for req in recorded_requests:
        set_cookie = req.response_headers.get("set-cookie") or req.response_headers.get("Set-Cookie")
        if not set_cookie:
            continue

        # Split multiple cookies if present
        cookie_headers = [c.strip() for c in set_cookie.split("\n") if c.strip()]
        for ch in cookie_headers:
            parts = [p.strip() for p in ch.split(";") if p.strip()]
            if not parts:
                continue

            first_part = parts[0]
            if "=" not in first_part:
                continue
            name, _ = first_part.split("=", 1)
            name = name.strip()

            if name in audited_cookies:
                continue
            audited_cookies.add(name)

            if not SESSION_COOKIE_RE.match(name):
                continue

            attrs = {p.split("=")[0].strip().lower(): (p.split("=")[1].strip() if "=" in p else True) for p in parts[1:]}

            # 1. Missing HttpOnly
            if "httponly" not in attrs:
                findings.append(
                    FindingResult(
                        type="COOKIE_SECURITY",
                        title=f"Session cookie '{name}' missing HttpOnly flag",
                        severity="Low",
                        confidence=90,
                        cvss_score=3.7,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe="CWE-1004",
                        owasp="A05:2021 - Security Misconfiguration",
                        method="GET",
                        url=req.url,
                        signature=req.signature,
                        source_role="scanner",
                        tested_role="anonymous",
                        description=f"Session cookie '{name}' is missing the 'HttpOnly' flag, allowing client JavaScript to access the cookie.",
                        remediation="Set the 'HttpOnly' attribute on all sensitive session and authentication cookies.",
                        evidence={"cookie_name": name, "header": redact_headers({"set-cookie": ch})["set-cookie"]},
                    )
                )

            # 2. Missing SameSite
            if "samesite" not in attrs:
                findings.append(
                    FindingResult(
                        type="COOKIE_SECURITY",
                        title=f"Session cookie '{name}' missing SameSite attribute",
                        severity="Low",
                        confidence=90,
                        cvss_score=3.7,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe="CWE-1004",
                        owasp="A05:2021 - Security Misconfiguration",
                        method="GET",
                        url=req.url,
                        signature=req.signature,
                        source_role="scanner",
                        tested_role="anonymous",
                        description=f"Session cookie '{name}' is missing the 'SameSite' attribute, increasing vulnerability to CSRF attacks.",
                        remediation="Set 'SameSite=Lax' or 'SameSite=Strict' on session cookies.",
                        evidence={"cookie_name": name, "header": redact_headers({"set-cookie": ch})["set-cookie"]},
                    )
                )

            # 3. Missing Secure (only when target uses HTTPS)
            if is_https and "secure" not in attrs:
                findings.append(
                    FindingResult(
                        type="COOKIE_SECURITY",
                        title=f"Session cookie '{name}' missing Secure flag",
                        severity="Low",
                        confidence=90,
                        cvss_score=3.7,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe="CWE-614",
                        owasp="A05:2021 - Security Misconfiguration",
                        method="GET",
                        url=req.url,
                        signature=req.signature,
                        source_role="scanner",
                        tested_role="anonymous",
                        description=f"Session cookie '{name}' was served over HTTPS without the 'Secure' attribute.",
                        remediation="Set the 'Secure' attribute on all cookies transmitted over HTTPS.",
                        evidence={"cookie_name": name, "header": redact_headers({"set-cookie": ch})["set-cookie"]},
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Module Runner
# ---------------------------------------------------------------------------

def run_misconfig_checks(
    recorded_requests: list[RecordedRequest],
    config: ScanConfig,
    replayer: Replayer,
    report: Callable[[str, int, str, str], None],
) -> list[FindingResult]:
    """Execute all web security misconfiguration checks."""
    findings: list[FindingResult] = []

    report("planning", 48, "Auditing cookie security flags from recorded traffic...", "info")
    cookie_findings = check_cookie_flags(recorded_requests, config)
    findings.extend(cookie_findings)

    report("planning", 49, "Probing for exposed repository and configuration files...", "info")
    file_findings = check_exposed_files(config, replayer)
    findings.extend(file_findings)

    report("planning", 50, "Testing for open redirect vulnerabilities in query parameters...", "info")
    redirect_findings = check_open_redirect(recorded_requests, config)
    findings.extend(redirect_findings)

    report("planning", 51, "Auditing CORS access policies on authenticated endpoints...", "info")
    cors_findings = check_cors(recorded_requests, config, replayer)
    findings.extend(cors_findings)

    return findings
