"""Stage 2 Module: JavaScript Static Analysis and Dynamic Replay Feed.

Extracts endpoints, API keys/secrets, and exposed source maps from recorded
JavaScript scripts. Feeds discovered GET endpoints back into the access-control
replay pipeline.
"""

from collections import Counter
import math
import re
from typing import Callable, Optional
from urllib.parse import urlparse, urljoin

import httpx

from aegis_scanner.cvss import base_score, severity_from_score
from aegis_scanner.diff.compare import similarity
from aegis_scanner.diff.normalize import normalize_body, Normalized
from aegis_scanner.models import (
    FindingResult,
    RecordedRequest,
    ReplayResult,
    ScanConfig,
)
from aegis_scanner.net_guard import host_in_scope, validate_url
from aegis_scanner.replay.replayer import Replayer
from aegis_scanner.signature import make_signature


# ---------------------------------------------------------------------------
# Entropy & Masking Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask_secret(secret: str) -> str:
    """Mask secret retaining only the first 4 and last 2 characters."""
    if len(secret) <= 6:
        return "***"
    return f"{secret[:4]}...{secret[-2:]}"


# ---------------------------------------------------------------------------
# Secret Detection Patterns
# ---------------------------------------------------------------------------

AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GOOGLE_KEY_RE = re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")
PRIVATE_KEY_RE = re.compile(r"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)")
GENERIC_SECRET_RE = re.compile(
    r"""(?i)(?:api[_-]?key|secret|token|passwd|password)["'\s:=]+["']([A-Za-z0-9_\-]{16,})["']"""
)

# Endpoints matching /api/, /rest/, /v1/, /graphql, or /admin
QUOTED_ENDPOINT_RE = re.compile(r"""(?:'([^'\r\n]+)'|"([^"\r\n]+)"|`([^`\r\n]+)`)""")
ENDPOINT_KEYWORDS = ("/api/", "/rest/", "/v1/", "/graphql", "/admin")

SOURCE_MAP_RE = re.compile(r"(?://|/\*)[#@]\s*sourceMappingURL=([^\s\*]+)")


# ---------------------------------------------------------------------------
# Extraction Functions
# ---------------------------------------------------------------------------

def extract_secrets(content: str, script_url: str = "") -> list[dict]:
    """Extract secrets matching defined regex patterns and entropy rules.
    
    Returns list of dicts with keys: secret_type, masked_secret, script_url.
    Never stores or returns unmasked secrets.
    """
    found: list[dict] = []
    seen_masks: set[str] = set()

    # 1. AWS Access Key ID
    for m in AWS_KEY_RE.finditer(content):
        val = m.group(1)
        mask = mask_secret(val)
        if mask not in seen_masks:
            seen_masks.add(mask)
            found.append({
                "secret_type": "AWS Access Key ID",
                "masked_secret": mask,
                "script_url": script_url,
            })

    # 2. Google API Key
    for m in GOOGLE_KEY_RE.finditer(content):
        val = m.group(1)
        mask = mask_secret(val)
        if mask not in seen_masks:
            seen_masks.add(mask)
            found.append({
                "secret_type": "Google API Key",
                "masked_secret": mask,
                "script_url": script_url,
            })

    # 3. Private Key Header
    for m in PRIVATE_KEY_RE.finditer(content):
        val = m.group(1)
        mask = "-----BEGIN...KEY-----"
        if mask not in seen_masks:
            seen_masks.add(mask)
            found.append({
                "secret_type": "Private Key",
                "masked_secret": mask,
                "script_url": script_url,
            })

    # 4. Generic Tokens / Passwords (requires entropy >= 3.5)
    for m in GENERIC_SECRET_RE.finditer(content):
        val = m.group(1)
        # Avoid false positives like example placeholders
        if val.upper().startswith("EXAMPLE") or "YOUR_KEY" in val.upper():
            continue
        ent = shannon_entropy(val)
        if ent >= 3.5:
            mask = mask_secret(val)
            if mask not in seen_masks:
                seen_masks.add(mask)
                found.append({
                    "secret_type": "Generic Secret/Token",
                    "masked_secret": mask,
                    "script_url": script_url,
                })

    return found


def extract_endpoints(content: str, base_url: str) -> list[str]:
    """Extract quoted string endpoints starting with / or http(s):// matching target keywords.
    
    Returns deduplicated same-origin URLs.
    """
    base_parsed = urlparse(base_url)
    base_origin = (base_parsed.scheme.lower(), base_parsed.netloc.lower())

    endpoints: list[str] = []
    seen: set[str] = set()

    for m in QUOTED_ENDPOINT_RE.finditer(content):
        cand = m.group(1) or m.group(2) or m.group(3)
        if not cand:
            continue
        cand = cand.strip()

        # Must start with / or http:// or https://
        if not (cand.startswith("/") or cand.startswith("http://") or cand.startswith("https://")):
            continue

        # Must contain one of the API/admin keywords
        if not any(kw in cand for kw in ENDPOINT_KEYWORDS):
            continue

        # Resolve to full URL and check same-origin
        if cand.startswith("/"):
            full_url = urljoin(base_url, cand)
        else:
            cand_parsed = urlparse(cand)
            cand_origin = (cand_parsed.scheme.lower(), cand_parsed.netloc.lower())
            if cand_origin != base_origin:
                continue
            full_url = cand

        # Ignore invalid characters or huge strings
        if len(full_url) > 500 or any(c in full_url for c in ("\n", "\r", "\t", " ", "<", ">")):
            continue

        if full_url not in seen:
            seen.add(full_url)
            endpoints.append(full_url)

    return endpoints


def check_source_map(
    content: str,
    script_url: str,
    config: ScanConfig,
) -> Optional[dict]:
    """Check for sourceMappingURL comment and test if the map file is exposed."""
    match = SOURCE_MAP_RE.search(content)
    if not match:
        return None

    map_ref = match.group(1).strip()
    map_url = urljoin(script_url, map_ref)

    try:
        parsed = urlparse(map_url)
        host = parsed.hostname or ""
        if not host_in_scope(host, config.scope_hosts):
            return None

        validate_url(map_url, allow_private=config.allow_private)

        with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=False) as client:
            resp = client.get(map_url)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict) and "sources" in data and isinstance(data["sources"], list):
                        return {
                            "script_url": script_url,
                            "map_url": map_url,
                            "source_count": len(data["sources"]),
                        }
                except Exception:
                    pass
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Module Runner
# ---------------------------------------------------------------------------

def run_js_analysis(
    recorded_scripts: list[RecordedRequest],
    config: ScanConfig,
    replayer: Replayer,
    report: Callable[[str, int, str, str], None],
    app_shell_fingerprint: Optional[Normalized] = None,
) -> tuple[list[FindingResult], list[RecordedRequest]]:
    """Execute JavaScript analysis on recorded scripts.
    
    Returns:
        (findings, synthetic_recorded_requests)
    """
    findings: list[FindingResult] = []
    discovered_endpoints: list[str] = []
    seen_endpoints: set[str] = set()

    for idx, script in enumerate(recorded_scripts):
        body = script.response_body or ""
        if not body:
            continue

        url = script.url

        # 1. Secrets analysis
        secrets = extract_secrets(body, script_url=url)
        for sec in secrets:
            findings.append(
                FindingResult(
                    type="HARDCODED_SECRET",
                    title="Hard-coded secret in JavaScript",
                    severity="Medium",
                    confidence=90,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe="CWE-798",
                    owasp="A01:2021 - Broken Access Control",
                    method="GET",
                    url=url,
                    signature=make_signature("GET", url),
                    source_role="scanner",
                    tested_role="anonymous",
                    description=(
                        f"Discovered hard-coded {sec['secret_type']} in client script at '{url}'. "
                        f"Masked credential: {sec['masked_secret']}. "
                        "Hard-coded secrets in frontend JavaScript are visible to all users."
                    ),
                    remediation="Remove hard-coded secrets from client-side code and rotate any exposed keys immediately.",
                    evidence={
                        "script_url": url,
                        "secret_type": sec["secret_type"],
                        "masked_secret": sec["masked_secret"],
                    },
                )
            )

        # 2. Source map check
        smap = check_source_map(body, script_url=url, config=config)
        if smap:
            findings.append(
                FindingResult(
                    type="EXPOSED_SOURCE_MAP",
                    title="Source map exposed",
                    severity="Low",
                    confidence=85,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe="CWE-540",
                    owasp="A05:2021 - Security Misconfiguration",
                    method="GET",
                    url=smap["map_url"],
                    signature=make_signature("GET", smap["map_url"]),
                    source_role="scanner",
                    tested_role="anonymous",
                    description=(
                        f"Exposed JavaScript source map at '{smap['map_url']}' referencing "
                        f"{smap['source_count']} source files. Source maps expose unminified client source code."
                    ),
                    remediation="Disable source map generation in production builds or restrict access via web server configuration.",
                    evidence=smap,
                )
            )

        # 3. Endpoint extraction
        eps = extract_endpoints(body, config.base_url)
        for ep in eps:
            if ep not in seen_endpoints:
                seen_endpoints.add(ep)
                discovered_endpoints.append(ep)

    # 4. Feed discovered endpoints back into access-control pipeline
    # Filter to endpoints without {} placeholders, max 30
    actionable_eps = [ep for ep in discovered_endpoints if "{" not in ep and "}" not in ep][:30]

    synthetic_recorded: list[RecordedRequest] = []
    if actionable_eps:
        report("planning", 48, f"Probing {len(actionable_eps)} endpoints discovered via JS analysis...", "info")
        for ep in actionable_eps:
            sig = make_signature("GET", ep)
            dummy_req = RecordedRequest(
                account_label="",
                method="GET",
                url=ep,
                headers={"Accept": "application/json, text/plain, */*"},
                body=None,
                resource_type="fetch",
                status=200,
                response_headers={},
                response_body=None,
                content_type=None,
                signature=sig,
            )

            for acc in config.accounts:
                res = replayer.send(dummy_req, as_label=acc.label)
                if 200 <= res.status < 300 and res.body and len(res.body) >= 20:
                    # Check if response matches app shell
                    if app_shell_fingerprint is not None:
                        norm_body = normalize_body(res.body, res.headers.get("content-type"))
                        if similarity(norm_body, app_shell_fingerprint) >= 0.95:
                            continue

                    synth = RecordedRequest(
                        account_label=acc.label,
                        method="GET",
                        url=ep,
                        headers={"Accept": "application/json, text/plain, */*"},
                        body=None,
                        resource_type="fetch",
                        status=res.status,
                        response_headers=dict(res.headers),
                        response_body=res.body,
                        content_type=res.headers.get("content-type"),
                        signature=sig,
                    )
                    synthetic_recorded.append(synth)

    return findings, synthetic_recorded
