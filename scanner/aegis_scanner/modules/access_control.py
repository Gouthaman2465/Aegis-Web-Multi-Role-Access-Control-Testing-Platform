"""Stage 1 Access Control scan orchestrator."""

from typing import Callable, Optional
from playwright.sync_api import sync_playwright

from aegis_scanner.cvss import base_score, severity_from_score
from aegis_scanner.diff.compare import similarity
from aegis_scanner.diff.normalize import normalize_body, Normalized
from aegis_scanner.diff.scoring import (
    Signals,
    is_finding_candidate,
    confidence_score,
    adjust_severity,
    extract_identifiers,
    contains_identifier,
    check_sensitive_fields,
)
from aegis_scanner.models import (
    AccountConfig,
    FindingResult,
    RecordedRequest,
    ReplayResult,
    ScanConfig,
    ScanResult,
)
from aegis_scanner.redact import redact_headers, redact_body
from aegis_scanner.recorder.crawler import record_account
from aegis_scanner.replay.planner import build_replay_plan, ReplayTask
from aegis_scanner.replay.replayer import Replayer
from aegis_scanner.replay.verdict import classify_response
from aegis_scanner.modules.js_analysis import run_js_analysis
from aegis_scanner.modules.misconfig import run_misconfig_checks

CVSS_VECTORS = {
    "HORIZONTAL_ACCESS": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "VERTICAL_ACCESS": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "UNAUTHENTICATED_ACCESS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

CWE_MAPPING = {
    "HORIZONTAL_ACCESS": "CWE-639",
    "VERTICAL_ACCESS": "CWE-863",
    "UNAUTHENTICATED_ACCESS": "CWE-306",
}


def run_access_control_scan(
    config: ScanConfig,
    report: Callable[[str, int, str, str], None],
    should_cancel: Callable[[], bool],
) -> ScanResult:
    """Execute the complete Stage 1 access-control scan workflow."""
    stats = {
        "requests_recorded": 0,
        "replays_sent": 0,
        "discarded_low_confidence": 0,
    }

    account_map = {acc.label: acc for acc in config.accounts}
    account_idents = {acc.label: extract_identifiers(acc) for acc in config.accounts}

    # -------------------------------------------------------------
    # 1. Recording Stage (0% - 45%)
    # -------------------------------------------------------------
    report("recording", 0, "Starting browser session recording...", "info")
    all_recorded: list[RecordedRequest] = []
    auth_states = {}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        total_accounts = len(config.accounts)

        for idx, acc in enumerate(config.accounts):
            if should_cancel():
                break

            pct_start = int((idx / max(1, total_accounts)) * 45)
            report(
                "recording",
                pct_start,
                f"Recording traffic for account '{acc.label}' ({idx + 1}/{total_accounts})...",
                "info",
            )

            recorded_reqs, auth_state = record_account(
                browser=browser,
                account=acc,
                config=config,
                report=report,
                should_cancel=should_cancel,
            )
            all_recorded.extend(recorded_reqs)
            auth_states[acc.label] = auth_state

        browser.close()

    stats["requests_recorded"] = len(all_recorded)

    if should_cancel():
        return ScanResult(endpoints=all_recorded, findings=[], stats=stats)

    # -------------------------------------------------------------
    # 2. Planning Stage (45% - 50%)
    # -------------------------------------------------------------
    report("planning", 46, "Fetching target base shell and constructing replay plan...", "info")
    replayer = Replayer(config=config, auth_states=auth_states)

    # Fetch app shell baseline anonymously
    shell_dummy_req = RecordedRequest(
        account_label="anonymous",
        method="GET",
        url=config.base_url,
        headers={"Accept": "text/html"},
        body=None,
        resource_type="document",
        status=200,
        response_headers={},
        response_body=None,
        content_type="text/html",
        signature="GET /",
    )
    shell_res = replayer.send(shell_dummy_req, as_label=None)
    app_shell_fingerprint = None
    if shell_res.status in (200, 301, 302) and shell_res.body:
        app_shell_fingerprint = normalize_body(shell_res.body, shell_res.headers.get("content-type"))

    extra_findings: list[FindingResult] = []

    # Stage 2: JavaScript Analysis (endpoints, secrets, source maps)
    if "js_analysis" in config.modules:
        report("planning", 47, "Analyzing recorded JavaScript files and discovering endpoints...", "info")
        recorded_scripts = [r for r in all_recorded if r.resource_type == "script" and r.response_body]
        js_findings, synthetic_reqs = run_js_analysis(
            recorded_scripts=recorded_scripts,
            config=config,
            replayer=replayer,
            report=report,
            app_shell_fingerprint=app_shell_fingerprint,
        )
        all_recorded.extend(synthetic_reqs)
        extra_findings.extend(js_findings)

    # Stage 2: Web Security Misconfiguration Checks
    if "misconfig" in config.modules:
        report("planning", 49, "Running web security misconfiguration checks...", "info")
        misconfig_findings = run_misconfig_checks(
            recorded_requests=all_recorded,
            config=config,
            replayer=replayer,
            report=report,
        )
        extra_findings.extend(misconfig_findings)

    tasks = build_replay_plan(
        recorded_by_account=all_recorded,
        accounts=config.accounts,
        config=config,
        app_shell_fingerprint=app_shell_fingerprint,
    )
    report("planning", 50, f"Constructed replay plan with {len(tasks)} tasks.", "info")

    if not tasks or should_cancel():
        return ScanResult(endpoints=all_recorded, findings=extra_findings, stats=stats)

    # -------------------------------------------------------------
    # 3. Control Replays & Stability Check (50% - 60%)
    # -------------------------------------------------------------
    report("stability", 50, "Running control replays to measure endpoint stability...", "info")
    distinct_reqs: dict[tuple[str, str], RecordedRequest] = {}
    for t in tasks:
        key = (t.request.method, t.request.url)
        if key not in distinct_reqs:
            distinct_reqs[key] = t.request

    stabilities: dict[tuple[str, str], float] = {}
    valid_distinct_keys: set[tuple[str, str]] = set()

    for idx, (key, req) in enumerate(distinct_reqs.items()):
        if should_cancel():
            break

        control_res = replayer.send(req, as_label=req.account_label)
        stats["replays_sent"] += 1

        if not (200 <= control_res.status < 300):
            # Dropped: cannot be reliably reproduced
            continue

        norm_orig = normalize_body(req.response_body, req.content_type)
        norm_ctrl = normalize_body(control_res.body, control_res.headers.get("content-type"))
        stab = similarity(norm_orig, norm_ctrl)
        stabilities[key] = stab
        valid_distinct_keys.add(key)

        pct = 50 + int(((idx + 1) / max(1, len(distinct_reqs))) * 10)
        report("stability", pct, f"Stability verified for {idx + 1}/{len(distinct_reqs)} endpoints.", "info")

    # Filter out tasks whose control check failed
    stable_tasks = [t for t in tasks if (t.request.method, t.request.url) in valid_distinct_keys]

    # -------------------------------------------------------------
    # 4. Test Replays & Candidate Scoring (60% - 95%)
    # -------------------------------------------------------------
    report("replaying", 60, f"Executing {len(stable_tasks)} test replays across roles...", "info")

    # Map to cache anonymous replay results per (method, url) to evaluate looks_public
    anon_results: dict[tuple[str, str], tuple[str, float]] = {}  # key -> (verdict, similarity)

    # To ensure anonymous checks are available for looks_public, sort tasks so anonymous runs first
    sorted_tasks = sorted(stable_tasks, key=lambda t: 0 if t.tested is None else 1)

    raw_findings: list[FindingResult] = list(extra_findings)

    for idx, task in enumerate(sorted_tasks):
        if should_cancel():
            break

        req = task.request
        source_label = task.source
        tested_label = task.tested
        req_key = (req.method, req.url)
        stability = stabilities.get(req_key, 1.0)

        replay_res = replayer.send(req, as_label=tested_label)
        stats["replays_sent"] += 1

        verdict = classify_response(replay_res, req)

        norm_orig = normalize_body(req.response_body, req.content_type)
        norm_replay = normalize_body(replay_res.body, replay_res.headers.get("content-type"))
        sim = similarity(norm_orig, norm_replay)

        if tested_label is None:
            anon_results[req_key] = (verdict, sim)

        if verdict != "allowed":
            continue

        # Extract signals
        orig_has_content = norm_orig.has_content
        source_acc = account_map[source_label]
        source_idents = account_idents.get(source_label, set())
        tested_acc = account_map.get(tested_label) if tested_label else None
        tested_idents = account_idents.get(tested_label, set()) if tested_label else set()

        personalized = contains_identifier(req.response_body or "", source_idents)
        has_source_id = contains_identifier(replay_res.body, source_idents)
        served_own = bool(
            tested_acc
            and contains_identifier(replay_res.body, tested_idents)
            and not has_source_id
        )

        id_in_path = "{id}" in req.signature
        body_len = len(replay_res.body)
        is_json = bool(
            (req.content_type and "json" in req.content_type.lower())
            or replay_res.body.strip().startswith(("{", "["))
        )
        sensitive = check_sensitive_fields(replay_res.body, is_json=is_json)

        # Evaluate looks_public
        looks_public = False
        if req_key in anon_results:
            anon_verdict, anon_sim = anon_results[req_key]
            if (
                anon_verdict == "allowed"
                and anon_sim >= min(0.85, stability - 0.05)
                and not has_source_id
                and not id_in_path
                and not sensitive
            ):
                looks_public = True

        signals = Signals(
            original_has_content=orig_has_content,
            similarity=sim,
            stability=stability,
            personalized=personalized,
            has_source_identifiers=has_source_id,
            served_own_data=served_own,
            id_in_path=id_in_path,
            body_len=body_len,
            sensitive_fields=sensitive,
            looks_public=looks_public,
        )

        if not is_finding_candidate(signals):
            continue

        conf = confidence_score(signals)
        if conf < 50:
            stats["discarded_low_confidence"] += 1
            continue

        # Determine finding type
        if tested_label is None:
            ftype = "UNAUTHENTICATED_ACCESS"
        else:
            if tested_acc.privilege_level == source_acc.privilege_level:
                ftype = "HORIZONTAL_ACCESS"
            else:
                ftype = "VERTICAL_ACCESS"

        cvss_vec = CVSS_VECTORS[ftype]
        cvss_sc = base_score(cvss_vec)
        base_sev = severity_from_score(cvss_sc)
        final_sev = adjust_severity(base_sev, conf)
        cwe_id = CWE_MAPPING[ftype]

        # Titles and descriptions
        if ftype == "HORIZONTAL_ACCESS":
            title = f"Horizontal Access Control Violation (IDOR) on {req.signature}"
            desc = (
                f"Role '{tested_label}' received the content of a request recorded by role '{source_label}' "
                f"(same privilege level) at '{req.url}'. The response matched the original with similarity {sim:.2f}. "
                "This indicates the server does not check that the requested object belongs to the requesting user. "
                "Aegis-Web verified read access only."
            )
        elif ftype == "VERTICAL_ACCESS":
            title = f"Vertical Privilege Escalation on {req.signature}"
            desc = (
                f"Role '{tested_label}' (lower privilege) received a response from '{req.url}' that role "
                f"'{source_label}' (higher privilege) recorded. This indicates a missing or incomplete "
                "function-level authorization check. Read access only was verified."
            )
        else:
            title = f"Unauthenticated Access to Protected Resource on {req.signature}"
            desc = (
                f"'{req.url}' returned content to an anonymous client that matched what role '{source_label}' "
                "received while logged in. Read access only was verified."
            )

        remediation = (
            "Enforce authorization on the server for every request: check the caller's identity, role and "
            "ownership of the requested object before returning data. Prefer deny-by-default. Do not rely on "
            "hidden links or client-side checks."
        )

        # Redact and truncate evidence
        orig_body_str = req.response_body or ""
        replay_body_str = replay_res.body or ""
        evidence = {
            "original": {
                "role": source_label,
                "status": req.status,
                "headers": redact_headers(req.response_headers),
                "body_preview": redact_body(orig_body_str[:2000], req.content_type),
            },
            "replay": {
                "role": tested_label or "anonymous",
                "status": replay_res.status,
                "headers": redact_headers(replay_res.headers),
                "body_preview": redact_body(
                    replay_body_str[:2000], replay_res.headers.get("content-type")
                ),
            },
            "similarity": round(sim, 3),
            "stability": round(stability, 3),
            "signals": [
                name
                for name, val in [
                    ("original_has_content", signals.original_has_content),
                    ("personalized", signals.personalized),
                    ("has_source_identifiers", signals.has_source_identifiers),
                    ("served_own_data", signals.served_own_data),
                    ("id_in_path", signals.id_in_path),
                    ("sensitive_fields", signals.sensitive_fields),
                    ("looks_public", signals.looks_public),
                ]
                if val
            ],
            "confidence_breakdown": {
                "base_similarity": round(50 * min(1.0, signals.similarity / max(signals.stability, 0.5))),
                "source_identifiers": 25 if signals.has_source_identifiers else 0,
                "id_in_path": 15 if signals.id_in_path else 0,
                "body_length_bonus": 10 if signals.body_len >= 100 else 0,
                "sensitive_fields_bonus": 10 if signals.sensitive_fields else 0,
                "public_penalty": -30 if signals.looks_public else 0,
                "total_confidence": conf,
            },
        }

        finding = FindingResult(
            type=ftype,
            title=title,
            severity=final_sev,
            confidence=conf,
            cvss_score=cvss_sc,
            cvss_vector=cvss_vec,
            cwe=cwe_id,
            owasp="A01:2021 - Broken Access Control",
            method=req.method,
            url=req.url,
            signature=req.signature,
            source_role=source_label,
            tested_role=tested_label or "anonymous",
            description=desc,
            remediation=remediation,
            evidence=evidence,
        )
        raw_findings.append(finding)

        pct = 60 + int(((idx + 1) / max(1, len(sorted_tasks))) * 35)
        report("replaying", pct, f"Replayed task {idx + 1}/{len(sorted_tasks)}: {req.signature}", "info")

    # -------------------------------------------------------------
    # 5. Deduplication & Finalizing Stage (95% - 100%)
    # -------------------------------------------------------------
    report("finalizing", 95, "Deduplicating findings and assembling report...", "info")
    deduped_map: dict[tuple, FindingResult] = {}

    for f in raw_findings:
        fp_key = (f.type, f.method, f.signature, f.source_role, f.tested_role)
        if fp_key not in deduped_map:
            f.evidence["other_urls"] = []
            deduped_map[fp_key] = f
        else:
            existing = deduped_map[fp_key]
            if f.confidence > existing.confidence:
                # Replace with higher confidence finding and preserve other URLs
                other_urls = existing.evidence.get("other_urls", [])
                if existing.url not in other_urls and len(other_urls) < 5:
                    other_urls.append(existing.url)
                f.evidence["other_urls"] = other_urls
                deduped_map[fp_key] = f
            else:
                other_urls = existing.evidence.get("other_urls", [])
                if f.url not in other_urls and len(other_urls) < 5:
                    other_urls.append(f.url)
                existing.evidence["other_urls"] = other_urls

    final_findings = list(deduped_map.values())
    report("finalizing", 100, f"Scan completed. Discovered {len(final_findings)} access-control flaws.", "info")

    return ScanResult(
        endpoints=all_recorded,
        findings=final_findings,
        stats=stats,
    )
