"""Database-backed asynchronous scan execution worker."""

import logging
import re
import signal
import time
from datetime import datetime, timedelta, timezone
from typing import Callable
from sqlalchemy.orm import Session

from aegis_scanner.models import (
    AccountConfig,
    ScanConfig,
    ScanResult,
    FindingResult,
    RecordedRequest,
)
from aegis_scanner.modules.access_control import run_access_control_scan
from aegis_scanner.redact import redact_headers, redact_body
from app.config import get_settings
from app.core.audit import record_audit
from app.core.crypto import decrypt_secret
from app.core.fingerprint import compute_fingerprint
from app.db import SessionLocal
from app.models.finding import Finding
from app.models.scan import Scan, ScanEvent, Endpoint
from app.models.target import Target, TargetAccount

logger = logging.getLogger("aegis_worker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

_running = True


def claim_next_job(db: Session) -> Scan | None:
    """Select the oldest queued scan with lock, mark it running, and return it."""
    try:
        scan = (
            db.query(Scan)
            .filter(Scan.status == "queued")
            .order_by(Scan.created_at.asc(), Scan.id.asc())
            .with_for_update(skip_locked=True)
            .first()
        )
    except Exception:
        # SQLite or dialects lacking FOR UPDATE SKIP LOCKED
        scan = (
            db.query(Scan)
            .filter(Scan.status == "queued")
            .order_by(Scan.created_at.asc(), Scan.id.asc())
            .first()
        )

    if not scan:
        return None

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.progress_stage = "initializing"
    scan.progress_percent = 0
    db.commit()
    db.refresh(scan)
    return scan


def recover_stale_jobs(db: Session) -> int:
    """On worker startup, mark scans stuck in running state for longer than timeout as failed."""
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.SCAN_TIMEOUT_SECONDS)
    stale_scans = (
        db.query(Scan)
        .filter(
            Scan.status == "running",
            (Scan.started_at == None) | (Scan.started_at < cutoff),
        )
        .all()
    )
    count = 0
    for s in stale_scans:
        s.status = "failed"
        s.error_message = "Worker restarted"
        s.finished_at = datetime.now(timezone.utc)
        count += 1

    if count > 0:
        db.commit()
    return count


def _defensively_redact_evidence(evidence: dict) -> dict:
    """Defensively redact any sensitive headers and request/response previews in evidence."""
    if not isinstance(evidence, dict):
        return {}
    ev_copy = dict(evidence)
    for section_key in ("original", "replay"):
        if section_key in ev_copy and isinstance(ev_copy[section_key], dict):
            sec = dict(ev_copy[section_key])
            if "headers" in sec and isinstance(sec["headers"], dict):
                sec["headers"] = redact_headers(sec["headers"])
            if "body_preview" in sec and isinstance(sec["body_preview"], str):
                sec["body_preview"] = redact_body(sec["body_preview"])
            ev_copy[section_key] = sec
    return ev_copy


def process_one_job(session_factory: Callable[[], Session]) -> bool:
    """Claim and execute one pending scan job. Returns True if a job was processed."""
    settings = get_settings()
    with session_factory() as db:
        scan = claim_next_job(db)
        if not scan:
            return False

        scan_id = scan.id
        owner_id = scan.owner_id
        target_id = scan.target_id
        scan_options = dict(scan.options) if scan.options else {}

        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            scan.status = "failed"
            scan.error_message = "Target not found"
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            return True

        accounts = db.query(TargetAccount).filter(TargetAccount.target_id == target_id).all()
        if len(accounts) < 2:
            scan.status = "failed"
            scan.error_message = "At least 2 accounts required for access control evaluation"
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            return True

        # Decrypt passwords in memory only
        account_configs: list[AccountConfig] = []
        passwords_in_memory: list[str] = []
        for acc in accounts:
            plain_pwd = decrypt_secret(acc.password_encrypted)
            passwords_in_memory.append(plain_pwd)
            account_configs.append(
                AccountConfig(
                    label=acc.role_label,
                    privilege_level=acc.privilege_level,
                    login_url=acc.login_url,
                    username=acc.username,
                    password=plain_pwd,
                    username_selector=acc.username_selector,
                    password_selector=acc.password_selector,
                    submit_selector=acc.submit_selector,
                    dismiss_selectors=list(acc.dismiss_selectors or []),
                    success_url_contains=acc.success_url_contains,
                    identifiers=list(acc.identifiers or []),
                )
            )

        allow_private = target.ownership_status == "lab"
        scan_config = ScanConfig(
            base_url=target.base_url,
            scope_hosts=list(target.scope_hosts or []),
            accounts=account_configs,
            max_pages=scan_options.get("max_pages", 30),
            max_depth=scan_options.get("max_depth", 3),
            request_delay_ms=scan_options.get("request_delay_ms", 200),
            max_replays=scan_options.get("max_replays", 500),
            seed_paths=scan_options.get("seed_paths", []),
            allow_private=allow_private,
            modules=scan_options.get("modules", ["access_control"]),
        )

    # Execution state trackers
    start_time = time.monotonic()
    deadline = start_time + settings.SCAN_TIMEOUT_SECONDS
    is_timed_out = False
    is_cancelled = False

    def sanitize_log_message(msg: str) -> str:
        clean = msg
        for p in passwords_in_memory:
            if p:
                clean = clean.replace(p, "[REDACTED]")
        clean = re.sub(r"(?i)(password|passwd|secret|token)=\S+", r"\1=[REDACTED]", clean)
        return clean

    def report(stage: str, percent: int, message: str, level: str = "info") -> None:
        clean_msg = sanitize_log_message(message)
        with session_factory() as rep_db:
            event = ScanEvent(
                scan_id=scan_id,
                level=level,
                stage=stage,
                message=clean_msg,
                percent=percent,
            )
            rep_db.add(event)
            s = rep_db.query(Scan).filter(Scan.id == scan_id).first()
            if s:
                s.progress_percent = percent
                s.progress_stage = stage
            rep_db.commit()

    def should_cancel() -> bool:
        nonlocal is_timed_out, is_cancelled
        if time.monotonic() >= deadline:
            is_timed_out = True
            return True
        with session_factory() as chk_db:
            s = chk_db.query(Scan).filter(Scan.id == scan_id).first()
            if s and s.cancel_requested:
                is_cancelled = True
                return True
        return False

    report("starting", 0, "Scan initialized, launching crawler engine...", "info")

    try:
        # Check deadline before launching scanner
        if should_cancel():
            raise TimeoutError("Scan timed out before execution") if is_timed_out else RuntimeError("Cancelled")

        result: ScanResult = run_access_control_scan(scan_config, report, should_cancel)

        # Check deadline/cancellation right after scanner execution
        if time.monotonic() >= deadline:
            is_timed_out = True

        with session_factory() as chk_db:
            s = chk_db.query(Scan).filter(Scan.id == scan_id).first()
            if s and s.cancel_requested:
                is_cancelled = True

        with session_factory() as final_db:
            s = final_db.query(Scan).filter(Scan.id == scan_id).first()
            if not s:
                return True

            if is_timed_out:
                s.status = "failed"
                s.error_message = "Scan timed out"
                s.progress_stage = "failed"
                s.finished_at = datetime.now(timezone.utc)
                final_db.commit()
                record_audit(
                    final_db,
                    user_id=owner_id,
                    action="scan.finish",
                    resource_type="scan",
                    resource_id=scan_id,
                    ip=None,
                    details={"status": "failed", "error": "Scan timed out"},
                )
                return True

            if is_cancelled:
                s.status = "cancelled"
                s.progress_stage = "cancelled"
                s.finished_at = datetime.now(timezone.utc)
                final_db.commit()
                record_audit(
                    final_db,
                    user_id=owner_id,
                    action="scan.finish",
                    resource_type="scan",
                    resource_id=scan_id,
                    ip=None,
                    details={"status": "cancelled"},
                )
                return True

            # Persist recorded endpoints
            for ep in result.endpoints:
                endpoint_row = Endpoint(
                    scan_id=scan_id,
                    account_label=ep.account_label,
                    method=ep.method,
                    url=ep.url,
                    signature=ep.signature,
                    resource_type=ep.resource_type,
                    status_code=ep.status,
                    content_type=ep.content_type,
                )
                final_db.add(endpoint_row)

            # Persist findings with computed fingerprint and defensive redaction
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for f in result.findings:
                fp = compute_fingerprint(f.type, f.method, f.signature, f.source_role, f.tested_role)
                if f.severity in sev_counts:
                    sev_counts[f.severity] += 1
                finding_row = Finding(
                    scan_id=scan_id,
                    fingerprint=fp,
                    type=f.type,
                    title=f.title,
                    severity=f.severity,
                    confidence=f.confidence,
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    cwe=f.cwe,
                    owasp=f.owasp,
                    method=f.method,
                    url=f.url,
                    signature=f.signature,
                    source_role=f.source_role,
                    tested_role=f.tested_role,
                    description=f.description,
                    remediation=f.remediation,
                    status="open",
                    note=None,
                    evidence=_defensively_redact_evidence(f.evidence),
                )
                final_db.add(finding_row)

            s.status = "completed"
            s.progress_percent = 100
            s.progress_stage = "completed"
            s.finished_at = datetime.now(timezone.utc)
            s.summary = {
                "requests_recorded": len(result.endpoints),
                "replays_sent": result.stats.get("replays_sent", 0),
                "findings_by_severity": sev_counts,
                "discarded_low_confidence": result.stats.get("discarded_low_confidence", 0),
            }
            final_db.commit()

            record_audit(
                final_db,
                user_id=owner_id,
                action="scan.finish",
                resource_type="scan",
                resource_id=scan_id,
                ip=None,
                details={"status": "completed", "findings_count": len(result.findings)},
            )
            report("completed", 100, f"Scan completed successfully with {len(result.findings)} findings.", "info")

        return True

    except Exception as exc:
        logger.exception(f"Unhandled error during scan execution for scan ID {scan_id}: {exc}")
        with session_factory() as fail_db:
            s = fail_db.query(Scan).filter(Scan.id == scan_id).first()
            if s:
                if is_timed_out or isinstance(exc, TimeoutError):
                    s.status = "failed"
                    s.error_message = "Scan timed out"
                elif is_cancelled:
                    s.status = "cancelled"
                else:
                    s.status = "failed"
                    err_msg = str(exc)
                    for p in passwords_in_memory:
                        if p:
                            err_msg = err_msg.replace(p, "[REDACTED]")
                    s.error_message = err_msg[:255] if err_msg else "Scan execution failed"

                s.progress_stage = s.status
                s.finished_at = datetime.now(timezone.utc)
                fail_db.commit()

                record_audit(
                    fail_db,
                    user_id=owner_id,
                    action="scan.finish",
                    resource_type="scan",
                    resource_id=scan_id,
                    ip=None,
                    details={"status": s.status, "error": s.error_message},
                )
        return True


def _handle_signal(signum, frame):
    global _running
    logger.info("Termination signal received. Stopping worker loop...")
    _running = False


def main():
    """Main worker daemon loop."""
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    settings = get_settings()
    logger.info("Aegis-Web Scan Worker starting up...")

    with SessionLocal() as db:
        recovered = recover_stale_jobs(db)
        if recovered > 0:
            logger.info(f"Recovered {recovered} stale running scan jobs.")

    while _running:
        try:
            processed = process_one_job(SessionLocal)
            if not processed and _running:
                time.sleep(settings.WORKER_POLL_SECONDS)
        except Exception as e:
            logger.exception(f"Unhandled exception in worker loop: {e}")
            time.sleep(1)

    logger.info("Worker stopped cleanly.")


if __name__ == "__main__":
    main()
