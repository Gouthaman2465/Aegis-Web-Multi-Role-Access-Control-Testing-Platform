"""Scans execution, monitoring, events, and reports API."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.db import get_db
from app.deps import get_current_user, scan_rate_limit
from app.models.finding import Finding
from app.models.scan import Scan, ScanEvent, Endpoint
from app.models.user import User
from app.schemas.finding import CompareResponse, FindingResponse
from app.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanEventResponse,
    EndpointResponse,
)
from app.services.compare_service import compare_scans
from app.services.report_service import build_markdown
from app.services.scan_service import create_scan_job, cancel_scan_job

router = APIRouter(prefix="/scans", tags=["Scans"])


def _get_user_scan(scan_id: int, user: User, db: Session) -> Scan:
    """Fetch scan enforcing strict owner isolation. Returns 404 if not found or belongs to another user."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    req: ScanCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    _rate_limit=Depends(scan_rate_limit),
    db: Session = Depends(get_db),
):
    """Enqueue a new scan job for a verified or lab target."""
    client_ip = request.client.host if request.client else None
    return create_scan_job(req, current_user, client_ip, db)


@router.get("", response_model=list[ScanResponse])
def list_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List scans belonging to the current user in descending order."""
    return db.query(Scan).filter(Scan.owner_id == current_user.id).order_by(Scan.id.desc()).all()


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve details and progress status of a specific scan."""
    return _get_user_scan(scan_id, current_user, db)


@router.get("/{scan_id}/events", response_model=list[ScanEventResponse])
def get_scan_events(
    scan_id: int,
    after: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve incremental scan event logs after a specified event ID."""
    _get_user_scan(scan_id, current_user, db)
    return (
        db.query(ScanEvent)
        .filter(ScanEvent.scan_id == scan_id, ScanEvent.id > after)
        .order_by(ScanEvent.id.asc())
        .limit(200)
        .all()
    )


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Request cancellation of an active or queued scan."""
    client_ip = request.client.host if request.client else None
    return cancel_scan_job(scan_id, current_user, client_ip, db)


@router.get("/{scan_id}/endpoints", response_model=list[EndpointResponse])
def get_scan_endpoints(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve attack surface endpoints recorded during scan crawl."""
    _get_user_scan(scan_id, current_user, db)
    return db.query(Endpoint).filter(Endpoint.scan_id == scan_id).order_by(Endpoint.id.asc()).all()


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_scan_findings(
    scan_id: int,
    severity: str | None = None,
    type: str | None = None,
    finding_status: str | None = Query(None, alias="status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List findings for a scan with optional filters (evidence excluded from summary)."""
    _get_user_scan(scan_id, current_user, db)
    query = db.query(Finding).filter(Finding.scan_id == scan_id)

    if severity:
        query = query.filter(Finding.severity == severity)
    if type:
        query = query.filter(Finding.type == type)
    if finding_status:
        query = query.filter(Finding.status == finding_status)

    return query.order_by(Finding.id.asc()).all()


@router.get("/{scan_id}/compare/{other_id}", response_model=CompareResponse)
def compare_with_scan(
    scan_id: int,
    other_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Compare two scans for the same target to identify new, fixed, and persisting flaws."""
    scan_a = _get_user_scan(scan_id, current_user, db)
    scan_b = _get_user_scan(other_id, current_user, db)

    if scan_a.target_id != scan_b.target_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot compare scans belonging to different targets.",
        )

    findings_a = db.query(Finding).filter(Finding.scan_id == scan_a.id).all()
    findings_b = db.query(Finding).filter(Finding.scan_id == scan_b.id).all()

    return compare_scans(scan_a, scan_b, findings_a, findings_b)


@router.get("/{scan_id}/report.md")
def export_markdown_report(
    scan_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export an injection-proof Markdown audit report."""
    scan = _get_user_scan(scan_id, current_user, db)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    record_audit(
        db,
        user_id=current_user.id,
        action="report.export",
        resource_type="scan",
        resource_id=scan.id,
        ip=request.client.host if request.client else None,
        details={"format": "markdown"},
    )

    report_content = build_markdown(scan, findings)
    return Response(content=report_content, media_type="text/markdown")


@router.get("/{scan_id}/report.json")
def export_json_report(
    scan_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export scan summary and detailed findings as JSON."""
    scan = _get_user_scan(scan_id, current_user, db)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    record_audit(
        db,
        user_id=current_user.id,
        action="report.export",
        resource_type="scan",
        resource_id=scan.id,
        ip=request.client.host if request.client else None,
        details={"format": "json"},
    )

    return {
        "scan": ScanResponse.model_validate(scan).model_dump(),
        "findings": [
            {
                "id": f.id,
                "fingerprint": f.fingerprint,
                "type": f.type,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "method": f.method,
                "url": f.url,
                "signature": f.signature,
                "source_role": f.source_role,
                "tested_role": f.tested_role,
                "description": f.description,
                "remediation": f.remediation,
                "status": f.status,
                "note": f.note,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }
