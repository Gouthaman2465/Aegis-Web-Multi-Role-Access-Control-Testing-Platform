"""Scan management service handling job creation and lifecycle requests."""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.models.scan import Scan
from app.models.target import Target, TargetAccount
from app.models.user import User
from app.schemas.scan import ScanCreate


def create_scan_job(req: ScanCreate, user: User, client_ip: str | None, db: Session) -> Scan:
    """Validate target ownership and accounts before enqueueing a new scan."""
    # Strict owner isolation on target lookup
    target = db.query(Target).filter(Target.id == req.target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )

    # Ownership check: must be verified or lab
    if target.ownership_status not in ("verified", "lab"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target ownership must be verified or marked as lab before scanning.",
        )

    # Account requirement: at least 2 accounts required for multi-role comparison
    account_count = db.query(TargetAccount).filter(TargetAccount.target_id == target.id).count()
    if account_count < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least 2 target accounts are required to execute an access-control comparison scan.",
        )

    scan = Scan(
        owner_id=user.id,
        target_id=target.id,
        status="queued",
        options=req.options.model_dump(),
        progress_percent=0,
        progress_stage="queued",
        summary={
            "requests_recorded": 0,
            "replays_sent": 0,
            "findings_by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "discarded_low_confidence": 0,
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    record_audit(
        db,
        user_id=user.id,
        action="scan.create",
        resource_type="scan",
        resource_id=scan.id,
        ip=client_ip,
        details={"target_id": target.id, "target_name": target.name},
    )

    return scan


def cancel_scan_job(scan_id: int, user: User, client_ip: str | None, db: Session) -> Scan:
    """Request scan cancellation. Queued jobs cancel immediately; running jobs flag cancellation."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_id == user.id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    if scan.status not in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel a scan with status '{scan.status}'.",
        )

    if scan.status == "queued":
        scan.status = "cancelled"
        scan.progress_stage = "cancelled"
    else:
        scan.cancel_requested = True

    db.commit()
    db.refresh(scan)

    record_audit(
        db,
        user_id=user.id,
        action="scan.cancel",
        resource_type="scan",
        resource_id=scan.id,
        ip=client_ip,
    )

    return scan
