"""Findings triage and detail retrieval API."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.db import get_db
from app.deps import get_current_user
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingDetailResponse, FindingUpdate

router = APIRouter(prefix="/findings", tags=["Findings"])


def _get_user_finding(finding_id: int, user: User, db: Session) -> Finding:
    """Fetch finding ensuring its parent scan belongs to the requesting user. Returns 404 otherwise."""
    finding = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.id == finding_id, Scan.owner_id == user.id)
        .first()
    )
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )
    return finding


@router.get("/{finding_id}", response_model=FindingDetailResponse)
def get_finding(
    finding_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve full finding details including raw evidence diffs."""
    return _get_user_finding(finding_id, current_user, db)


@router.patch("/{finding_id}", response_model=FindingDetailResponse)
def update_finding(
    finding_id: int,
    req: FindingUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update triage status or note for a specific finding."""
    finding = _get_user_finding(finding_id, current_user, db)
    client_ip = request.client.host if request.client else None

    old_status = finding.status
    if req.status is not None:
        finding.status = req.status
    if req.note is not None:
        finding.note = req.note.strip()

    db.commit()
    db.refresh(finding)

    record_audit(
        db,
        user_id=current_user.id,
        action="finding.status_change",
        resource_type="finding",
        resource_id=finding.id,
        ip=client_ip,
        details={
            "old_status": old_status,
            "new_status": finding.status,
            "signature": finding.signature,
        },
    )

    return finding
