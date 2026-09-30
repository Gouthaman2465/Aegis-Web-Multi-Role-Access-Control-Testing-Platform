"""Administrative operations and system audit log API."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import require_admin
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.finding import AuditLogResponse

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/audit-log", response_model=list[AuditLogResponse])
def get_audit_log(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Retrieve platform audit logs with pagination (Administrator access only)."""
    return (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
