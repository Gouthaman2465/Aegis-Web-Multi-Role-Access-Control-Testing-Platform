"""Audit trail recording with automatic secret sanitization."""

import re
from typing import Any
from sqlalchemy.orm import Session
from app.models.audit import AuditLog

AUDIT_SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key)", re.IGNORECASE)


def _sanitize_details(data: Any) -> Any:
    """Recursively strip sensitive keys from audit log detail dictionaries."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if AUDIT_SECRET_KEY_RE.search(str(k)):
                continue
            sanitized[k] = _sanitize_details(v)
        return sanitized
    elif isinstance(data, list):
        return [_sanitize_details(item) for item in data]
    return data


def record_audit(
    db: Session,
    *,
    user_id: int | None,
    action: str,
    resource_type: str | None = None,
    resource_id: int | None = None,
    ip: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    """Record an action in the immutable audit log table, ensuring no secrets are stored."""
    clean_details = _sanitize_details(details) if details else {}

    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=ip,
        details=clean_details,
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry
