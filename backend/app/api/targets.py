"""Targets and test-accounts management API."""

from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from aegis_scanner.net_guard import validate_url, BlockedTargetError
from app.config import get_settings
from app.core.audit import record_audit
from app.core.crypto import encrypt_secret
from app.core.ownership import new_ownership_token, verify_ownership
from app.db import get_db
from app.deps import get_current_user, require_admin
from app.models.scan import Scan
from app.models.target import Target, TargetAccount
from app.models.user import User
from app.schemas.target import (
    TargetCreate,
    TargetResponse,
    TargetVerifyResponse,
    AccountCreate,
    AccountResponse,
)

router = APIRouter(prefix="/targets", tags=["Targets"])


def _get_target_for_user(target_id: int, user: User, db: Session) -> Target:
    """Fetch target ensuring strict owner isolation. Returns 404 if not found or unauthorized."""
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )
    return target


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    req: TargetCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Register a new target application in unverified state."""
    # Syntax-only validation: allow_private=True during creation
    try:
        validate_url(req.base_url, allow_private=True, syntax_only=True)
    except BlockedTargetError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target URL: {e}",
        )

    parsed = urlparse(req.base_url)
    default_host = parsed.hostname or ""
    scope_hosts = req.scope_hosts if req.scope_hosts else [default_host]

    token = new_ownership_token()
    target = Target(
        owner_id=current_user.id,
        name=req.name.strip(),
        base_url=req.base_url.strip(),
        scope_hosts=scope_hosts,
        ownership_status="unverified",
        ownership_token=token,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    record_audit(
        db,
        user_id=current_user.id,
        action="target.create",
        resource_type="target",
        resource_id=target.id,
        ip=request.client.host if request.client else None,
        details={"name": target.name, "base_url": target.base_url},
    )

    return target


@router.get("", response_model=list[TargetResponse])
def list_targets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List targets belonging to the current user."""
    return db.query(Target).filter(Target.owner_id == current_user.id).order_by(Target.id.desc()).all()


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve target details for current user."""
    return _get_target_for_user(target_id, current_user, db)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete target and its accounts. Returns 409 if target has associated scans."""
    target = _get_target_for_user(target_id, current_user, db)

    # Check for scan history (must not orphan scan logs)
    has_scans = db.query(Scan).filter(Scan.target_id == target.id).first()
    if has_scans:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete target with existing scan history.",
        )

    db.delete(target)
    db.commit()

    record_audit(
        db,
        user_id=current_user.id,
        action="target.delete",
        resource_type="target",
        resource_id=target_id,
        ip=request.client.host if request.client else None,
        details={"name": target.name},
    )
    return None


@router.post("/{target_id}/verify", response_model=TargetVerifyResponse)
def verify_target(
    target_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Attempt ownership verification by checking the domain verification file."""
    target = _get_target_for_user(target_id, current_user, db)
    client_ip = request.client.host if request.client else None

    is_verified = verify_ownership(target)
    if is_verified:
        target.ownership_status = "verified"
        target.verified_at = datetime.now(timezone.utc)
        db.commit()
        record_audit(
            db,
            user_id=current_user.id,
            action="target.verify.success",
            resource_type="target",
            resource_id=target.id,
            ip=client_ip,
        )
    else:
        record_audit(
            db,
            user_id=current_user.id,
            action="target.verify.failure",
            resource_type="target",
            resource_id=target.id,
            ip=client_ip,
        )

    instructions = (
        f"Place your ownership token in {target.base_url.rstrip('/')}/.well-known/aegis-verification.txt "
        f"with content: {target.ownership_token}"
    )
    return TargetVerifyResponse(verified=is_verified, instructions=instructions)


@router.post("/{target_id}/mark-lab", response_model=TargetResponse)
def mark_target_as_lab(
    target_id: int,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Admin-only: Mark target as a lab instance, allowing private network scanning."""
    settings = get_settings()
    if not settings.ENABLE_LAB_MODE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Lab mode is disabled in this environment.",
        )

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )

    target.ownership_status = "lab"
    target.verified_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(target)

    record_audit(
        db,
        user_id=admin_user.id,
        action="target.mark_lab",
        resource_type="target",
        resource_id=target.id,
        ip=request.client.host if request.client else None,
        details={"name": target.name},
    )

    return target


@router.post("/{target_id}/accounts", response_model=AccountResponse, status_code=status.HTTP_201_CREATED)
def create_account(
    target_id: int,
    req: AccountCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add a test account to a target, encrypting its password immediately."""
    target = _get_target_for_user(target_id, current_user, db)

    # Check for duplicate role label on this target
    existing = (
        db.query(TargetAccount)
        .filter(TargetAccount.target_id == target.id, TargetAccount.role_label == req.role_label)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An account with role label '{req.role_label}' already exists on this target.",
        )

    encrypted_password = encrypt_secret(req.password)
    account = TargetAccount(
        target_id=target.id,
        role_label=req.role_label,
        privilege_level=req.privilege_level,
        login_url=req.login_url,
        username=req.username,
        password_encrypted=encrypted_password,
        username_selector=req.username_selector,
        password_selector=req.password_selector,
        submit_selector=req.submit_selector,
        dismiss_selectors=req.dismiss_selectors,
        success_url_contains=req.success_url_contains,
        identifiers=req.identifiers,
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    record_audit(
        db,
        user_id=current_user.id,
        action="account.create",
        resource_type="account",
        resource_id=account.id,
        ip=request.client.host if request.client else None,
        details={"role_label": account.role_label, "target_id": target.id},
    )

    return account


@router.get("/{target_id}/accounts", response_model=list[AccountResponse])
def list_accounts(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List test accounts for a target without credentials."""
    target = _get_target_for_user(target_id, current_user, db)
    return db.query(TargetAccount).filter(TargetAccount.target_id == target.id).all()


@router.delete("/{target_id}/accounts/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    target_id: int,
    account_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a test account."""
    target = _get_target_for_user(target_id, current_user, db)
    account = (
        db.query(TargetAccount)
        .filter(TargetAccount.id == account_id, TargetAccount.target_id == target.id)
        .first()
    )
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found.",
        )

    db.delete(account)
    db.commit()

    record_audit(
        db,
        user_id=current_user.id,
        action="account.delete",
        resource_type="account",
        resource_id=account_id,
        ip=request.client.host if request.client else None,
        details={"role_label": account.role_label, "target_id": target.id},
    )
    return None
