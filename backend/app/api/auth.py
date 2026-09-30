"""Authentication and registration API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.audit import record_audit
from app.core.rate_limit import login_rate_limit
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    validate_password_policy,
    PasswordPolicyError,
)
from app.db import get_db
from app.deps import get_current_user
from app.models.user import User
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(req: UserRegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Register a new platform user."""
    settings = get_settings()
    if not settings.ALLOW_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User registration is currently disabled.",
        )

    # Enforce password complexity policy
    try:
        validate_password_policy(req.password)
    except PasswordPolicyError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    clean_email = req.email.strip().lower()

    # Check for existing email (generic 409 to prevent email enumeration)
    existing = db.query(User).filter(User.email == clean_email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    pwd_hash = hash_password(req.password)
    new_user = User(
        email=clean_email,
        password_hash=pwd_hash,
        role="user",
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = request.client.host if request.client else None
    record_audit(
        db,
        user_id=new_user.id,
        action="user.register",
        resource_type="user",
        resource_id=new_user.id,
        ip=client_ip,
        details={"email": clean_email},
    )

    return new_user


@router.post("/login", response_model=TokenResponse)
def login(
    req: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rate_limit=Depends(login_rate_limit),
):
    """Authenticate with email and password to obtain a signed JWT access token."""
    clean_email = req.email.strip().lower()
    client_ip = request.client.host if request.client else None

    user = db.query(User).filter(User.email == clean_email).first()

    # Uniform 401 error message for non-existent users and incorrect passwords
    if not user or not verify_password(req.password, user.password_hash) or not user.is_active:
        record_audit(
            db,
            user_id=user.id if user else None,
            action="user.login.failure",
            resource_type="user",
            resource_id=user.id if user else None,
            ip=client_ip,
            details={"email": clean_email},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    record_audit(
        db,
        user_id=user.id,
        action="user.login.success",
        resource_type="user",
        resource_id=user.id,
        ip=client_ip,
        details={"email": clean_email},
    )

    token = create_access_token(user_id=user.id, role=user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
def get_current_profile(current_user: User = Depends(get_current_user)):
    """Retrieve details for the currently authenticated user."""
    return current_user
