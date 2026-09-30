"""Authentication, password hashing with Argon2id, and pinned HS256 JWT operations."""

from datetime import datetime, timezone, timedelta
import re
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, HashingError, InvalidHashError
import jwt
from app.config import get_settings

ph = PasswordHasher()


class InvalidTokenError(Exception):
    """Raised when a JWT token is invalid, expired, or has incorrect claims."""
    pass


class PasswordPolicyError(ValueError):
    """Raised when a password fails complexity or length rules."""
    pass


def hash_password(plain: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against an Argon2id hash without raising exceptions."""
    try:
        return ph.verify(hashed, plain)
    except (VerificationError, HashingError, InvalidHashError, Exception):
        return False


def validate_password_policy(password: str) -> None:
    """Enforce registration password policy: min 10 characters, at least one letter and digit."""
    if len(password) < 10:
        raise PasswordPolicyError("Password must be at least 10 characters long.")
    if not re.search(r"[A-Za-z]", password):
        raise PasswordPolicyError("Password must contain at least one letter.")
    if not re.search(r"\d", password):
        raise PasswordPolicyError("Password must contain at least one digit.")


def create_access_token(user_id: int, role: str) -> str:
    """Generate a signed HS256 JWT access token."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token pinned strictly to HS256."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "sub"]},
        )
        return payload
    except Exception as e:
        raise InvalidTokenError(f"Token decoding failed: {e}") from e
