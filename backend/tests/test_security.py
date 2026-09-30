"""Unit tests for password hashing, policy, and JWT validation."""

from datetime import datetime, timezone, timedelta
import jwt
import pytest
from app.config import get_settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    validate_password_policy,
    InvalidTokenError,
    PasswordPolicyError,
)


def test_password_hash_and_verify():
    plain = "SuperSecurePass123"
    hashed = hash_password(plain)

    assert hashed != plain
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword123", hashed) is False
    assert verify_password(plain, "corrupted_hash") is False


def test_password_policy():
    # Valid passwords
    validate_password_policy("StrongPassword123")
    validate_password_policy("a1b2c3d4e5f6")

    # Too short (<10 chars)
    with pytest.raises(PasswordPolicyError, match="at least 10 characters"):
        validate_password_policy("Short1a")

    # Missing letter
    with pytest.raises(PasswordPolicyError, match="at least one letter"):
        validate_password_policy("123456789012")

    # Missing digit
    with pytest.raises(PasswordPolicyError, match="at least one digit"):
        validate_password_policy("LettersOnlyPassword")


def test_jwt_roundtrip():
    token = create_access_token(user_id=42, role="admin")
    payload = decode_access_token(token)

    assert payload["sub"] == "42"
    assert payload["role"] == "admin"
    assert "exp" in payload
    assert "iat" in payload


def test_jwt_expired_rejected():
    settings = get_settings()
    now = datetime.now(timezone.utc)
    # Expired 5 minutes ago
    expired_payload = {
        "sub": "42",
        "role": "user",
        "iat": int((now - timedelta(minutes=10)).timestamp()),
        "exp": int((now - timedelta(minutes=5)).timestamp()),
    }
    expired_token = jwt.encode(expired_payload, settings.JWT_SECRET, algorithm="HS256")

    with pytest.raises(InvalidTokenError, match="Token decoding failed"):
        decode_access_token(expired_token)


def test_jwt_alg_none_and_wrong_algorithm_rejected():
    # 1. alg: none attack vector
    payload = {"sub": "42", "role": "admin", "exp": 9999999999}
    none_token = jwt.encode(payload, key="", algorithm="none")

    with pytest.raises(InvalidTokenError):
        decode_access_token(none_token)

    # 2. Asymmetric RSA algorithm token signed with arbitrary key
    # HS256 pin should immediately reject other algorithms
    wrong_alg_token = jwt.encode(payload, "secret", algorithm="HS512")
    with pytest.raises(InvalidTokenError):
        decode_access_token(wrong_alg_token)


def test_jwt_tampered_signature_rejected():
    token = create_access_token(user_id=42, role="user")
    # Mutate the signature portion (last part of dot-separated JWT)
    parts = token.split(".")
    tampered_sig = parts[2][:-4] + "AAAA"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    with pytest.raises(InvalidTokenError):
        decode_access_token(tampered_token)
