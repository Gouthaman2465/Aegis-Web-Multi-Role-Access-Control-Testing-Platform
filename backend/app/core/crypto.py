"""Symmetric credential encryption and decryption at rest using Fernet."""

from cryptography.fernet import Fernet, InvalidToken
from app.config import get_settings


class SecretDecryptionError(Exception):
    """Raised when decrypting an encrypted credential fails."""
    pass


def _get_fernet(key: str | None = None) -> Fernet:
    if key is None:
        key = get_settings().CREDENTIAL_ENCRYPTION_KEY
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_secret(plain: str) -> str:
    """Encrypt a plaintext credential string for at-rest database storage."""
    fernet = _get_fernet()
    return fernet.encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str, key: str | None = None) -> str:
    """Decrypt a stored credential string without leaking cipher details on error."""
    try:
        fernet = _get_fernet(key)
        return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception) as e:
        raise SecretDecryptionError("Failed to decrypt secret: invalid or tampered key/ciphertext.") from e
