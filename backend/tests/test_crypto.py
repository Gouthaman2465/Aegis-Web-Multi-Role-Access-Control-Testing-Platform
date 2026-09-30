"""Unit tests for Fernet credential encryption at rest."""

from cryptography.fernet import Fernet
import pytest
from app.core.crypto import encrypt_secret, decrypt_secret, SecretDecryptionError


def test_crypto_roundtrip():
    plain = "SuperSecretDbPassword2026!"
    ciphertext = encrypt_secret(plain)

    # Ciphertext must differ from plaintext
    assert ciphertext != plain
    assert "SuperSecretDbPassword2026!" not in ciphertext

    decrypted = decrypt_secret(ciphertext)
    assert decrypted == plain


def test_crypto_wrong_key_raises_decryption_error():
    plain = "TargetAccountPass123"
    ciphertext = encrypt_secret(plain)

    different_key = Fernet.generate_key().decode()

    with pytest.raises(SecretDecryptionError):
        decrypt_secret(ciphertext, key=different_key)


def test_crypto_tampered_ciphertext_raises_decryption_error():
    plain = "SecretData"
    ciphertext = encrypt_secret(plain)

    # Tamper with cipher characters
    tampered = ciphertext[:-4] + "zzzz"

    with pytest.raises(SecretDecryptionError):
        decrypt_secret(tampered)
