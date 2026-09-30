"""Application settings and startup environment validation."""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / ".env"


class Settings(BaseSettings):
    """Central configuration loaded from environment and root .env file."""
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    POSTGRES_USER: str = "aegis"
    POSTGRES_PASSWORD: str = "CHANGE_ME_DB_PASSWORD"
    POSTGRES_DB: str = "aegis"
    DATABASE_URL: str = "postgresql+psycopg://aegis:CHANGE_ME_DB_PASSWORD@localhost:5432/aegis"

    JWT_SECRET: str = Field(default="CHANGE_ME_generate_at_least_32_random_chars")
    JWT_EXPIRE_MINUTES: int = 60

    CREDENTIAL_ENCRYPTION_KEY: str = Field(default="CHANGE_ME_fernet_key")

    CORS_ORIGINS: str = "http://localhost:5173"
    ENABLE_LAB_MODE: bool = True
    ALLOW_REGISTRATION: bool = True

    SCAN_TIMEOUT_SECONDS: int = 900
    WORKER_POLL_SECONDS: float = 2.0


def validate_secrets(settings: Settings) -> None:
    """Enforce strict production startup checks on cryptographic keys."""
    # 1. Validate JWT_SECRET
    if len(settings.JWT_SECRET) < 32 or "CHANGE_ME" in settings.JWT_SECRET:
        raise ValueError(
            "Security startup error: JWT_SECRET must be at least 32 characters long "
            "and cannot contain 'CHANGE_ME'. Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
        )

    # 2. Validate CREDENTIAL_ENCRYPTION_KEY is a valid Fernet key
    try:
        Fernet(settings.CREDENTIAL_ENCRYPTION_KEY.encode())
    except Exception as e:
        raise ValueError(
            f"Security startup error: CREDENTIAL_ENCRYPTION_KEY is not a valid 32-byte Fernet key ({e}). "
            "Generate one with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        ) from e


_settings_instance = None


def get_settings() -> Settings:
    """Return validated singleton application settings."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
        validate_secrets(_settings_instance)
    return _settings_instance
