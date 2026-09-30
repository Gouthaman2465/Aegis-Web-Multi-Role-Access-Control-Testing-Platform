"""Pydantic schemas for targets and target credentials."""

import re
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, ConfigDict

ROLE_LABEL_RE = re.compile(r"^[a-z0-9_-]{1,32}$")


class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    base_url: str = Field(..., min_length=1, max_length=1024)
    scope_hosts: list[str] | None = None


class TargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    base_url: str
    scope_hosts: list[str]
    ownership_status: str
    ownership_token: str
    verified_at: datetime | None
    created_at: datetime


class TargetVerifyResponse(BaseModel):
    verified: bool
    instructions: str


class AccountCreate(BaseModel):
    role_label: str
    privilege_level: int = Field(..., ge=1, le=100)
    login_url: str
    username: str
    password: str  # Write-only password, encrypted immediately upon receipt
    username_selector: str
    password_selector: str
    submit_selector: str
    dismiss_selectors: list[str] = Field(default_factory=list)
    success_url_contains: str | None = None
    identifiers: list[str] = Field(default_factory=list)

    @field_validator("role_label")
    @classmethod
    def validate_role_label(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean == "anonymous":
            raise ValueError("The role label 'anonymous' is reserved.")
        if not ROLE_LABEL_RE.match(clean):
            raise ValueError("Role label must be 1-32 chars matching ^[a-z0-9_-]+$")
        return clean


class AccountResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    role_label: str
    privilege_level: int
    login_url: str
    username: str
    username_selector: str
    password_selector: str
    submit_selector: str
    dismiss_selectors: list[str]
    success_url_contains: str | None
    identifiers: list[str]
    # Note: password is never present in AccountResponse!
