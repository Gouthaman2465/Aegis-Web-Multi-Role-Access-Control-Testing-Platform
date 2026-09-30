"""Pydantic schemas for access control findings, reports, and comparisons."""

from datetime import datetime
from pydantic import BaseModel, Field, field_validator, ConfigDict


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    fingerprint: str
    type: str
    title: str
    severity: str
    confidence: int
    cvss_score: float
    cvss_vector: str
    cwe: str
    owasp: str
    method: str
    url: str
    signature: str
    source_role: str
    tested_role: str
    status: str
    created_at: datetime


class FindingDetailResponse(FindingResponse):
    description: str
    remediation: str
    note: str | None
    evidence: dict


class FindingUpdate(BaseModel):
    status: str | None = None
    note: str | None = Field(None, max_length=1000)

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        if v is not None:
            valid = {"open", "false_positive", "fixed", "accepted"}
            if v not in valid:
                raise ValueError(f"Status must be one of {valid}")
        return v


class CompareResponse(BaseModel):
    new: list[dict]
    fixed: list[dict]
    persisting: list[dict]


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None
    action: str
    resource_type: str | None
    resource_id: int | None
    ip: str | None
    details: dict
    created_at: datetime
