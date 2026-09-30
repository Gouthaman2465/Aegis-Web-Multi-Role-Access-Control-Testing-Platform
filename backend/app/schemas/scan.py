"""Pydantic schemas for scan jobs, options, and observed endpoints."""

from datetime import datetime
from pydantic import BaseModel, Field, field_validator, ConfigDict


class ScanOptions(BaseModel):
    max_pages: int = Field(30, ge=1, le=100)
    max_depth: int = Field(3, ge=1, le=5)
    request_delay_ms: int = Field(200, ge=0, le=2000)
    max_replays: int = Field(500, ge=1, le=1000)
    seed_paths: list[str] = Field(default_factory=list)
    modules: list[str] = Field(default_factory=lambda: ["access_control"])

    @field_validator("seed_paths")
    @classmethod
    def validate_seed_paths(cls, paths: list[str]) -> list[str]:
        if len(paths) > 50:
            raise ValueError("At most 50 seed paths are allowed.")
        for p in paths:
            if not p.startswith("/"):
                raise ValueError(f"Seed path '{p}' must be relative and start with '/'.")
        return paths


class ScanCreate(BaseModel):
    target_id: int
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    status: str
    options: dict
    progress_percent: int
    progress_stage: str
    error_message: str | None
    cancel_requested: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    summary: dict


class ScanEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    level: str
    stage: str
    message: str
    percent: int
    created_at: datetime


class EndpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    account_label: str
    method: str
    url: str
    signature: str
    resource_type: str
    status_code: int
    content_type: str | None
    created_at: datetime
