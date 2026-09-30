"""Vulnerability and access control finding models."""

from datetime import datetime, timezone
from sqlalchemy import (
    Integer,
    String,
    Float,
    Text,
    DateTime,
    ForeignKey,
    JSON,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base


class Finding(Base):
    """Specific access-control violation or security finding."""
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_fingerprint", "fingerprint"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(32), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # Critical|High|Medium|Low|Info
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)   # 0..100
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    cvss_vector: Mapped[str] = mapped_column(String(128), nullable=False)
    cwe: Mapped[str] = mapped_column(String(32), nullable=False)
    owasp: Mapped[str] = mapped_column(String(64), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    signature: Mapped[str] = mapped_column(String(512), nullable=False)
    source_role: Mapped[str] = mapped_column(String(32), nullable=False)
    tested_role: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)  # open|false_positive|fixed|accepted
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    scan = relationship("Scan", back_populates="findings")
