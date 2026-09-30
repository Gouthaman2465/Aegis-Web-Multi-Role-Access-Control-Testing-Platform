"""Target application and associated test account models."""

from datetime import datetime, timezone
from sqlalchemy import (
    Integer,
    String,
    DateTime,
    ForeignKey,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base


class Target(Base):
    """Web application target configured for access control evaluation."""
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    scope_hosts: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    ownership_status: Mapped[str] = mapped_column(String(32), default="unverified", nullable=False)  # "unverified" | "verified" | "lab"
    ownership_token: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    owner = relationship("User", back_populates="targets")
    accounts = relationship("TargetAccount", back_populates="target", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="target")


class TargetAccount(Base):
    """Credentials and login selectors for an authenticated role on a target."""
    __tablename__ = "target_accounts"
    __table_args__ = (
        UniqueConstraint("target_id", "role_label", name="uq_target_role_label"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    role_label: Mapped[str] = mapped_column(String(32), nullable=False)
    privilege_level: Mapped[int] = mapped_column(Integer, nullable=False)  # 1..100
    login_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    password_encrypted: Mapped[str] = mapped_column(String(1024), nullable=False)
    username_selector: Mapped[str] = mapped_column(String(255), nullable=False)
    password_selector: Mapped[str] = mapped_column(String(255), nullable=False)
    submit_selector: Mapped[str] = mapped_column(String(255), nullable=False)
    dismiss_selectors: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    success_url_contains: Mapped[str | None] = mapped_column(String(255), nullable=True)
    identifiers: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    target = relationship("Target", back_populates="accounts")
