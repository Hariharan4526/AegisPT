from __future__ import annotations

import enum
import uuid

from sqlalchemy import Boolean, Enum, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin, UUIDMixin


class TargetType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    url = "url"


class Target(Base, UUIDMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("project_id", "value", name="uq_targets_project_value"),
        Index("ix_targets_project_id", "project_id"),
        Index("ix_targets_target_type", "target_type"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_type: Mapped[TargetType] = mapped_column(
        Enum(TargetType, name="target_type", native_enum=False),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    project: Mapped["Project"] = relationship(back_populates="targets")
