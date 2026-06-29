from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.project import Project
    from app.models.target import Target


class WebEnumerationTool(str, enum.Enum):
    ffuf = "ffuf"
    whatweb = "whatweb"


class WebEnumerationStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class WebEnumeration(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "web_enumerations"
    __table_args__ = (
        Index("ix_web_enumerations_project_id", "project_id"),
        Index("ix_web_enumerations_target_id", "target_id"),
        Index("ix_web_enumerations_tool", "tool"),
        Index("ix_web_enumerations_status", "status"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    tool: Mapped[WebEnumerationTool] = mapped_column(
        Enum(WebEnumerationTool, name="web_enumeration_tool", native_enum=False),
        nullable=False,
    )
    status: Mapped[WebEnumerationStatus] = mapped_column(
        Enum(WebEnumerationStatus, name="web_enumeration_status", native_enum=False),
        default=WebEnumerationStatus.pending,
        nullable=False,
    )
    command: Mapped[str] = mapped_column(String(255), nullable=False)
    arguments: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    project: Mapped["Project"] = relationship()
    target: Mapped["Target"] = relationship()
    findings: Mapped[list["WebFinding"]] = relationship(
        back_populates="enumeration",
        cascade="all, delete-orphan",
    )


class WebFindingType(str, enum.Enum):
    directory = "directory"
    technology = "technology"
    header = "header"
    cookie = "cookie"
    file = "file"
    metadata = "metadata"


class WebFinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "web_findings"
    __table_args__ = (
        Index("ix_web_findings_enumeration_id", "enumeration_id"),
        Index("ix_web_findings_finding_type", "finding_type"),
        Index("ix_web_findings_name", "name"),
    )

    enumeration_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("web_enumerations.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_type: Mapped[WebFindingType] = mapped_column(
        Enum(WebFindingType, name="web_finding_type", native_enum=False),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_code: Mapped[int | None] = mapped_column(nullable=True)
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    enumeration: Mapped["WebEnumeration"] = relationship(back_populates="findings")
