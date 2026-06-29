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


class ScanType(str, enum.Enum):
    host_discovery = "host_discovery"
    tcp_scan = "tcp_scan"
    udp_scan = "udp_scan"
    version_detection = "version_detection"
    os_detection = "os_detection"
    nse_scripts = "nse_scripts"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Scan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_project_id", "project_id"),
        Index("ix_scans_target_id", "target_id"),
        Index("ix_scans_status", "status"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType, name="scan_type", native_enum=False),
        nullable=False,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", native_enum=False),
        default=ScanStatus.pending,
        nullable=False,
    )
    command: Mapped[str] = mapped_column(String(255), nullable=False)
    arguments: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship()
    project: Mapped["Project"] = relationship()
    hosts: Mapped[list["ScanHost"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class ScanHost(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scan_hosts"
    __table_args__ = (
        Index("ix_scan_hosts_scan_id", "scan_id"),
        Index("ix_scan_hosts_address", "address"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    address: Mapped[str] = mapped_column(String(128), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scan: Mapped["Scan"] = relationship(back_populates="hosts")
    ports: Mapped[list["ScanPort"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )


class ScanPort(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scan_ports"
    __table_args__ = (
        Index("ix_scan_ports_host_id", "host_id"),
        Index("ix_scan_ports_port_number", "port_number"),
    )

    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    port_number: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    host: Mapped["ScanHost"] = relationship(back_populates="ports")
    service: Mapped["ScanService | None"] = relationship(
        back_populates="port",
        cascade="all, delete-orphan",
        uselist=False,
    )


class ScanService(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scan_services"
    __table_args__ = (
        Index("ix_scan_services_port_id", "port_id"),
        Index("ix_scan_services_name", "name"),
    )

    port_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_ports.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    extrainfo: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tunnel: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped["ScanPort"] = relationship(back_populates="service")
