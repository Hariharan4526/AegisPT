from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.scan import ScanStatus, ScanType


class ScanCreate(BaseModel):
    scan_type: ScanType = ScanType.tcp_scan
    arguments: list[str] = Field(default_factory=list)


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    target_id: UUID
    scan_type: ScanType
    status: ScanStatus
    command: str
    arguments: dict
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    raw_output: dict | None
    created_at: datetime
    updated_at: datetime


class ScanServiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str | None
    product: str | None
    version: str | None
    extrainfo: str | None
    cpe: str | None
    tunnel: str | None


class ScanPortRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    port_number: int
    protocol: str
    state: str
    reason: str | None
    service: ScanServiceRead | None


class ScanHostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    address: str
    hostname: str | None
    status: str | None
    ports: list[ScanPortRead]


class ScanDetailRead(ScanRead):
    hosts: list[ScanHostRead] = Field(default_factory=list)
