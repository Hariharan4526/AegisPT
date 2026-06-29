from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.web_enum import WebEnumerationStatus, WebEnumerationTool, WebFindingType


class WebEnumerationCreate(BaseModel):
    tool: WebEnumerationTool
    arguments: list[str] = Field(default_factory=list)


class WebFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_type: WebFindingType
    name: str
    value: str | None
    source: str | None
    status_code: int | None
    extra: dict | None


class WebEnumerationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    target_id: UUID
    tool: WebEnumerationTool
    status: WebEnumerationStatus
    command: str
    arguments: dict
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    raw_output: dict | None
    created_at: datetime
    updated_at: datetime


class WebEnumerationDetailRead(WebEnumerationRead):
    findings: list[WebFindingRead] = Field(default_factory=list)
