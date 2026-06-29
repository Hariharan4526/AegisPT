from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.target import TargetType


class TargetCreate(BaseModel):
    target_type: TargetType
    value: str = Field(min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=1000)


class TargetUpdate(BaseModel):
    target_type: TargetType | None = None
    value: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=1000)
    is_enabled: bool | None = None


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    target_type: TargetType
    value: str
    description: str | None
    is_enabled: bool
    created_at: datetime
    updated_at: datetime
