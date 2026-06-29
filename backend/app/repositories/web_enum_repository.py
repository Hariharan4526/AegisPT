from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models.web_enum import WebEnumeration, WebEnumerationStatus, WebEnumerationTool, WebFinding, WebFindingType


class WebEnumerationRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        *,
        project_id: UUID,
        target_id: UUID,
        tool: WebEnumerationTool,
        command: str,
        arguments: dict,
    ) -> WebEnumeration:
        enumeration = WebEnumeration(
            project_id=project_id,
            target_id=target_id,
            tool=tool,
            status=WebEnumerationStatus.pending,
            command=command,
            arguments=arguments,
        )
        self.session.add(enumeration)
        self.session.flush()
        return enumeration

    def get_by_id(self, enumeration_id: UUID) -> WebEnumeration | None:
        statement: Select[tuple[WebEnumeration]] = select(WebEnumeration).where(
            WebEnumeration.id == enumeration_id,
        )
        return self.session.scalars(statement).first()

    def list_by_target(self, target_id: UUID) -> list[WebEnumeration]:
        statement = select(WebEnumeration).where(
            WebEnumeration.target_id == target_id,
        ).order_by(WebEnumeration.created_at.desc())
        return list(self.session.scalars(statement).all())

    def mark_running(self, enumeration: WebEnumeration) -> None:
        enumeration.status = WebEnumerationStatus.running
        enumeration.started_at = datetime.now(timezone.utc)
        self.session.add(enumeration)

    def mark_completed(self, enumeration: WebEnumeration, raw_output: dict) -> None:
        enumeration.status = WebEnumerationStatus.completed
        enumeration.completed_at = datetime.now(timezone.utc)
        enumeration.raw_output = raw_output
        self.session.add(enumeration)

    def mark_failed(self, enumeration: WebEnumeration, error_message: str) -> None:
        enumeration.status = WebEnumerationStatus.failed
        enumeration.completed_at = datetime.now(timezone.utc)
        enumeration.error_message = error_message
        self.session.add(enumeration)

    def add_finding(
        self,
        *,
        enumeration_id: UUID,
        finding_type: WebFindingType,
        name: str,
        value: str | None,
        source: str | None,
        status_code: int | None,
        extra: dict | None,
    ) -> WebFinding:
        finding = WebFinding(
            enumeration_id=enumeration_id,
            finding_type=finding_type,
            name=name,
            value=value,
            source=source,
            status_code=status_code,
            extra=extra,
        )
        self.session.add(finding)
        self.session.flush()
        return finding
