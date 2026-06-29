from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.target import Target, TargetType


class ProjectRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, *, owner_id: UUID, name: str, description: str | None) -> Project:
        project = Project(owner_id=owner_id, name=name, description=description)
        self.session.add(project)
        self.session.flush()
        return project

    def get_by_id(self, project_id: UUID) -> Project | None:
        statement: Select[tuple[Project]] = select(Project).where(
            Project.id == project_id,
            Project.deleted_at.is_(None),
        )
        return self.session.scalars(statement).first()

    def list_by_owner(self, owner_id: UUID) -> list[Project]:
        statement = select(Project).where(
            Project.owner_id == owner_id,
            Project.deleted_at.is_(None),
        ).order_by(Project.created_at.desc())
        return list(self.session.scalars(statement).all())

    def list_all(self) -> list[Project]:
        statement = select(Project).where(Project.deleted_at.is_(None)).order_by(Project.created_at.desc())
        return list(self.session.scalars(statement).all())

    def delete(self, project: Project) -> None:
        project.deleted_at = datetime.now(timezone.utc)
        self.session.add(project)


class TargetRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        *,
        project_id: UUID,
        target_type: TargetType,
        value: str,
        description: str | None,
    ) -> Target:
        target = Target(
            project_id=project_id,
            target_type=target_type,
            value=value,
            description=description,
        )
        self.session.add(target)
        self.session.flush()
        return target

    def list_by_project(self, project_id: UUID) -> list[Target]:
        statement = select(Target).where(
            Target.project_id == project_id,
            Target.deleted_at.is_(None),
        ).order_by(Target.created_at.desc())
        return list(self.session.scalars(statement).all())

    def get_by_id(self, target_id: UUID) -> Target | None:
        statement: Select[tuple[Target]] = select(Target).where(
            Target.id == target_id,
            Target.deleted_at.is_(None),
        )
        return self.session.scalars(statement).first()

    def delete(self, target: Target) -> None:
        target.deleted_at = datetime.now(timezone.utc)
        self.session.add(target)
