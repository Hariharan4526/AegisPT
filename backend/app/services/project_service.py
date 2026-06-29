from __future__ import annotations

from datetime import datetime, timezone
from logging import Logger
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.token import AuditAction
from app.models.user import User, UserRole
from app.repositories.project_repository import ProjectRepository, TargetRepository
from app.repositories.user_repository import AuditLogRepository
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate
from app.schemas.target import TargetCreate, TargetRead, TargetUpdate


class ProjectService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.logger: Logger = get_logger("pentestlab.projects")
        self.projects = ProjectRepository(session)
        self.targets = TargetRepository(session)
        self.audit_logs = AuditLogRepository(session)

    def create_project(self, current_user: User, payload: ProjectCreate) -> ProjectRead:
        self._assert_project_write_access(current_user)
        project = self.projects.create(
            owner_id=current_user.id,
            name=payload.name,
            description=payload.description,
        )
        self.audit_logs.create(
            user_id=current_user.id,
            action="projects.create",
            details={"project_id": str(project.id), "name": project.name},
            occurred_at=datetime.now(timezone.utc),
        )
        self.session.commit()
        self.logger.info("project_created")
        return ProjectRead.model_validate(project)

    def list_projects(self, current_user: User) -> list[ProjectRead]:
        projects = self.projects.list_all() if current_user.role == UserRole.admin else self.projects.list_by_owner(current_user.id)
        self.logger.info("projects_listed")
        return [ProjectRead.model_validate(project) for project in projects]

    def get_project(self, current_user: User, project_id: UUID) -> ProjectRead:
        project = self._get_project_or_404(current_user, project_id)
        return ProjectRead.model_validate(project)

    def update_project(self, current_user: User, project_id: UUID, payload: ProjectUpdate) -> ProjectRead:
        project = self._get_project_or_404(current_user, project_id)
        self._assert_project_owner_or_admin(current_user, project.owner_id)
        if payload.name is not None:
            project.name = payload.name
        if payload.description is not None:
            project.description = payload.description
        self.audit_logs.create(
            user_id=current_user.id,
            action="projects.update",
            details={"project_id": str(project.id)},
            occurred_at=datetime.now(timezone.utc),
        )
        self.session.commit()
        self.session.refresh(project)
        self.logger.info("project_updated")
        return ProjectRead.model_validate(project)

    def delete_project(self, current_user: User, project_id: UUID) -> None:
        project = self._get_project_or_404(current_user, project_id)
        self._assert_project_owner_or_admin(current_user, project.owner_id)
        self.projects.delete(project)
        self.audit_logs.create(
            user_id=current_user.id,
            action="projects.delete",
            details={"project_id": str(project.id)},
            occurred_at=datetime.now(timezone.utc),
        )
        self.session.commit()
        self.logger.warning("project_deleted")

    def add_target(self, current_user: User, project_id: UUID, payload: TargetCreate) -> TargetRead:
        project = self._get_project_or_404(current_user, project_id)
        self._assert_project_owner_or_admin(current_user, project.owner_id)
        target = self.targets.create(
            project_id=project.id,
            target_type=payload.target_type,
            value=payload.value,
            description=payload.description,
        )
        self.audit_logs.create(
            user_id=current_user.id,
            action="targets.create",
            details={"project_id": str(project.id), "target_id": str(target.id)},
            occurred_at=datetime.now(timezone.utc),
        )
        self.session.commit()
        self.logger.info("target_created")
        return TargetRead.model_validate(target)

    def list_targets(self, current_user: User, project_id: UUID) -> list[TargetRead]:
        project = self._get_project_or_404(current_user, project_id)
        self._assert_project_access(current_user, project.owner_id)
        targets = self.targets.list_by_project(project.id)
        self.logger.info("targets_listed")
        return [TargetRead.model_validate(target) for target in targets]

    def update_target(self, current_user: User, project_id: UUID, target_id: UUID, payload: TargetUpdate) -> TargetRead:
        project = self._get_project_or_404(current_user, project_id)
        self._assert_project_owner_or_admin(current_user, project.owner_id)
        target = self._get_target_or_404(target_id, project.id)
        if payload.target_type is not None:
            target.target_type = payload.target_type
        if payload.value is not None:
            target.value = payload.value
        if payload.description is not None:
            target.description = payload.description
        if payload.is_enabled is not None:
            target.is_enabled = payload.is_enabled
        self.audit_logs.create(
            user_id=current_user.id,
            action="targets.update",
            details={"project_id": str(project.id), "target_id": str(target.id)},
            occurred_at=datetime.now(timezone.utc),
        )
        self.session.commit()
        self.session.refresh(target)
        self.logger.info("target_updated")
        return TargetRead.model_validate(target)

    def delete_target(self, current_user: User, project_id: UUID, target_id: UUID) -> None:
        project = self._get_project_or_404(current_user, project_id)
        self._assert_project_owner_or_admin(current_user, project.owner_id)
        target = self._get_target_or_404(target_id, project.id)
        self.targets.delete(target)
        self.audit_logs.create(
            user_id=current_user.id,
            action="targets.delete",
            details={"project_id": str(project.id), "target_id": str(target.id)},
            occurred_at=datetime.now(timezone.utc),
        )
        self.session.commit()
        self.logger.warning("target_deleted")

    def _get_project_or_404(self, current_user: User, project_id: UUID):
        project = self.projects.get_by_id(project_id)
        if project is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
        self._assert_project_access(current_user, project.owner_id)
        return project

    def _get_target_or_404(self, target_id: UUID, project_id: UUID):
        target = self.targets.get_by_id(target_id)
        if target is None or target.project_id != project_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
        return target

    def _assert_project_access(self, current_user: User, owner_id: UUID) -> None:
        if current_user.role == UserRole.admin or current_user.id == owner_id:
            return
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied for this project.")

    def _assert_project_owner_or_admin(self, current_user: User, owner_id: UUID) -> None:
        if current_user.role == UserRole.admin or current_user.id == owner_id:
            return
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not allowed to modify this project.")

    def _assert_project_write_access(self, current_user: User) -> None:
        if current_user.role in {UserRole.admin, UserRole.analyst, UserRole.operator}:
            return
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your role cannot create projects.")
