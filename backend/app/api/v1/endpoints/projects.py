from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Response, status

from app.api.deps import SessionDep, get_current_active_user
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate
from app.schemas.target import TargetCreate, TargetRead, TargetUpdate
from app.services.project_service import ProjectService

router = APIRouter(prefix="/projects", tags=["Projects"])


def get_project_service(session: SessionDep) -> ProjectService:
    return ProjectService(session=session)


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> ProjectRead:
    return project_service.create_project(current_user, payload)


@router.get("", response_model=list[ProjectRead])
def list_projects(
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> list[ProjectRead]:
    return project_service.list_projects(current_user)


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(
    project_id: UUID,
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> ProjectRead:
    return project_service.get_project(current_user, project_id)


@router.put("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: UUID,
    payload: ProjectUpdate,
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> ProjectRead:
    return project_service.update_project(current_user, project_id, payload)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: UUID,
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> Response:
    project_service.delete_project(current_user, project_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{project_id}/targets", response_model=list[TargetRead])
def list_targets(
    project_id: UUID,
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> list[TargetRead]:
    return project_service.list_targets(current_user, project_id)


@router.post("/{project_id}/targets", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def create_target(
    project_id: UUID,
    payload: TargetCreate,
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> TargetRead:
    return project_service.add_target(current_user, project_id, payload)


@router.put("/{project_id}/targets/{target_id}", response_model=TargetRead)
def update_target(
    project_id: UUID,
    target_id: UUID,
    payload: TargetUpdate,
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> TargetRead:
    return project_service.update_target(current_user, project_id, target_id, payload)


@router.delete("/{project_id}/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    project_id: UUID,
    target_id: UUID,
    current_user=Depends(get_current_active_user),
    project_service: ProjectService = Depends(get_project_service),
) -> Response:
    project_service.delete_target(current_user, project_id, target_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
