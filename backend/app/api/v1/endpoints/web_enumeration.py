from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.api.deps import SessionDep, get_current_active_user
from app.schemas.web_enum import WebEnumerationCreate, WebEnumerationDetailRead, WebEnumerationRead
from app.services.web_enum_service import WebEnumerationService

router = APIRouter(prefix="/projects/{project_id}/targets/{target_id}/web-enumeration", tags=["Web Enumeration"])


def get_web_enumeration_service(session: SessionDep) -> WebEnumerationService:
    return WebEnumerationService(session=session)


@router.post("", response_model=WebEnumerationDetailRead, status_code=status.HTTP_201_CREATED)
def start_web_enumeration(
    project_id: UUID,
    target_id: UUID,
    payload: WebEnumerationCreate,
    current_user=Depends(get_current_active_user),
    web_enumeration_service: WebEnumerationService = Depends(get_web_enumeration_service),
) -> WebEnumerationDetailRead:
    return web_enumeration_service.start_enumeration(
        current_user=current_user,
        project_id=project_id,
        target_id=target_id,
        payload=payload,
    ).detail


@router.get("", response_model=list[WebEnumerationRead])
def list_web_enumerations(
    project_id: UUID,
    target_id: UUID,
    current_user=Depends(get_current_active_user),
    web_enumeration_service: WebEnumerationService = Depends(get_web_enumeration_service),
) -> list[WebEnumerationRead]:
    return web_enumeration_service.list_enumerations(current_user, project_id, target_id)


@router.get("/{enumeration_id}", response_model=WebEnumerationDetailRead)
def get_web_enumeration(
    project_id: UUID,
    target_id: UUID,
    enumeration_id: UUID,
    current_user=Depends(get_current_active_user),
    web_enumeration_service: WebEnumerationService = Depends(get_web_enumeration_service),
) -> WebEnumerationDetailRead:
    return web_enumeration_service.get_enumeration(current_user, project_id, target_id, enumeration_id)
