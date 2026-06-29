from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.api.deps import SessionDep, get_current_active_user
from app.schemas.vulnerability import (
    CveRecordRead,
    VulnerabilityAssessmentRead,
    VulnerabilityAssessmentRunRead,
)
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter(prefix="/projects/{project_id}/vulnerabilities", tags=["Vulnerabilities"])


def get_vulnerability_service(session: SessionDep) -> VulnerabilityService:
    return VulnerabilityService(session=session)


@router.post("/assess", response_model=VulnerabilityAssessmentRunRead, status_code=status.HTTP_201_CREATED)
def assess_project_vulnerabilities(
    project_id: UUID,
    current_user=Depends(get_current_active_user),
    vulnerability_service: VulnerabilityService = Depends(get_vulnerability_service),
) -> VulnerabilityAssessmentRunRead:
    result = vulnerability_service.assess_project(current_user, project_id)
    return VulnerabilityAssessmentRunRead(
        project_id=result.project_id,
        services_analyzed=result.services_analyzed,
        cves_upserted=result.cves_upserted,
        assessments_upserted=result.assessments_upserted,
        generated_at=result.generated_at,
    )


@router.get("", response_model=list[VulnerabilityAssessmentRead])
def list_vulnerability_assessments(
    project_id: UUID,
    current_user=Depends(get_current_active_user),
    vulnerability_service: VulnerabilityService = Depends(get_vulnerability_service),
) -> list[VulnerabilityAssessmentRead]:
    return vulnerability_service.list_assessments(current_user, project_id)


@router.get("/cves", response_model=list[CveRecordRead])
def list_project_cves(
    project_id: UUID,
    current_user=Depends(get_current_active_user),
    vulnerability_service: VulnerabilityService = Depends(get_vulnerability_service),
) -> list[CveRecordRead]:
    return vulnerability_service.list_cves(current_user, project_id)
