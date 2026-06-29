from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.api.deps import SessionDep, get_current_active_user
from app.schemas.scan import ScanCreate, ScanDetailRead, ScanRead
from app.services.nmap_service import NmapScanService

router = APIRouter(prefix="/projects/{project_id}/targets/{target_id}/scans", tags=["Scans"])


def get_scan_service(session: SessionDep) -> NmapScanService:
    return NmapScanService(session=session)


@router.post("", response_model=ScanDetailRead, status_code=status.HTTP_201_CREATED)
def start_scan(
    project_id: UUID,
    target_id: UUID,
    payload: ScanCreate,
    current_user=Depends(get_current_active_user),
    scan_service: NmapScanService = Depends(get_scan_service),
) -> ScanDetailRead:
    return scan_service.start_scan(
        current_user=current_user,
        project_id=project_id,
        target_id=target_id,
        payload=payload,
    ).detail


@router.get("", response_model=list[ScanRead])
def list_scans(
    project_id: UUID,
    target_id: UUID,
    current_user=Depends(get_current_active_user),
    scan_service: NmapScanService = Depends(get_scan_service),
) -> list[ScanRead]:
    return scan_service.list_scans(current_user, project_id, target_id)


@router.get("/{scan_id}", response_model=ScanDetailRead)
def get_scan(
    project_id: UUID,
    target_id: UUID,
    scan_id: UUID,
    current_user=Depends(get_current_active_user),
    scan_service: NmapScanService = Depends(get_scan_service),
) -> ScanDetailRead:
    return scan_service.get_scan(current_user, project_id, target_id, scan_id)
