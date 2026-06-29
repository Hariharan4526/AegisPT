from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models.scan import Scan, ScanHost, ScanPort, ScanService, ScanStatus, ScanType


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_scan(
        self,
        *,
        project_id: UUID,
        target_id: UUID,
        scan_type: ScanType,
        command: str,
        arguments: dict,
    ) -> Scan:
        scan = Scan(
            project_id=project_id,
            target_id=target_id,
            scan_type=scan_type,
            status=ScanStatus.pending,
            command=command,
            arguments=arguments,
        )
        self.session.add(scan)
        self.session.flush()
        return scan

    def get_by_id(self, scan_id: UUID) -> Scan | None:
        statement: Select[tuple[Scan]] = select(Scan).where(Scan.id == scan_id)
        return self.session.scalars(statement).first()

    def list_by_target(self, target_id: UUID) -> list[Scan]:
        statement = select(Scan).where(Scan.target_id == target_id).order_by(Scan.created_at.desc())
        return list(self.session.scalars(statement).all())

    def mark_running(self, scan: Scan) -> None:
        scan.status = ScanStatus.running
        scan.started_at = datetime.now(timezone.utc)
        self.session.add(scan)

    def mark_completed(self, scan: Scan, raw_output: dict) -> None:
        scan.status = ScanStatus.completed
        scan.completed_at = datetime.now(timezone.utc)
        scan.raw_output = raw_output
        self.session.add(scan)

    def mark_failed(self, scan: Scan, error_message: str) -> None:
        scan.status = ScanStatus.failed
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = error_message
        self.session.add(scan)

    def add_host(self, scan_id: UUID, address: str, hostname: str | None, status: str | None) -> ScanHost:
        host = ScanHost(scan_id=scan_id, address=address, hostname=hostname, status=status)
        self.session.add(host)
        self.session.flush()
        return host

    def add_port(
        self,
        *,
        host_id: UUID,
        port_number: int,
        protocol: str,
        state: str,
        reason: str | None,
    ) -> ScanPort:
        port = ScanPort(
            host_id=host_id,
            port_number=port_number,
            protocol=protocol,
            state=state,
            reason=reason,
        )
        self.session.add(port)
        self.session.flush()
        return port

    def add_service(
        self,
        *,
        port_id: UUID,
        name: str | None,
        product: str | None,
        version: str | None,
        extrainfo: str | None,
        cpe: str | None,
        tunnel: str | None,
    ) -> ScanService:
        service = ScanService(
            port_id=port_id,
            name=name,
            product=product,
            version=version,
            extrainfo=extrainfo,
            cpe=cpe,
            tunnel=tunnel,
        )
        self.session.add(service)
        self.session.flush()
        return service
