from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from logging import Logger
from typing import Protocol
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.repositories.project_repository import ProjectRepository, TargetRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.user_repository import AuditLogRepository
from app.schemas.scan import ScanCreate, ScanDetailRead, ScanRead


class NmapExecutor(Protocol):
    def run(self, target: str, arguments: list[str]) -> str:
        raise NotImplementedError


class SubprocessNmapExecutor:
    def __init__(self, executable: str = "nmap") -> None:
        self.executable = executable

    def run(self, target: str, arguments: list[str]) -> str:
        command = [self.executable, "-oX", "-"] + arguments + [target]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "nmap scan failed")
        return completed.stdout


@dataclass(slots=True)
class ScanResult:
    scan: Scan
    detail: ScanDetailRead


class NmapScanService:
    def __init__(self, session: Session, executor: NmapExecutor | None = None) -> None:
        self.session = session
        self.executor = executor or SubprocessNmapExecutor()
        self.scans = ScanRepository(session)
        self.projects = ProjectRepository(session)
        self.targets = TargetRepository(session)
        self.audit_logs = AuditLogRepository(session)
        self.logger: Logger = get_logger("pentestlab.nmap")

    def start_scan(
        self,
        *,
        current_user: User,
        project_id: UUID,
        target_id: UUID,
        payload: ScanCreate,
    ) -> ScanResult:
        project = self._get_project_for_user(current_user, project_id)
        target = self._get_target_for_project(project.id, target_id)
        scan = self.scans.create_scan(
            project_id=project.id,
            target_id=target.id,
            scan_type=payload.scan_type,
            command="nmap",
            arguments={"args": payload.arguments},
        )
        self.scans.mark_running(scan)
        self.session.commit()

        try:
            xml_output = self.executor.run(target.value, payload.arguments)
            parsed_output = self._parse_xml_output(xml_output)
            self._persist_results(scan, parsed_output)
            self.scans.mark_completed(scan, parsed_output)
            self.audit_logs.create(
                user_id=current_user.id,
                action="scans.completed",
                details={"scan_id": str(scan.id), "target_id": str(target.id)},
                occurred_at=datetime.now(timezone.utc),
            )
            self.session.commit()
            self.session.refresh(scan)
            self.logger.info("scan_completed", extra={"scan_id": str(scan.id), "target": target.value})
        except Exception as exc:
            self.scans.mark_failed(scan, str(exc))
            self.audit_logs.create(
                user_id=current_user.id,
                action="scans.failed",
                details={"scan_id": str(scan.id), "error": str(exc)},
                occurred_at=datetime.now(timezone.utc),
            )
            self.session.commit()
            self.logger.exception("scan_failed", extra={"scan_id": str(scan.id)})
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="The scan engine failed to complete the requested scan.",
            ) from exc

        return ScanResult(scan=scan, detail=ScanDetailRead.model_validate(scan))

    def list_scans(self, current_user: User, project_id: UUID, target_id: UUID) -> list[ScanRead]:
        project = self._get_project_for_user(current_user, project_id)
        self._get_target_for_project(project.id, target_id)
        scans = self.scans.list_by_target(target_id)
        return [ScanRead.model_validate(scan) for scan in scans]

    def get_scan(self, current_user: User, project_id: UUID, target_id: UUID, scan_id: UUID) -> ScanDetailRead:
        project = self._get_project_for_user(current_user, project_id)
        self._get_target_for_project(project.id, target_id)
        scan = self.scans.get_by_id(scan_id)
        if scan is None or scan.target_id != target_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
        return self._build_detail(scan)

    def _persist_results(self, scan: Scan, parsed_output: dict) -> None:
        for host_data in parsed_output.get("hosts", []):
            host = self.scans.add_host(
                scan_id=scan.id,
                address=host_data["address"],
                hostname=host_data.get("hostname"),
                status=host_data.get("status"),
            )
            for port_data in host_data.get("ports", []):
                port = self.scans.add_port(
                    host_id=host.id,
                    port_number=port_data["port_number"],
                    protocol=port_data["protocol"],
                    state=port_data["state"],
                    reason=port_data.get("reason"),
                )
                service_data = port_data.get("service")
                if service_data:
                    self.scans.add_service(
                        port_id=port.id,
                        name=service_data.get("name"),
                        product=service_data.get("product"),
                        version=service_data.get("version"),
                        extrainfo=service_data.get("extrainfo"),
                        cpe=service_data.get("cpe"),
                        tunnel=service_data.get("tunnel"),
                    )

    def _parse_xml_output(self, xml_output: str) -> dict:
        root = ET.fromstring(xml_output)
        parsed_hosts: list[dict] = []
        for host_element in root.findall("host"):
            address_element = host_element.find("address")
            if address_element is None:
                continue
            ports: list[dict] = []
            ports_element = host_element.find("ports")
            if ports_element is not None:
                for port_element in ports_element.findall("port"):
                    state_element = port_element.find("state")
                    service_element = port_element.find("service")
                    ports.append(
                        {
                            "port_number": int(port_element.attrib["portid"]),
                            "protocol": port_element.attrib["protocol"],
                            "state": state_element.attrib.get("state") if state_element is not None else "unknown",
                            "reason": state_element.attrib.get("reason") if state_element is not None else None,
                            "service": {
                                "name": service_element.attrib.get("name") if service_element is not None else None,
                                "product": service_element.attrib.get("product") if service_element is not None else None,
                                "version": service_element.attrib.get("version") if service_element is not None else None,
                                "extrainfo": service_element.attrib.get("extrainfo") if service_element is not None else None,
                                "cpe": service_element.attrib.get("cpe") if service_element is not None else None,
                                "tunnel": service_element.attrib.get("tunnel") if service_element is not None else None,
                            }
                            if service_element is not None
                            else None,
                        }
                    )
            hostnames_element = host_element.find("hostnames")
            hostname_value = None
            if hostnames_element is not None:
                hostname = hostnames_element.find("hostname")
                if hostname is not None:
                    hostname_value = hostname.attrib.get("name")
            status_element = host_element.find("status")
            parsed_hosts.append(
                {
                    "address": address_element.attrib.get("addr", "unknown"),
                    "hostname": hostname_value,
                    "status": status_element.attrib.get("state") if status_element is not None else None,
                    "ports": ports,
                }
            )
        return {"hosts": parsed_hosts}

    def _build_detail(self, scan: Scan) -> ScanDetailRead:
        self.session.refresh(scan)
        return ScanDetailRead.model_validate(scan)

    def _get_project_for_user(self, current_user: User, project_id: UUID) -> Project:
        project = self.projects.get_by_id(project_id)
        if project is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
        if current_user.id != project.owner_id and current_user.role.value != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied for this project.")
        return project

    def _get_target_for_project(self, project_id: UUID, target_id: UUID) -> Target:
        target = self.targets.get_by_id(target_id)
        if target is None or target.project_id != project_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
        return target
