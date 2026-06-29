from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from logging import Logger
from typing import Protocol
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.project import Project
from app.models.target import Target
from app.models.user import User
from app.models.web_enum import WebEnumeration, WebEnumerationTool, WebFindingType
from app.repositories.project_repository import ProjectRepository, TargetRepository
from app.repositories.user_repository import AuditLogRepository
from app.repositories.web_enum_repository import WebEnumerationRepository
from app.schemas.web_enum import WebEnumerationCreate, WebEnumerationDetailRead, WebEnumerationRead


class WebEnumerationExecutor(Protocol):
    def run(self, target_url: str, arguments: list[str]) -> str:
        raise NotImplementedError


class SubprocessFfufExecutor:
    def __init__(self, executable: str = "ffuf") -> None:
        self.executable = executable

    def run(self, target_url: str, arguments: list[str]) -> str:
        command = [self.executable] + arguments + ["-u", f"{target_url}/FUZZ", "-of", "json"]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "ffuf scan failed")
        return completed.stdout


class SubprocessWhatWebExecutor:
    def __init__(self, executable: str = "whatweb") -> None:
        self.executable = executable

    def run(self, target_url: str, arguments: list[str]) -> str:
        command = [self.executable, "--log-json=-"] + arguments + [target_url]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "whatweb scan failed")
        return completed.stdout


@dataclass(slots=True)
class WebEnumerationResult:
    enumeration: WebEnumeration
    detail: WebEnumerationDetailRead


class WebEnumerationService:
    def __init__(self, session: Session, executor: WebEnumerationExecutor | None = None) -> None:
        self.session = session
        self.executor = executor
        self.enumerations = WebEnumerationRepository(session)
        self.projects = ProjectRepository(session)
        self.targets = TargetRepository(session)
        self.audit_logs = AuditLogRepository(session)
        self.logger: Logger = get_logger("pentestlab.web")

    def start_enumeration(
        self,
        *,
        current_user: User,
        project_id: UUID,
        target_id: UUID,
        payload: WebEnumerationCreate,
    ) -> WebEnumerationResult:
        project = self._get_project_for_user(current_user, project_id)
        target = self._get_target_for_project(project.id, target_id)
        normalized_url = self._normalize_target_url(target.value)
        executor = self.executor or self._executor_for_tool(payload.tool)
        command = payload.tool.value
        enumeration = self.enumerations.create(
            project_id=project.id,
            target_id=target.id,
            tool=payload.tool,
            command=command,
            arguments={"args": payload.arguments, "target": normalized_url},
        )
        self.enumerations.mark_running(enumeration)
        self.session.commit()

        try:
            raw_output = executor.run(normalized_url, payload.arguments)
            parsed_output = self._parse_tool_output(payload.tool, raw_output)
            self._persist_results(enumeration, parsed_output)
            self.enumerations.mark_completed(enumeration, parsed_output)
            self.audit_logs.create(
                user_id=current_user.id,
                action="web_enumerations.completed",
                details={"enumeration_id": str(enumeration.id), "target_id": str(target.id)},
                occurred_at=datetime.now(timezone.utc),
            )
            self.session.commit()
            self.session.refresh(enumeration)
            self.logger.info("web_enumeration_completed", extra={"enumeration_id": str(enumeration.id), "tool": payload.tool.value})
        except Exception as exc:
            self.enumerations.mark_failed(enumeration, str(exc))
            self.audit_logs.create(
                user_id=current_user.id,
                action="web_enumerations.failed",
                details={"enumeration_id": str(enumeration.id), "error": str(exc)},
                occurred_at=datetime.now(timezone.utc),
            )
            self.session.commit()
            self.logger.exception("web_enumeration_failed", extra={"enumeration_id": str(enumeration.id)})
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="The web enumeration engine failed to complete the requested scan.",
            ) from exc

        return WebEnumerationResult(enumeration=enumeration, detail=WebEnumerationDetailRead.model_validate(enumeration))

    def list_enumerations(self, current_user: User, project_id: UUID, target_id: UUID) -> list[WebEnumerationRead]:
        project = self._get_project_for_user(current_user, project_id)
        self._get_target_for_project(project.id, target_id)
        enumerations = self.enumerations.list_by_target(target_id)
        return [WebEnumerationRead.model_validate(enumeration) for enumeration in enumerations]

    def get_enumeration(self, current_user: User, project_id: UUID, target_id: UUID, enumeration_id: UUID) -> WebEnumerationDetailRead:
        project = self._get_project_for_user(current_user, project_id)
        self._get_target_for_project(project.id, target_id)
        enumeration = self.enumerations.get_by_id(enumeration_id)
        if enumeration is None or enumeration.target_id != target_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Web enumeration not found.")
        return self._build_detail(enumeration)

    def _persist_results(self, enumeration: WebEnumeration, parsed_output: dict) -> None:
        for finding in parsed_output.get("findings", []):
            self.enumerations.add_finding(
                enumeration_id=enumeration.id,
                finding_type=WebFindingType(finding["finding_type"]),
                name=finding["name"],
                value=finding.get("value"),
                source=finding.get("source"),
                status_code=finding.get("status_code"),
                extra=finding.get("extra"),
            )

    def _parse_tool_output(self, tool: WebEnumerationTool, raw_output: str) -> dict:
        if tool == WebEnumerationTool.ffuf:
            return self._parse_ffuf_output(raw_output)
        if tool == WebEnumerationTool.whatweb:
            return self._parse_whatweb_output(raw_output)
        raise ValueError(f"Unsupported tool: {tool}")

    def _parse_ffuf_output(self, raw_output: str) -> dict:
        payload = json.loads(raw_output or "{}")
        findings: list[dict] = []
        for result in payload.get("results", []):
            findings.append(
                {
                    "finding_type": WebFindingType.directory.value,
                    "name": result.get("input", {}).get("FUZZ", result.get("url", "directory")),
                    "value": result.get("url"),
                    "source": "ffuf",
                    "status_code": result.get("status"),
                    "extra": {
                        "length": result.get("length"),
                        "words": result.get("words"),
                        "lines": result.get("lines"),
                    },
                }
            )
        return {"findings": findings}

    def _parse_whatweb_output(self, raw_output: str) -> dict:
        payload = json.loads(raw_output or "[]")
        findings: list[dict] = []
        for item in payload:
            target_url = item.get("target")
            plugins = item.get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                findings.append(
                    {
                        "finding_type": WebFindingType.technology.value,
                        "name": plugin_name,
                        "value": target_url,
                        "source": "whatweb",
                        "status_code": None,
                        "extra": plugin_data,
                    }
                )
        return {"findings": findings}

    def _build_detail(self, enumeration: WebEnumeration) -> WebEnumerationDetailRead:
        self.session.refresh(enumeration)
        return WebEnumerationDetailRead.model_validate(enumeration)

    def _executor_for_tool(self, tool: WebEnumerationTool) -> WebEnumerationExecutor:
        if tool == WebEnumerationTool.ffuf:
            return SubprocessFfufExecutor()
        if tool == WebEnumerationTool.whatweb:
            return SubprocessWhatWebExecutor()
        raise ValueError(f"Unsupported tool: {tool}")

    def _normalize_target_url(self, target_value: str) -> str:
        if target_value.startswith("http://") or target_value.startswith("https://"):
            return target_value.rstrip("/")
        return f"http://{target_value}".rstrip("/")

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
