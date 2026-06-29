from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import Depends

from app.api.deps import get_db_session
from app.api.v1.endpoints.scans import get_scan_service
from app.api.v1.endpoints.vulnerabilities import get_vulnerability_service
from app.models.scan import ScanType
from app.services.nmap_service import NmapScanService
from app.services.vulnerability_service import CveMatch, VulnerabilityService


class FakeScanExecutor:
    def run(self, target: str, arguments: list[str]) -> str:
        return """
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.0.2.10" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" />
        <service name="https" product="Apache httpd" version="2.4.58" cpe="cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*" />
      </port>
    </ports>
  </host>
</nmaprun>
""".strip()


class FakeNvdClient:
    def search_by_cpe(self, cpe_name: str) -> list[CveMatch]:
        return [
            CveMatch(
                cve_id="CVE-2024-9999",
                description="Apache httpd request smuggling vulnerability.",
                severity="high",
                cvss_version="3.1",
                cvss_score=8.8,
                published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
                last_modified_at=datetime(2024, 1, 2, tzinfo=timezone.utc),
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-9999"],
                weaknesses=["CWE-79"],
                cwe_ids=["CWE-79"],
            )
        ]


def _register_project_target_and_scan(client):
    email = f"vuln-{uuid4().hex[:8]}@example.com"
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Vuln Owner",
            "role": "analyst",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongPassword123!"},
    )
    assert login_response.status_code == 200
    headers = {"Authorization": f"Bearer {login_response.json()['tokens']['access_token']}"}

    project_response = client.post(
        "/api/v1/projects",
        headers=headers,
        json={"name": "Vuln Project"},
    )
    assert project_response.status_code == 201
    project_id = project_response.json()["id"]

    target_response = client.post(
        f"/api/v1/projects/{project_id}/targets",
        headers=headers,
        json={"target_type": "domain", "value": "example.test"},
    )
    assert target_response.status_code == 201
    target_id = target_response.json()["id"]

    original_scan_service = client.app.dependency_overrides.get(get_scan_service)

    def fake_scan_service(session=Depends(get_db_session)):
        return NmapScanService(session=session, executor=FakeScanExecutor())

    client.app.dependency_overrides[get_scan_service] = fake_scan_service
    try:
        scan_response = client.post(
            f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
            headers=headers,
            json={"scan_type": ScanType.tcp_scan.value, "arguments": ["-sV"]},
        )
        assert scan_response.status_code == 201
    finally:
        if original_scan_service is None:
            client.app.dependency_overrides.pop(get_scan_service, None)
        else:
            client.app.dependency_overrides[get_scan_service] = original_scan_service

    return headers, project_id


def test_vulnerability_assessment_and_cve_enrichment(client) -> None:
    headers, project_id = _register_project_target_and_scan(client)

    original_vulnerability_service = client.app.dependency_overrides.get(get_vulnerability_service)

    def fake_vulnerability_service(session=Depends(get_db_session)):
        return VulnerabilityService(session=session, client=FakeNvdClient())

    client.app.dependency_overrides[get_vulnerability_service] = fake_vulnerability_service
    try:
        assess_response = client.post(
            f"/api/v1/projects/{project_id}/vulnerabilities/assess",
            headers=headers,
        )
        assert assess_response.status_code == 201
        summary = assess_response.json()
        assert summary["services_analyzed"] == 1
        assert summary["cves_upserted"] == 1
        assert summary["assessments_upserted"] == 1

        assessments_response = client.get(
            f"/api/v1/projects/{project_id}/vulnerabilities",
            headers=headers,
        )
        assert assessments_response.status_code == 200
        assessments = assessments_response.json()
        assert len(assessments) == 1
        assert assessments[0]["severity"] == "high"
        assert assessments[0]["owasp_category"] == "A03:2021-Injection"
        assert assessments[0]["risk_score"] > 0

        cves_response = client.get(
            f"/api/v1/projects/{project_id}/vulnerabilities/cves",
            headers=headers,
        )
        assert cves_response.status_code == 200
        cves = cves_response.json()
        assert len(cves) == 1
        assert cves[0]["cve_id"] == "CVE-2024-9999"
    finally:
        if original_vulnerability_service is None:
            client.app.dependency_overrides.pop(get_vulnerability_service, None)
        else:
            client.app.dependency_overrides[get_vulnerability_service] = original_vulnerability_service
