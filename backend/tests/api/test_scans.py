from __future__ import annotations

from uuid import uuid4

from fastapi import Depends

from app.api.deps import get_db_session
from app.api.v1.endpoints.scans import get_scan_service
from app.services.nmap_service import NmapScanService


class FakeExecutor:
    def run(self, target: str, arguments: list[str]) -> str:
        return """
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.0.2.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="test-host.example" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" />
        <service name="http" product="Apache httpd" version="2.4.58" />
      </port>
    </ports>
  </host>
</nmaprun>
""".strip()


def _register_project_and_target(client):
    email = f"scan-{uuid4().hex[:8]}@example.com"
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Scan Owner",
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
        json={"name": "Scanner Project"},
    )
    assert project_response.status_code == 201
    project_id = project_response.json()["id"]
    target_response = client.post(
        f"/api/v1/projects/{project_id}/targets",
        headers=headers,
        json={"target_type": "ip", "value": "192.0.2.10"},
    )
    assert target_response.status_code == 201
    return headers, project_id, target_response.json()["id"]


def test_start_and_read_scan(client) -> None:
    headers, project_id, target_id = _register_project_and_target(client)
    app = client.app

    def fake_scan_service(session=Depends(get_db_session)):
        return NmapScanService(session=session, executor=FakeExecutor())

    original = app.dependency_overrides.get(get_scan_service)
    app.dependency_overrides[get_scan_service] = fake_scan_service
    try:
        start_response = client.post(
            f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
            headers=headers,
            json={"scan_type": "tcp_scan", "arguments": ["-sV", "-O"]},
        )
        assert start_response.status_code == 201
        payload = start_response.json()
        assert payload["status"] == "completed"
        assert len(payload["hosts"]) == 1
        assert payload["hosts"][0]["address"] == "192.0.2.10"
        assert payload["hosts"][0]["ports"][0]["service"]["name"] == "http"

        list_response = client.get(
            f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
            headers=headers,
        )
        assert list_response.status_code == 200
        assert len(list_response.json()) == 1

        scan_id = payload["id"]
        detail_response = client.get(
            f"/api/v1/projects/{project_id}/targets/{target_id}/scans/{scan_id}",
            headers=headers,
        )
        assert detail_response.status_code == 200
        assert detail_response.json()["status"] == "completed"
    finally:
        if original is None:
            app.dependency_overrides.pop(get_scan_service, None)
        else:
            app.dependency_overrides[get_scan_service] = original
