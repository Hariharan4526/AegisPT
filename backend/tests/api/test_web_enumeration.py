from __future__ import annotations

from uuid import uuid4

from fastapi import Depends

from app.api.deps import get_db_session
from app.api.v1.endpoints.web_enumeration import get_web_enumeration_service
from app.models.web_enum import WebEnumerationTool
from app.services.web_enum_service import WebEnumerationService


class FakeFfufExecutor:
    def run(self, target_url: str, arguments: list[str]) -> str:
        return """
{
  "results": [
    {
      "input": {"FUZZ": "admin"},
      "url": "http://example.test/admin",
      "status": 200,
      "length": 1234,
      "words": 100,
      "lines": 20
    }
  ]
}
""".strip()


class FakeWhatWebExecutor:
    def run(self, target_url: str, arguments: list[str]) -> str:
        return """
[
  {
    "target": "http://example.test",
    "plugins": {
      "Apache": {"string": "Apache/2.4.58"},
      "PHP": {"string": "PHP/8.2.0"}
    }
  }
]
""".strip()


def _register_project_and_target(client, target_value: str = "example.test"):
    email = f"web-{uuid4().hex[:8]}@example.com"
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Web Enum Owner",
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
        json={"name": "Web Project"},
    )
    assert project_response.status_code == 201
    project_id = project_response.json()["id"]
    target_response = client.post(
        f"/api/v1/projects/{project_id}/targets",
        headers=headers,
        json={"target_type": "domain", "value": target_value},
    )
    assert target_response.status_code == 201
    return headers, project_id, target_response.json()["id"]


def test_ffuf_and_whatweb_enumeration(client) -> None:
    headers, project_id, target_id = _register_project_and_target(client)
    app = client.app

    original = app.dependency_overrides.get(get_web_enumeration_service)

    def fake_service_factory(session=Depends(get_db_session)):
        return WebEnumerationService(session=session, executor=FakeFfufExecutor())

    app.dependency_overrides[get_web_enumeration_service] = fake_service_factory
    try:
        ffuf_response = client.post(
            f"/api/v1/projects/{project_id}/targets/{target_id}/web-enumeration",
            headers=headers,
            json={"tool": WebEnumerationTool.ffuf.value, "arguments": ["-w", "wordlist.txt"]},
        )
        assert ffuf_response.status_code == 201
        ffuf_payload = ffuf_response.json()
        assert ffuf_payload["status"] == "completed"
        assert ffuf_payload["findings"][0]["finding_type"] == "directory"
        assert ffuf_payload["findings"][0]["name"] == "admin"

        def fake_whatweb_service_factory(session=Depends(get_db_session)):
            return WebEnumerationService(session=session, executor=FakeWhatWebExecutor())

        app.dependency_overrides[get_web_enumeration_service] = fake_whatweb_service_factory

        whatweb_response = client.post(
            f"/api/v1/projects/{project_id}/targets/{target_id}/web-enumeration",
            headers=headers,
            json={"tool": WebEnumerationTool.whatweb.value, "arguments": []},
        )
        assert whatweb_response.status_code == 201
        whatweb_payload = whatweb_response.json()
        assert whatweb_payload["status"] == "completed"
        assert any(finding["name"] == "Apache" for finding in whatweb_payload["findings"])

        list_response = client.get(
            f"/api/v1/projects/{project_id}/targets/{target_id}/web-enumeration",
            headers=headers,
        )
        assert list_response.status_code == 200
        assert len(list_response.json()) >= 2
    finally:
        if original is None:
            app.dependency_overrides.pop(get_web_enumeration_service, None)
        else:
            app.dependency_overrides[get_web_enumeration_service] = original
