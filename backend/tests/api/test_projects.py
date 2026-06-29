from __future__ import annotations

from uuid import uuid4


def _register_and_login(client):
    email = f"project-{uuid4().hex[:8]}@example.com"
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Project Owner",
            "role": "analyst",
        },
    )
    assert register_response.status_code == 201
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongPassword123!"},
    )
    assert login_response.status_code == 200
    return login_response.json()["tokens"]["access_token"]


def test_project_and_target_lifecycle(client) -> None:
    access_token = _register_and_login(client)
    headers = {"Authorization": f"Bearer {access_token}"}

    create_project_response = client.post(
        "/api/v1/projects",
        headers=headers,
        json={"name": "Red Team Lab", "description": "Authorized lab scope"},
    )
    assert create_project_response.status_code == 201
    project_id = create_project_response.json()["id"]

    update_project_response = client.put(
        f"/api/v1/projects/{project_id}",
        headers=headers,
        json={"description": "Updated description"},
    )
    assert update_project_response.status_code == 200
    assert update_project_response.json()["description"] == "Updated description"

    create_target_response = client.post(
        f"/api/v1/projects/{project_id}/targets",
        headers=headers,
        json={"target_type": "domain", "value": "example.test", "description": "Primary domain"},
    )
    assert create_target_response.status_code == 201
    target_id = create_target_response.json()["id"]

    list_targets_response = client.get(f"/api/v1/projects/{project_id}/targets", headers=headers)
    assert list_targets_response.status_code == 200
    assert len(list_targets_response.json()) == 1

    update_target_response = client.put(
        f"/api/v1/projects/{project_id}/targets/{target_id}",
        headers=headers,
        json={"is_enabled": False},
    )
    assert update_target_response.status_code == 200
    assert update_target_response.json()["is_enabled"] is False

    delete_target_response = client.delete(
        f"/api/v1/projects/{project_id}/targets/{target_id}",
        headers=headers,
    )
    assert delete_target_response.status_code == 204

    delete_project_response = client.delete(f"/api/v1/projects/{project_id}", headers=headers)
    assert delete_project_response.status_code == 204


def test_viewer_cannot_create_project(client) -> None:
    email = f"viewer-{uuid4().hex[:8]}@example.com"
    client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Viewer User",
            "role": "viewer",
        },
    )
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongPassword123!"},
    )
    access_token = login_response.json()["tokens"]["access_token"]
    response = client.post(
        "/api/v1/projects",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"name": "Denied Project"},
    )
    assert response.status_code == 403
