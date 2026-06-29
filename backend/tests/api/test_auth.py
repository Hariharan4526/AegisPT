from __future__ import annotations


def test_register_login_refresh_and_me(client) -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "security@example.com",
            "password": "StrongPassword123!",
            "full_name": "Security Analyst",
            "role": "analyst",
        },
    )

    assert register_response.status_code == 201
    register_payload = register_response.json()
    assert register_payload["user"]["email"] == "security@example.com"
    assert register_payload["tokens"]["token_type"] == "bearer"

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "security@example.com",
            "password": "StrongPassword123!",
        },
    )

    assert login_response.status_code == 200
    login_payload = login_response.json()
    access_token = login_payload["tokens"]["access_token"]
    refresh_token = login_payload["tokens"]["refresh_token"]

    me_response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert me_response.status_code == 200
    assert me_response.json()["email"] == "security@example.com"

    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert refresh_response.status_code == 200
    refresh_payload = refresh_response.json()
    assert refresh_payload["user"]["email"] == "security@example.com"
    assert refresh_payload["tokens"]["access_token"] != access_token
