from __future__ import annotations

from datetime import timedelta

from app.core.security import create_access_token, decode_token, hash_password, verify_password


def test_password_hash_round_trip() -> None:
    password = "StrongPassword123!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_access_token_round_trip() -> None:
    token = create_access_token(
        subject="123",
        secret_key="unit-test-secret-key-with-length",
        algorithm="HS256",
        expires_delta=timedelta(minutes=15),
        claims={"role": "analyst"},
    )

    payload = decode_token(
        token,
        secret_key="unit-test-secret-key-with-length",
        algorithm="HS256",
    )

    assert payload["sub"] == "123"
    assert payload["type"] == "access"
    assert payload["role"] == "analyst"
