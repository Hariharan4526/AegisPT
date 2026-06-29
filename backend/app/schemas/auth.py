from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.user import UserCreate


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=32)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=32)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class AuthResponse(BaseModel):
    user: "UserRead"
    tokens: TokenPair


class RegisterRequest(UserCreate):
    pass


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=12, max_length=128)


from app.schemas.user import UserRead  # noqa: E402
