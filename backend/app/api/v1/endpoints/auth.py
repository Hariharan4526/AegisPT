from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import SessionDep, SettingsDep, get_current_active_user
from app.schemas.auth import (
    AuthResponse,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
)
from app.schemas.user import UserRead
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_auth_service(session: SessionDep, settings: SettingsDep) -> AuthService:
    return AuthService(session=session, settings=settings)


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthResponse:
    result = auth_service.register_user(payload)
    return AuthResponse(user=result.user, tokens=result.tokens)


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthResponse:
    result = auth_service.login(
        payload,
        actor_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return AuthResponse(user=result.user, tokens=result.tokens)


@router.post("/refresh", response_model=AuthResponse)
def refresh(
    payload: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthResponse:
    result = auth_service.refresh(payload)
    return AuthResponse(user=result.user, tokens=result.tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    payload: LogoutRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    auth_service.logout(payload)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserRead)
def me(current_user=Depends(get_current_active_user)) -> UserRead:
    return UserRead.model_validate(current_user)
