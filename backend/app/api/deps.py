from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.models.user import User, UserRole
from app.repositories.user_repository import UserRepository

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_settings_dependency() -> Settings:
    return get_settings()


def get_db() -> Generator[Session, None, None]:
    yield from get_db_session()


SettingsDep = Annotated[Settings, Depends(get_settings_dependency)]
SessionDep = Annotated[Session, Depends(get_db)]
TokenDep = Annotated[str, Security(oauth2_scheme)]


def get_current_user(
    token: TokenDep,
    session: SessionDep,
    settings: SettingsDep,
) -> User:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        if payload.get("type") != "access":
            raise ValueError("Invalid token type")
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Missing subject")
        user_uuid = UUID(user_id)
    except (JWTError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
        ) from exc

    user = UserRepository(session).get_by_id(user_uuid)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled.",
        )
    return user


def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    return current_user


def require_roles(*roles: UserRole) -> Callable[[User], User]:
    def _dependency(current_user: Annotated[User, Depends(get_current_active_user)]) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )
        return current_user

    return _dependency
