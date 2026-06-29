from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from logging import Logger
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import get_logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.models.token import AuditAction
from app.models.user import User
from app.repositories.user_repository import (
    AuditLogRepository,
    RefreshTokenRepository,
    UserRepository,
)
from app.schemas.auth import AuthResponse, LogoutRequest, RefreshRequest, TokenPair
from app.schemas.user import UserCreate, UserLogin, UserRead


@dataclass(slots=True)
class AuthResult:
    user: UserRead
    tokens: TokenPair


class AuthService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        self.logger: Logger = get_logger("pentestlab.auth")
        self.users = UserRepository(session)
        self.tokens = RefreshTokenRepository(session)
        self.audit_logs = AuditLogRepository(session)

    def register_user(self, payload: UserCreate) -> AuthResult:
        existing_user = self.users.get_by_email(payload.email)
        if existing_user is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this email already exists.",
            )

        now = datetime.now(timezone.utc)
        user = self.users.create(
            email=payload.email,
            password_hash=hash_password(payload.password),
            full_name=payload.full_name,
            role=payload.role,
        )
        token_pair = self._issue_tokens(user=user, issued_at=now)
        self.audit_logs.create(
            user_id=user.id,
            action=AuditAction.AUTH_REGISTER,
            details={"email": user.email, "role": user.role.value},
            occurred_at=now,
        )
        self.session.commit()
        self.session.refresh(user)
        return AuthResult(user=UserRead.model_validate(user), tokens=token_pair)

    def login(
        self,
        payload: UserLogin,
        *,
        actor_ip: str | None = None,
        user_agent: str | None = None,
    ) -> AuthResult:
        user = self.users.get_by_email(payload.email)
        if user is None or not verify_password(payload.password, user.password_hash):
            self.audit_logs.create(
                user_id=user.id if user else None,
                action=AuditAction.AUTH_FAILED_LOGIN,
                details={"email": payload.email},
                occurred_at=datetime.now(timezone.utc),
                actor_ip=actor_ip,
                user_agent=user_agent,
            )
            self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The account is disabled.",
            )

        now = datetime.now(timezone.utc)
        token_pair = self._issue_tokens(user=user, issued_at=now)
        self.audit_logs.create(
            user_id=user.id,
            action=AuditAction.AUTH_LOGIN,
            details={"email": user.email},
            occurred_at=now,
            actor_ip=actor_ip,
            user_agent=user_agent,
        )
        self.session.commit()
        self.session.refresh(user)
        return AuthResult(user=UserRead.model_validate(user), tokens=token_pair)

    def refresh(self, payload: RefreshRequest) -> AuthResult:
        token_payload = decode_token(
            payload.refresh_token,
            self.settings.secret_key,
            self.settings.jwt_algorithm,
        )
        if token_payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type.")

        token_hash = hash_token(payload.refresh_token)
        stored_token = self.tokens.get_active_by_hash(token_hash)
        if stored_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token is invalid or revoked.",
            )

        user = self.users.get_by_id(stored_token.user_id)
        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not available.")

        now = datetime.now(timezone.utc)
        self.tokens.revoke(stored_token, revoked_at=now)
        token_pair = self._issue_tokens(user=user, issued_at=now)
        self.audit_logs.create(
            user_id=user.id,
            action=AuditAction.AUTH_REFRESH,
            details={"jti": token_payload.get("jti")},
            occurred_at=now,
        )
        self.session.commit()
        self.session.refresh(user)
        return AuthResult(user=UserRead.model_validate(user), tokens=token_pair)

    def logout(self, payload: LogoutRequest) -> None:
        token_hash = hash_token(payload.refresh_token)
        token = self.tokens.get_active_by_hash(token_hash)
        if token is None:
            return

        now = datetime.now(timezone.utc)
        self.tokens.revoke(token, revoked_at=now)
        self.audit_logs.create(
            user_id=token.user_id,
            action=AuditAction.AUTH_LOGOUT,
            details={"jti": token.jti},
            occurred_at=now,
        )
        self.session.commit()

    def _issue_tokens(self, user: User, issued_at: datetime) -> TokenPair:
        access_expiry = timedelta(minutes=self.settings.access_token_expire_minutes)
        refresh_expiry = timedelta(days=self.settings.refresh_token_expire_days)
        access_jti = str(uuid4())
        refresh_jti = str(uuid4())
        access_token = create_access_token(
            subject=str(user.id),
            secret_key=self.settings.secret_key,
            algorithm=self.settings.jwt_algorithm,
            expires_delta=access_expiry,
            claims={"email": user.email, "role": user.role.value, "jti": access_jti},
        )
        refresh_token = create_refresh_token(
            subject=str(user.id),
            secret_key=self.settings.secret_key,
            algorithm=self.settings.jwt_algorithm,
            expires_delta=refresh_expiry,
            jti=refresh_jti,
            claims={"email": user.email, "role": user.role.value},
        )
        self.tokens.create(
            user_id=user.id,
            jti=refresh_jti,
            token_hash=hash_token(refresh_token),
            expires_at=issued_at + refresh_expiry,
        )
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(access_expiry.total_seconds()),
        )
