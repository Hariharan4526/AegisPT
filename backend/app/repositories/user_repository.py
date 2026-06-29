from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.token import RefreshToken
from app.models.user import User, UserRole


class UserRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_id(self, user_id: UUID) -> User | None:
        return self.session.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        statement: Select[tuple[User]] = select(User).where(User.email == email.lower())
        return self.session.scalars(statement).first()

    def create(
        self,
        *,
        email: str,
        password_hash: str,
        full_name: str | None,
        role: UserRole,
    ) -> User:
        user = User(
            email=email.lower(),
            password_hash=password_hash,
            full_name=full_name,
            role=role,
        )
        self.session.add(user)
        self.session.flush()
        return user

    def update_last_login(self, user: User) -> None:
        user.updated_at = datetime.now(timezone.utc)
        self.session.add(user)


class RefreshTokenRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        *,
        user_id: UUID,
        jti: str,
        token_hash: str,
        expires_at: datetime,
    ) -> RefreshToken:
        token = RefreshToken(
            user_id=user_id,
            jti=jti,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        self.session.add(token)
        self.session.flush()
        return token

    def get_active_by_hash(self, token_hash: str) -> RefreshToken | None:
        statement = select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
        return self.session.scalars(statement).first()

    def revoke(self, token: RefreshToken, revoked_at: datetime) -> None:
        token.revoked_at = revoked_at
        self.session.add(token)


class AuditLogRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        *,
        user_id: UUID | None,
        action: str,
        details: dict | None,
        occurred_at: datetime,
        actor_ip: str | None = None,
        user_agent: str | None = None,
    ) -> AuditLog:
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            occurred_at=occurred_at,
            actor_ip=actor_ip,
            user_agent=user_agent,
        )
        self.session.add(audit_log)
        self.session.flush()
        return audit_log
