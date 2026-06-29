from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.base import Base


def _engine_kwargs(database_url: str) -> dict:
    if database_url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True}


@lru_cache(maxsize=4)
def get_engine(database_url: str | None = None) -> Engine:
    settings = get_settings()
    url = database_url or settings.database_url
    return create_engine(url, future=True, echo=settings.debug, **_engine_kwargs(url))


@lru_cache(maxsize=4)
def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:
    engine = get_engine(database_url)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


def get_db_session() -> Generator[Session, None, None]:
    session_factory = get_session_factory()
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def initialize_database(database_url: str | None = None) -> None:
    import app.models.audit_log  # noqa: F401
    import app.models.project  # noqa: F401
    import app.models.scan  # noqa: F401
    import app.models.target  # noqa: F401
    import app.models.token  # noqa: F401
    import app.models.user  # noqa: F401

    engine = get_engine(database_url)
    Base.metadata.create_all(bind=engine)
