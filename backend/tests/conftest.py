from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEST_DB_PATH = Path(tempfile.gettempdir()) / "pentestlab_ai_test.db"
os.environ.setdefault("DATABASE_URL", f"sqlite+pysqlite:///{TEST_DB_PATH}")
os.environ.setdefault("SECRET_KEY", "test-secret-key-with-sufficient-length")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DEBUG", "false")

from app.core.config import get_settings
from app.db.session import get_engine, get_session_factory, initialize_database
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def test_database() -> None:
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    TEST_DB_PATH.unlink(missing_ok=True)
    get_settings.cache_clear()
    initialize_database()
    yield


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)
