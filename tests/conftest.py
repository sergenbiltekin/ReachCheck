"""Shared test fixtures.

Point the whole app at a throwaway SQLite file *before* importing anything from
``app`` so the global engine (used by the API/TestClient tests) never touches the
project's real database.
"""

from __future__ import annotations

import os
import pathlib
import tempfile

_TEST_DB = pathlib.Path(tempfile.gettempdir()) / "reachcheck_test.db"
if _TEST_DB.exists():
    _TEST_DB.unlink()
os.environ["REACHCHECK_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DB.as_posix()}"

import asyncio

import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.models  # noqa: F401 - register tables on Base.metadata
from app.db.base import Base


@pytest_asyncio.fixture
async def session_factory(tmp_path):
    """A fresh file-backed SQLite database per test, with tables created."""
    db_path = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def listener():
    """Start a loopback TCP listener; yields its port. Used as a reachable host."""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()
