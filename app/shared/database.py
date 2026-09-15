"""Database configuration and session management."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.settings import settings


# ════════════════════════════════════════════
# Base declarativa (era app/db/base.py)
# ════════════════════════════════════════════
class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


# ════════════════════════════════════════════
# Engine e SessionMaker (era app/db/session.py)
# ════════════════════════════════════════════
engine = create_async_engine(
    str(settings.database_url),
    echo=False,
    future=True,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


# ════════════════════════════════════════════
# Dependency injection para FastAPI
# ════════════════════════════════════════════
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Provide a request-scoped async SQLAlchemy session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


# ════════════════════════════════════════════
# Inicialização do banco (dev only)
# ════════════════════════════════════════════
async def init_db(create_all: bool = True) -> None:
    """Initialize DB objects for development.

    In production, prefer Alembic migrations over `create_all`.
    """
    if not create_all:
        return

    from . import models_imports  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
