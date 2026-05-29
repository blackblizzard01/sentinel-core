"""Async SQLAlchemy engine and session management for Sentinel AI."""

import logging
import os
from typing import AsyncGenerator

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.models import Base

load_dotenv()

logger = logging.getLogger(__name__)

DATABASE_URL: str = os.getenv("DATABASE_URL")
if DATABASE_URL is None:
    raise RuntimeError("DATABASE_URL is not set in environment variables")

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an AsyncSession and guarantees cleanup."""
    session: AsyncSession = AsyncSessionLocal()
    try:
        yield session
    except Exception:
        logger.exception("Database session error in get_db")
        raise
    finally:
        await session.close()


async def init_db() -> None:
    """Create all tables if they do not exist. Called once on app startup."""
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized")
    except Exception:
        logger.exception("Failed to initialize database tables")
        raise
