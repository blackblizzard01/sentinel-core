"""Alembic environment configuration with async SQLAlchemy migration support."""

import asyncio
import os
import logging
from logging.config import fileConfig

from dotenv import load_dotenv
from sqlalchemy.engine import Connection
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context
from backend.models import Base

load_dotenv()

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger(__name__)

target_metadata = Base.metadata

DATABASE_URL_ENV_KEY: str = "DATABASE_URL"
database_url: str | None = os.getenv(DATABASE_URL_ENV_KEY)
if database_url is None:
    raise RuntimeError("DATABASE_URL is not set in environment variables")

config.set_main_option("sqlalchemy.url", database_url)


def run_migrations_offline() -> None:
    """Run Alembic migrations in offline mode using emitted SQL scripts."""
    url: str = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run Alembic migrations in online mode using an async engine connection."""
    connectable = create_async_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
    )

    try:
        async with connectable.connect() as connection:
            await connection.run_sync(_run_sync_migrations)
    except Exception:
        logger.exception("Alembic online migration failed")
        raise
    finally:
        await connectable.dispose()


def _run_sync_migrations(connection: Connection) -> None:
    """Run migrations in a synchronous context bound to a connection."""
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
