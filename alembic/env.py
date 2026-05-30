import asyncio
import os
import logging

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

from backend.models import Base

load_dotenv()

target_metadata = Base.metadata


def get_url() -> str:
    """
    Retrieves the async database URL from environment.
    Raises EnvironmentError if DATABASE_URL is not set.
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        raise EnvironmentError("DATABASE_URL environment variable is not set.")
    return url


def do_run_migrations(connection) -> None:
    """Runs Alembic migrations synchronously within an async connection context."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """
    Creates an async engine from DATABASE_URL and runs migrations
    using SQLAlchemy's run_sync bridge for Alembic compatibility.
    """
    logger = logging.getLogger("alembic.env")
    url = get_url()
    logger.info("Running migrations against: %s", url.split("@")[-1])

    connectable = create_async_engine(url, echo=False)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_offline() -> None:
    """
    Run migrations in offline mode (generates SQL script only,
    does not connect to database). Uses sync URL by replacing asyncpg driver.
    """
    url = get_url().replace("postgresql+asyncpg://", "postgresql://")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
