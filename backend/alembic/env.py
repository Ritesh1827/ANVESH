"""Alembic environment: runs migrations against the configured database.

The URL resolves exactly like the runtime (DATABASE_URL env, else the
local SQLite file), so `alembic upgrade head` targets the same database
the API uses. Model metadata is imported for autogenerate support, but
the baseline migration in versions/ is hand-reviewed, not auto-blurted.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ecdat.persistence.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        if url.startswith("sqlite+aiosqlite://"):
            url = "sqlite://" + url[len("sqlite+aiosqlite://"):]
        elif url.startswith("postgresql+asyncpg://"):
            try:
                import psycopg2  # noqa: F401
                url = "postgresql+psycopg2://" + url[len("postgresql+asyncpg://"):]
            except ImportError:
                url = "postgresql://" + url[len("postgresql+asyncpg://"):]
        return url
    root = Path(__file__).resolve().parent.parent
    return f"sqlite:///{(root / 'ecdat.sqlite3')}"


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = _database_url()
    connect_args: dict = {}
    if url.startswith("postgresql"):
        # Same TLS requirement as the runtime engine (Supabase pooler).
        connect_args = {"sslmode": "require"}
    engine = create_engine(url, connect_args=connect_args)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
