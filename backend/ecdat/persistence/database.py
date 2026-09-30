"""ECDAT scan-job persistence — database engine setup.

SQLite (via aiosqlite) is the default so scans persist with zero external
services; a DATABASE_URL pointing at PostgreSQL+asyncpg keeps working
because the models avoid backend-specific column types.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlparse, urlunparse

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from ecdat.persistence.models import Base

# Columns added after the first release. SQLite has no full ALTER TABLE
# support in our path, so new NOT NULL columns always carry a default and
# are added idempotently here (create_all only creates missing *tables*,
# never missing *columns* on existing tables).
_SCHEMA_PATCHES: tuple[tuple[str, str], ...] = (
    ("scans", "user_id VARCHAR(64)"),
    ("scans", "surface_counts JSON DEFAULT '{}'"),
    ("scans", "reachability JSON"),
    ("scans", "llm_enrichment_requested BOOLEAN DEFAULT FALSE"),
    ("assets", "classification VARCHAR(32)"),
)

_INDEX_PATCHES: tuple[tuple[str, str, str], ...] = (
    ("assets", "ix_assets_purpose", "purpose"),
    ("assets", "ix_assets_priority", "priority"),
    ("assets", "ix_assets_classification", "classification"),
    ("assets", "ix_assets_scan_priority", "scan_id, priority"),
    ("assets", "ix_assets_scan_algorithm", "scan_id, algorithm"),
)

_CONFIGURED_URL: Optional[str] = None
_ENGINE = None
_SESSION_FACTORY = None
_LOCK = threading.Lock()

_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_SQLITE = f"sqlite:///{(_WORKSPACE_ROOT / 'backend' / 'ecdat.sqlite3')}"


def _sync_url(url: Optional[str]) -> str:
    if not url:
        return _DEFAULT_SQLITE
    parsed = urlparse(url)
    if parsed.scheme == "sqlite+aiosqlite":
        return urlunparse(parsed._replace(scheme="sqlite"))
    if parsed.scheme in ("postgresql", "postgres", "postgresql+psycopg", "postgresql+psycopg2", "postgresql+asyncpg"):
        return urlunparse(parsed._replace(scheme="postgresql+asyncpg"))
    return url


def configure(database_url: Optional[str] = None) -> None:
    """Pin the database URL for this process (idempotent per URL)."""
    global _CONFIGURED_URL, _ENGINE, _SESSION_FACTORY
    url = database_url or _DEFAULT_SQLITE
    with _LOCK:
        if url == _CONFIGURED_URL and _ENGINE is not None:
            return
        _CONFIGURED_URL = url
        sync_url = _sync_url(url)
        connect_args, engine_kwargs = _connection_options(sync_url)
        _ENGINE = create_engine(
            sync_url, connect_args=connect_args, future=True, **engine_kwargs)
        _SESSION_FACTORY = sessionmaker(bind=_ENGINE, class_=Session, expire_on_commit=False)


def _connection_options(sync_url: str) -> tuple[dict, dict]:
    """Backend-specific connection options.

    SQLite: single-threaded server access — disable the same-thread check.
    PostgreSQL (asyncpg): ssl context for encrypted connections (Supabase pooler).
    """
    if sync_url.startswith("sqlite"):
        return {"check_same_thread": False}, {}
    if "asyncpg" in sync_url:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return {"ssl": ctx}, {"pool_pre_ping": True}
    if sync_url.startswith("postgresql") or sync_url.startswith("postgres"):
        return {"sslmode": "require"}, {"pool_pre_ping": True}
    return {}, {}


def init_db_sync(database_url: Optional[str] = None) -> None:
    """Create all tables if they do not exist yet, then patch new columns."""
    configure(database_url or _CONFIGURED_URL)
    assert _ENGINE is not None
    Base.metadata.create_all(_ENGINE)
    _apply_schema_patches()


def _apply_schema_patches() -> None:
    """ADD COLUMN / CREATE INDEX for fields introduced after existing DBs."""
    assert _ENGINE is not None
    with _ENGINE.begin() as connection:
        for table, column_ddl in _SCHEMA_PATCHES:
            try:
                existing = {col["name"] for col in inspect(connection).get_columns(table)}
            except Exception:
                continue
            col_name = column_ddl.split()[0]
            if col_name in existing:
                continue
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column_ddl}"))
        try:
            existing_indexes = {
                idx["name"] for idx in inspect(connection).get_indexes("assets")
            }
        except Exception:
            existing_indexes = set()
        for table, name, cols in _INDEX_PATCHES:
            if name in existing_indexes:
                continue
            try:
                connection.execute(text(f"CREATE INDEX {name} ON {table} ({cols})"))
            except Exception:
                continue


@contextmanager
def session() -> Iterator[Session]:
    """Yield a transactional session bound to the configured database."""
    configure(_CONFIGURED_URL)
    assert _SESSION_FACTORY is not None
    db_session = _SESSION_FACTORY()
    try:
        yield db_session
    finally:
        db_session.close()
