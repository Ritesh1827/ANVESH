"""ECDAT scan-job persistence — database engine setup.

SQLite (via aiosqlite) is the default so scans persist with zero external
services; a DATABASE_URL pointing at PostgreSQL+asyncpg keeps working
because the models avoid backend-specific column types.

Production safety: when ECDAT_ENV=production, a missing or unreachable
PostgreSQL URL is a startup failure — the backend must NOT silently fall
back to a local SQLite file that vanishes on the next Render restart.
The SQLite fallback exists for local development only.
"""

from __future__ import annotations

import logging
import os
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

logger = logging.getLogger(__name__)

_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_SQLITE = f"sqlite:///{(_WORKSPACE_ROOT / 'backend' / 'ecdat.sqlite3')}"


def is_production() -> bool:
    """True when the backend runs in deployed mode (Render sets ECDAT_ENV=production)."""
    return os.environ.get("ECDAT_ENV", "").strip().lower() == "production"


def _live_sqlite_fallback(raw: Optional[str]) -> bool:
    """Whether the live engine is SQLite while the URL asked for Postgres.

    True only when the configured URL is non-SQLite (i.e. Postgres was
    requested) AND the running engine is SQLite. Derived from the running
    engine first, so a stale global can never misreport.
    """
    try:
        asked_sqlite = not raw or _sync_url(raw).startswith("sqlite")
    except Exception:
        asked_sqlite = False
    if asked_sqlite:
        return False
    try:
        if _ENGINE is not None:
            return _ENGINE.url.get_backend_name() == "sqlite"
    except Exception:
        pass
    return False


def database_fingerprint(url: Optional[str] = None) -> dict:
    """Safe, credential-free description of the configured database.

    Returns dialect, masked host, database name, and whether the SQLite
    fallback was used. Never includes passwords or full URLs. The
    sqlite_fallback flag reflects the live engine, not a stale global.
    """
    raw = url if url is not None else _CONFIGURED_URL
    fallback = _live_sqlite_fallback(raw)
    if not raw:
        return {"present": False, "dialect": None, "host": None,
                "name": None, "sqlite_fallback": fallback}
    try:
        parsed = urlparse(_sync_url(raw))
    except Exception:
        return {"present": True, "dialect": "unknown", "host": None,
                "name": None, "sqlite_fallback": fallback}
    scheme = (parsed.scheme or "").lower()
    if scheme.startswith("sqlite"):
        name = (parsed.path or "").rsplit("/", 1)[-1] or None
        return {"present": True, "dialect": "sqlite", "host": None,
                "name": name, "sqlite_fallback": fallback}
    if "postgres" in scheme:
        dbname = (parsed.path or "").lstrip("/") or None
        return {"present": True, "dialect": "postgresql",
                "host": parsed.hostname,
                "name": dbname, "sqlite_fallback": fallback}
    return {"present": True, "dialect": scheme or "unknown", "host": parsed.hostname,
            "name": (parsed.path or '').lstrip("/") or None,
            "sqlite_fallback": fallback}


def _log_db_config(stage: str, url: str, ok: bool, detail: str = "") -> None:
    """Log database config with credentials masked (host + db name only)."""
    fp = database_fingerprint(url)
    message = (
        f"[DB] {stage} present={fp['present']} "
        f"dialect={fp['dialect']} host={fp['host']} name={fp['name']} "
        f"sqlite_fallback={fp['sqlite_fallback']} ok={ok}"
        + (f" {detail}" if detail else "")
    )
    if ok:
        logger.info(message)
    else:
        logger.warning(message)
    print(message, flush=True)


def _sync_url(url: Optional[str]) -> str:
    if not url:
        return _DEFAULT_SQLITE
    if url == _DEFAULT_SQLITE:
        return url
    parsed = urlparse(url)
    if parsed.scheme in ("sqlite", "sqlite+aiosqlite"):
        return urlunparse(parsed._replace(scheme="sqlite"))
    if parsed.scheme in ("postgresql", "postgres", "postgresql+psycopg", "postgresql+psycopg2", "postgresql+asyncpg", "postgresql+pg8000"):
        return urlunparse(parsed._replace(scheme="postgresql"))
    return url


def configure(database_url: Optional[str] = None) -> None:
    """Pin the database URL for this process (idempotent per URL).

    Fallback policy: DATABASE_URL missing/unreachable falls back to local
    SQLite in development only. In production (ECDAT_ENV=production) the
    backend fails fast instead of silently writing to an ephemeral SQLite
    file that disappears on the next Render restart.
    """
    global _CONFIGURED_URL, _ENGINE, _SESSION_FACTORY
    url = database_url or _DEFAULT_SQLITE
    explicit_sqlite = url == _DEFAULT_SQLITE or _sync_url(url).startswith("sqlite")
    with _LOCK:
        if url == _CONFIGURED_URL and _ENGINE is not None:
            return
        _CONFIGURED_URL = url
        try:
            sync_url = _sync_url(url)
            connect_args, engine_kwargs = _connection_options(sync_url)
            engine = create_engine(
                sync_url, connect_args=connect_args, future=True, **engine_kwargs)
            with engine.connect() as conn:
                pass
            _ENGINE = engine
            _log_db_config("database configured:", url, True)
        except Exception as exc:
            if is_production() and not explicit_sqlite:
                _CONFIGURED_URL = None
                _log_db_config("database configured:", url, False,
                               f"error={type(exc).__name__}")
                raise RuntimeError(
                    "Could not connect to PostgreSQL in production "
                    f"(host={database_fingerprint(url).get('host')}); refusing "
                    "to fall back to ephemeral SQLite."
                ) from exc
            _log_db_config("database fallback to sqlite:", url, False,
                           f"error={type(exc).__name__}")
            sync_url = _DEFAULT_SQLITE
            connect_args, engine_kwargs = _connection_options(sync_url)
            fallback_engine = create_engine(
                sync_url, connect_args=connect_args, future=True, **engine_kwargs)
            with fallback_engine.connect() as conn:
                pass
            _ENGINE = fallback_engine
        _SESSION_FACTORY = sessionmaker(bind=_ENGINE, class_=Session, expire_on_commit=False)


def _connection_options(sync_url: str) -> tuple[dict, dict]:
    """Backend-specific connection options.

    SQLite: single-threaded server access — disable the same-thread check.
    PostgreSQL: sslmode=require for encrypted connections (Supabase pooler).
    """
    if sync_url.startswith("sqlite"):
        return {"check_same_thread": False}, {}
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


def database_identity() -> dict:
    """Safe runtime database identity: dialect, db name, schema, fallback flag.

    Never includes credentials. SELECT current_database()/current_schema()
    are metadata reads, not user data.
    """
    configure(_CONFIGURED_URL)
    assert _ENGINE is not None
    fp = database_fingerprint()
    identity = {
        "dialect": fp["dialect"],
        "host": fp["host"],
        "name": fp["name"],
        "sqlite_fallback": fp["sqlite_fallback"],
        "current_database": None,
        "current_schema": None,
    }
    try:
        with _ENGINE.connect() as connection:
            try:
                identity["current_database"] = connection.execute(
                    text("SELECT current_database()")).scalar()
            except Exception:
                pass
            try:
                identity["current_schema"] = connection.execute(
                    text("SELECT current_schema()")).scalar()
            except Exception:
                if fp["dialect"] == "sqlite":
                    identity["current_schema"] = "main"
    except Exception as exc:
        identity["error"] = type(exc).__name__
    return identity
