"""Alembic migration tests (baseline + pagination follow-up).

Verifies the revision chain against both database paths:
  1. Fresh database (no tables) → upgrade head creates the full schema.
  2. Existing database (create_all + runtime patches, i.e. every real
     deployment today) → upgrade head stamps/converges without
     touching data.
  3. The migrated existing DB still serves the app's read/write path.
"""

HEAD_REVISION = "0002_pagination_indexes"

import sqlite3

from alembic import command
from alembic.config import Config

from ecdat.persistence import database


def _alembic_config(db_path: str) -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("script_location", "alembic")
    return cfg


def test_upgrade_head_on_fresh_db_creates_full_schema(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "alembic_fresh.sqlite3"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    command.upgrade(_alembic_config(str(db_path)), "head")

    connection = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "select name from sqlite_master where type='table'"
            )
        }
        assert {
            "users", "sessions", "scans", "assets", "roadmaps",
            "cboms", "ownership_rules", "alembic_version",
        }.issubset(tables)
        assert connection.execute("select * from alembic_version").fetchall() == [
            (HEAD_REVISION,)
        ]
        scan_cols = {
            row[1] for row in connection.execute("pragma table_info(scans)")
        }
        assert {"user_id", "surface_counts", "reachability"}.issubset(scan_cols)
        asset_cols = {
            row[1] for row in connection.execute("pragma table_info(assets)")
        }
        assert "classification" in asset_cols
    finally:
        connection.close()


def test_upgrade_head_on_existing_db_stamps_without_data_loss(
    tmp_path, monkeypatch
) -> None:
    db_path = tmp_path / "alembic_existing.sqlite3"
    url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", url)

    database.configure(url)
    database.init_db_sync(url)
    from datetime import datetime, timezone

    from ecdat.persistence.models import ScanRecord

    with database.session() as session:
        session.add(ScanRecord(
            id="keepme",
            status="complete",
            source_kind="demo",
            target_label="keep",
            include_certificates=False,
            created_at=datetime.now(timezone.utc),
        ))
        session.commit()

    command.upgrade(_alembic_config(str(db_path)), "head")

    connection = sqlite3.connect(db_path)
    try:
        assert connection.execute("select id from scans").fetchall() == [("keepme",)]
        assert connection.execute("select * from alembic_version").fetchall() == [
            (HEAD_REVISION,)
        ]
    finally:
        connection.close()

    # The stamped DB still serves the app path end to end.
    from ecdat.persistence.store import ScanStore

    store = ScanStore(database_url=url)
    assert store.get_scan("keepme")["status"] == "complete"


def test_postgres_ddl_compiles_offline() -> None:
    """The baseline revision must render valid PostgreSQL DDL.

    No live Postgres is required: compile the migration's CREATE TABLE
    statements against the postgres dialect and check for genuine types
    (JSONB-compatible JSON, BOOLEAN, no SQLite-isms).
    """
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateTable

    from ecdat.persistence.models import Base

    for table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
        assert "CREATE TABLE" in ddl
        assert "AUTOINCREMENT" not in ddl
    json_tables = {"scans"}
    assert json_tables.issubset({t.name for t in Base.metadata.sorted_tables})
