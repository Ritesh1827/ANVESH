"""Baseline schema: all ECDAT tables as of the Task 2 freeze.

Revision ID: 0001_baseline
Revises: None
Create Date: 2026-09-25

Captures the full stable schema in one revision:
  scans (incl. user_id, surface_counts, reachability from Tasks 1–2),
  assets, roadmaps, cboms, users, sessions, ownership_rules, alembic_version.

SQLite and PostgreSQL compatibility notes:
  - JSON columns use SQLAlchemy's generic JSON type (TEXT on SQLite,
    JSONB/JSON on Postgres) — portable across both backends.
  - booleans use Boolean (INTEGER on SQLite, BOOLEAN on Postgres).
  - datetimes use DateTime without timezone storage; values are UTC.
  - FK ondelete behaviour (CASCADE / SET NULL) is enforced by the
    database on Postgres; on SQLite it is Kendall' convention plus
    application-level deletes (SQLite needs PRAGMA foreign_keys=ON
    per connection to enforce — the app does not rely on it).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None

_EXISTING_TABLES = {
    "users", "sessions", "scans", "assets", "roadmaps", "cboms",
    "ownership_rules",
}


def _table_exists(name: str) -> bool:
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    try:
        return sa_inspect(bind).has_table(name)
    except Exception:
        return False


def _stamp_existing_as_baseline() -> bool:
    """Existing DBs (created by create_all + patches) already match HEAD.

    Alembic's version table is the only thing missing, so stamp it instead
    of re-creating tables. Returns True when the stamp path was taken.
    """
    bind = op.get_bind()
    try:
        from sqlalchemy import inspect as sa_inspect

        present = set(sa_inspect(bind).get_table_names())
    except Exception:
        return False
    if not _EXISTING_TABLES.issubset(present):
        return False
    # Do NOT write the version row here: Alembic inserts it automatically
    # after upgrade() returns. Just signal "tables already match HEAD".
    return True


def upgrade() -> None:
    if _stamp_existing_as_baseline():
        return
    for table in (
        "ownership_rules", "cboms", "roadmaps", "assets", "scans",
        "sessions", "users",
    ):
        if _table_exists(table):
            raise RuntimeError(
                f"Table '{table}' already exists but the schema is incomplete — "
                "restore from backup or drop it before running this baseline."
            )
    op.create_table(
        "users",
        sa.Column("id", sa.String(64), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "sessions",
        sa.Column("token", sa.String(128), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token"),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"], unique=False)

    op.create_table(
        "scans",
        sa.Column("id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("stage", sa.String(256), nullable=True),
        sa.Column("user_id", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=True),
        sa.Column("target_label", sa.Text(), nullable=False),
        sa.Column("include_certificates", sa.Boolean(), nullable=False),
        sa.Column("llm_enrichment_requested", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("cert_refs", sa.JSON(), nullable=False),
        sa.Column("binary_refs", sa.JSON(), nullable=False),
        sa.Column("container_refs", sa.JSON(), nullable=False),
        sa.Column("infra_endpoints", sa.JSON(), nullable=False),
        sa.Column("recorded_only_surfaces", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("asset_count", sa.Integer(), nullable=False),
        sa.Column("certificate_asset_count", sa.Integer(), nullable=False),
        sa.Column("surface_counts", sa.JSON(), nullable=False),
        sa.Column("priority_counts", sa.JSON(), nullable=False),
        sa.Column("hndl_count", sa.Integer(), nullable=False),
        sa.Column("completeness", sa.JSON(), nullable=True),
        sa.Column("scanned_surfaces", sa.JSON(), nullable=False),
        sa.Column("reachability", sa.JSON(), nullable=True),
        sa.Column("cbom_component_count", sa.Integer(), nullable=False),
        sa.Column("cbom_quality", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_status", "scans", ["status"], unique=False)
    op.create_index("ix_scans_user_id", "scans", ["user_id"], unique=False)

    op.create_table(
        "assets",
        sa.Column("asset_id", sa.String(64), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(128), nullable=False),
        sa.Column("purpose", sa.String(64), nullable=False),
        sa.Column("priority", sa.String(8), nullable=True),
        sa.Column("classification", sa.String(32), nullable=True),
        sa.Column("source_surface", sa.String(32), nullable=False),
        sa.Column("location", sa.Text(), nullable=False),
        sa.Column("asset_json", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id"),
    )
    op.create_index("ix_assets_algorithm", "assets", ["algorithm"], unique=False)
    op.create_index("ix_assets_purpose", "assets", ["purpose"], unique=False)
    op.create_index("ix_assets_priority", "assets", ["priority"], unique=False)
    op.create_index("ix_assets_classification", "assets", ["classification"], unique=False)
    op.create_index("ix_assets_scan_id", "assets", ["scan_id"], unique=False)
    op.create_index(
        "ix_assets_scan_surface", "assets", ["scan_id", "source_surface"], unique=False
    )
    op.create_index(
        "ix_assets_scan_priority", "assets", ["scan_id", "priority"], unique=False
    )
    op.create_index(
        "ix_assets_scan_algorithm", "assets", ["scan_id", "algorithm"], unique=False
    )

    op.create_table(
        "roadmaps",
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("asset_id", sa.String(64), nullable=False),
        sa.Column("roadmap_json", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id", "asset_id"),
    )

    op.create_table(
        "cboms",
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("format", sa.String(8), nullable=False),
        sa.Column("document", sa.Text(), nullable=False),
        sa.Column("component_count", sa.Integer(), nullable=False),
        sa.Column("quality_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id"),
    )

    op.create_table(
        "ownership_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("owner", sa.String(256), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("surface", sa.String(32), nullable=True),
        sa.Column("purpose", sa.String(64), nullable=True),
        sa.Column("algorithm_prefix", sa.String(128), nullable=True),
        sa.Column("path_contains", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("ownership_rules")
    op.drop_table("cboms")
    op.drop_table("roadmaps")
    op.drop_index("ix_assets_scan_algorithm", table_name="assets")
    op.drop_index("ix_assets_scan_priority", table_name="assets")
    op.drop_index("ix_assets_scan_surface", table_name="assets")
    op.drop_index("ix_assets_scan_id", table_name="assets")
    op.drop_index("ix_assets_classification", table_name="assets")
    op.drop_index("ix_assets_priority", table_name="assets")
    op.drop_index("ix_assets_purpose", table_name="assets")
    op.drop_index("ix_assets_algorithm", table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_scans_user_id", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
