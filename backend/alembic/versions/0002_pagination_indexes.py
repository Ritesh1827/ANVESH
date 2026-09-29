"""Pagination follow-up: index + column catch-up for live databases.

Revision ID: 0002_pagination_indexes
Revises: 0001_baseline
Create Date: 2026-09-26

The paginated read path needs, on databases created before it:
  - assets.classification column (server-side classification filter)
  - single-column indexes on purpose / priority / classification
  - composite (scan_id, priority) and (scan_id, algorithm) indexes
All idempotent: each step checks for existence first, so fresh DBs
(which already have everything via the updated baseline) and partially
patched DBs converge to the same schema.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_pagination_indexes"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    bind = op.get_bind()
    try:
        from sqlalchemy import inspect as sa_inspect

        return {c["name"] for c in sa_inspect(bind).get_columns(table)}
    except Exception:
        return set()


def _indexes(table: str) -> set[str]:
    bind = op.get_bind()
    try:
        from sqlalchemy import inspect as sa_inspect

        return {i["name"] for i in sa_inspect(bind).get_indexes(table)}
    except Exception:
        return set()


def upgrade() -> None:
    if "classification" not in _columns("assets"):
        op.add_column(
            "assets", sa.Column("classification", sa.String(32), nullable=True))
    wanted = {
        "ix_assets_purpose": (["purpose"], False),
        "ix_assets_priority": (["priority"], False),
        "ix_assets_classification": (["classification"], False),
        "ix_assets_scan_priority": (["scan_id", "priority"], False),
        "ix_assets_scan_algorithm": (["scan_id", "algorithm"], False),
    }
    existing = _indexes("assets")
    for name, (cols, unique) in wanted.items():
        if name not in existing:
            op.create_index(name, "assets", cols, unique=unique)


def downgrade() -> None:
    for name in (
        "ix_assets_scan_algorithm",
        "ix_assets_scan_priority",
        "ix_assets_classification",
        "ix_assets_priority",
        "ix_assets_purpose",
    ):
        try:
            op.drop_index(name, table_name="assets")
        except Exception:
            pass
