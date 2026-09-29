"""ECDAT scan-job persistence — SQLAlchemy models.

Each pipeline run is stored as a scan job with its full result set:
  ScanRecord    — one row per scan (status, inputs, summary)
  AssetRecord   — one row per scored CryptoAsset (indexed columns + full JSON)
  RoadmapRecord — one row per migration roadmap (full JSON)
  CBOMRecord    — the serialised CycloneDX document per scan

PRD §5 stage 12 / §6: scan history persists per-scan in a real database
keyed by scan ID — never recomputed or held only in memory.
"""

from __future__ import annotations

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    """Declarative base for all ECDAT persistence models."""


class ScanRecord(Base):
    """One row per scan job: lifecycle status, inputs, and result summary."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    stage: Mapped[str | None] = mapped_column(String(256), nullable=True)

    user_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_label: Mapped[str] = mapped_column(Text, nullable=False)
    include_certificates: Mapped[bool] = mapped_column(nullable=False, default=True)
    llm_enrichment_requested: Mapped[bool] = mapped_column(
        nullable=False, default=False)

    cert_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    binary_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    container_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    infra_endpoints: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    recorded_only_surfaces: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    certificate_asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    surface_counts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    priority_counts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    hndl_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completeness: Mapped[dict | None] = mapped_column(
        SQLiteJSON().with_variant(JSON(), "postgresql"), nullable=True
    )
    scanned_surfaces: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reachability: Mapped[dict | None] = mapped_column(
        SQLiteJSON().with_variant(JSON(), "postgresql"), nullable=True
    )

    cbom_component_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cbom_quality: Mapped[dict | None] = mapped_column(
        SQLiteJSON().with_variant(JSON(), "postgresql"), nullable=True
    )

    created_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    started_at: Mapped[object | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[object | None] = mapped_column(DateTime, nullable=True)


class AssetRecord(Base):
    """One row per scored asset: searchable columns plus the full JSON."""

    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    algorithm: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    priority: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    classification: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    source_surface: Mapped[str] = mapped_column(String(32), nullable=False)
    location: Mapped[str] = mapped_column(Text, nullable=False)
    asset_json: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("ix_assets_scan_surface", "scan_id", "source_surface"),
        Index("ix_assets_scan_priority", "scan_id", "priority"),
        Index("ix_assets_scan_algorithm", "scan_id", "algorithm"),
    )


class RoadmapRecord(Base):
    """One row per migration roadmap, keyed by scan + asset."""

    __tablename__ = "roadmaps"

    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    asset_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    roadmap_json: Mapped[str] = mapped_column(Text, nullable=False)


class CBOMRecord(Base):
    """The serialised CycloneDX document for a scan."""

    __tablename__ = "cboms"

    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    document: Mapped[str] = mapped_column(Text, nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    quality_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserRecord(Base):
    """A real ECDAT account: email plus a bcrypt password hash."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[object] = mapped_column(DateTime, nullable=False)


class SessionRecord(Base):
    """A bearer session token bound to a user, with an expiry."""

    __tablename__ = "sessions"

    token: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[object] = mapped_column(DateTime, nullable=False)


class OwnershipRuleRecord(Base):
    """One user-configurable ownership mapping rule (first match wins)."""

    __tablename__ = "ownership_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner: Mapped[str] = mapped_column(String(256), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    surface: Mapped[str | None] = mapped_column(String(32), nullable=True)
    purpose: Mapped[str | None] = mapped_column(String(64), nullable=True)
    algorithm_prefix: Mapped[str | None] = mapped_column(String(128), nullable=True)
    path_contains: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[object | None] = mapped_column(DateTime, nullable=True)
