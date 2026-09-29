"""
CBOM export schema — PRD §5 stage 12 (Outputs: CycloneDX CBOM export).

This module defines the data-contract layer for CycloneDX CBOM export.
It captures the structure of what ECDAT will pass to cyclonedx-python-lib
(Day 8) for final schema-valid CycloneDX rendering.

IMPORTANT:
  - This schema describes what ECDAT produces internally before passing
    to cyclonedx-python-lib.
  - The actual CycloneDX serialisation (JSON/XML with full schema validation)
    is performed by cyclonedx-python-lib in the CBOM export engine (Day 8).
  - This schema does NOT replace CycloneDX's own schema validation.

PRD requirements captured here:
  - Schema-validated CycloneDX CBOM export (PRD §5 stage 12)
  - Quality score for the exported inventory (PRD §5 stage 12)
  - Version-diff support (PRD §5 stage 12)
  - The CBOM itself is a sensitive artifact (PRD §6)

Reference: PRD §5 stage 12, §6, §8 (cyclonedx-python-lib).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, field_validator

from .enums import CBOMFormat
from .crypto_asset import CryptoAsset


class CBOMMetadata(BaseModel):
    """
    Metadata block for a CBOM export run.

    Carries provenance information about the scan and export that produced
    this CBOM, so that reviewers/auditors can answer: when was this scanned,
    what was scanned, and by which version of ECDAT?
    """

    ecdat_version: str = Field(
        description="Version of ECDAT that produced this CBOM.",
    )
    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the scan run that produced this CBOM. "
                    "Stable reference for version-diff comparison (PRD §5 stage 12).",
    )
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the scan was completed.",
    )
    scanned_targets: list[str] = Field(
        default_factory=list,
        description="List of scanned targets (repository paths, binary paths, "
                    "endpoint identifiers, certificate paths). "
                    "At least one target is expected.",
    )
    input_surfaces: list[str] = Field(
        default_factory=list,
        description="Input surfaces covered in this scan "
                    "(e.g. ['source_code', 'certificate']). "
                    "Supports Discovery Completeness reporting (PRD §5 stage 8).",
    )
    tool_name: str = Field(
        default="ECDAT",
        description="Tool name for the CycloneDX component/tool metadata block.",
    )
    tool_vendor: str = Field(
        default="ECDAT Project",
        description="Tool vendor for CycloneDX metadata.",
    )

    model_config = {"frozen": True}


class CBOMQualityScore(BaseModel):
    """
    Quality score for the exported CBOM (PRD §5 stage 12).

    Quantifies how complete and evidence-backed the exported inventory is.
    These scores are computed by the CBOM export engine (Day 8) — the schema
    just carries the result.
    """

    completeness_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Fraction of discovered assets that have complete evidence records "
                    "(0.0 = no evidence, 1.0 = all assets fully evidenced).",
    )
    evidence_coverage: float = Field(
        ge=0.0,
        le=1.0,
        description="Fraction of assets for which at least one evidence record exists.",
    )
    risk_coverage: float = Field(
        ge=0.0,
        le=1.0,
        description="Fraction of assets that have been processed by the Mosca Risk Engine.",
    )
    recommendation_coverage: float = Field(
        ge=0.0,
        le=1.0,
        description="Fraction of assets that have a PQC recommendation.",
    )
    duplicate_rate: float = Field(
        ge=0.0,
        le=1.0,
        description="Fraction of raw findings that were deduplicated. "
                    "High duplicate rate may indicate overly broad detection rules.",
    )
    overall_quality: float = Field(
        ge=0.0,
        le=1.0,
        description="Composite quality score (0.0–1.0). "
                    "Computed by the CBOM export engine from the above metrics.",
    )

    model_config = {"frozen": True}


class CBOMVersionDiff(BaseModel):
    """
    Version-diff record for comparing two CBOM exports (PRD §5 stage 12).

    Supports detecting newly introduced vulnerable crypto over time.
    Note: Continuous monitoring is future scope (PRD §12); this model
    supports point-in-time diff comparisons between two scans.
    """

    baseline_scan_id: str = Field(
        description="scan_id of the earlier (baseline) CBOM export.",
    )
    current_scan_id: str = Field(
        description="scan_id of the current (new) CBOM export.",
    )
    new_assets: list[str] = Field(
        default_factory=list,
        description="asset_ids present in the current scan but not in baseline. "
                    "Newly introduced cryptographic assets.",
    )
    removed_assets: list[str] = Field(
        default_factory=list,
        description="asset_ids present in baseline but not in current scan. "
                    "Cryptographic assets that have been removed.",
    )
    changed_assets: list[str] = Field(
        default_factory=list,
        description="asset_ids present in both scans but with changed attributes "
                    "(e.g. algorithm, risk level, recommendation).",
    )
    diff_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the diff was computed.",
    )

    model_config = {"frozen": True}


class CBOMExport(BaseModel):
    """
    Top-level CBOM export record.

    This is the internal representation that the CBOM export engine (Day 8)
    will serialise via cyclonedx-python-lib into a schema-valid CycloneDX document.

    PRD §5 stage 12: "a schema-validated CycloneDX CBOM export (with quality
    score and version-diff support)".
    """

    # ── Identifiers ───────────────────────────────────────────────────────────
    export_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this export run.",
    )
    export_format: CBOMFormat = Field(
        default=CBOMFormat.JSON,
        description="Output format: JSON or XML.",
    )

    # ── Metadata ──────────────────────────────────────────────────────────────
    metadata: CBOMMetadata = Field(
        description="Provenance metadata for this CBOM export.",
    )

    # ── Inventory ─────────────────────────────────────────────────────────────
    assets: list[CryptoAsset] = Field(
        default_factory=list,
        description="The deduplicated, evidence-backed crypto asset inventory "
                    "being exported. These are the records from stage 5 of the pipeline, "
                    "enriched by all subsequent stages that have run.",
    )

    # ── Quality ───────────────────────────────────────────────────────────────
    quality_score: Optional[CBOMQualityScore] = Field(
        default=None,
        description="Quality score for this export. "
                    "Computed by the CBOM export engine before serialisation.",
    )

    # ── Version diff ─────────────────────────────────────────────────────────
    version_diff: Optional[CBOMVersionDiff] = Field(
        default=None,
        description="Version-diff record if this export is being compared against "
                    "a baseline. None for first-time scans.",
    )

    # ── Discovery completeness (PRD §5 stage 8) ───────────────────────────────
    discovery_completeness_pct: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Discovery completeness percentage: found asset categories "
                    "vs. expected categories, across all source types (PRD §5 stage 8). "
                    "Computed by the Discovery Completeness stage.",
    )

    # ── Audit ─────────────────────────────────────────────────────────────────
    exported_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when this export record was created.",
    )

    @field_validator("assets")
    @classmethod
    def assets_must_have_evidence(cls, assets: list[CryptoAsset]) -> list[CryptoAsset]:
        """
        Every asset in a CBOM export must have an evidence record.
        PRD §6: 'Every finding must be traceable to its evidence.'
        """
        missing = [a.asset_id for a in assets if a.evidence is None]
        if missing:
            raise ValueError(
                f"All assets in a CBOM export must have evidence records. "
                f"Missing evidence on asset_ids: {missing}"
            )
        return assets

    model_config = {"frozen": False}
