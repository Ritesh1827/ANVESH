"""
Recommendation schema — PRD §5 stage 10 (PQC Recommendation Engine).

This model is the data contract for PQC recommendation output. It captures:
  - The NIST-standardized replacement algorithm
  - The migration path type (hybrid, pure-PQC, etc.)
  - Standardization status (finalized vs. under standardization)
  - Affected components and validation steps

IMPORTANT — schema vs. engine separation:
  This model ONLY validates and carries recommendation output.
  The algorithm + purpose → PQC mapping logic belongs ENTIRELY to the
  Recommendation Engine (engines/recommendation.py) and its editable
  JSON/YAML configuration (PRD §8: "keeps algorithm-to-PQC mappings as
  editable data, not hardcoded logic").

  Do NOT add any mapping logic here such as:
    RSA → ML-KEM
    ECDSA → ML-DSA
  Those rules belong in config/pqc_mappings.yaml (Day 4).

Reference: PRD §5 stage 10, §8 (Recommendation/lookup logic), §9 sample output.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field

from .enums import StandardizationStatus, MigrationPathType


class Recommendation(BaseModel):
    """
    PQC recommendation record produced by the Recommendation Engine.

    Fields match the PRD §9 sample JSON exactly:
      {
        "standardized_replacement": "ML-KEM (FIPS 203)",
        "migration_path": "hybrid: X25519 + ML-KEM",
        "status": "standardized"
      }

    The `status` field uses the StandardizationStatus enum to enforce
    PRD §5 stage 10's explicit requirement: keep standardized algorithms
    (FIPS 203/204/205) separate from those still under standardization
    (e.g. HQC, Falcon), and never recommend the latter as primary.
    """

    # ── Primary replacement ───────────────────────────────────────────────────
    standardized_replacement: str = Field(
        description="The recommended NIST-standard PQC algorithm, including the "
                    "FIPS reference where applicable. "
                    "Examples: 'ML-KEM (FIPS 203)', 'ML-DSA (FIPS 204)', "
                    "'SLH-DSA (FIPS 205)'. "
                    "PRD §9 sample: 'ML-KEM (FIPS 203)'.",
    )

    # ── Migration path ────────────────────────────────────────────────────────
    migration_path: str = Field(
        description="Human-readable migration path description. "
                    "PRD §5 stage 10: hybrid (classical + PQC) is the default "
                    "during migration; pure-PQC only for greenfield systems. "
                    "PRD §9 sample: 'hybrid: X25519 + ML-KEM'.",
    )
    migration_path_type: MigrationPathType = Field(
        default=MigrationPathType.HYBRID,
        description="Structured classification of the migration strategy. "
                    "Hybrid is the default during migration per PRD §5 stage 10.",
    )

    # ── Standardization status ────────────────────────────────────────────────
    status: StandardizationStatus = Field(
        description="Standardization status of the recommended replacement. "
                    "Must be 'standardized' for primary recommendations. "
                    "PRD §9 sample: 'standardized'. "
                    "Algorithms still under standardization (e.g. HQC) must never "
                    "appear here as a primary recommendation (PRD §5 stage 10).",
    )

    # ── Secondary / alternative recommendation ───────────────────────────────
    alternative_replacement: Optional[str] = Field(
        default=None,
        description="Alternative PQC algorithm if the primary is not suitable "
                    "for this specific context. Must also carry a standardization "
                    "status check via the engine before being populated.",
    )

    # ── Affected components (populated by Migration Impact Analysis, Day 8) ──
    affected_protocols: Optional[list[str]] = Field(
        default=None,
        description="Protocols that will be affected by this migration "
                    "(e.g. ['TLS 1.3', 'QUIC']). Populated by Migration Impact Analysis.",
    )
    affected_libraries: Optional[list[str]] = Field(
        default=None,
        description="Libraries/dependencies that need updating "
                    "(e.g. ['OpenSSL >= 3.3', 'BouncyCastle >= 1.78']). "
                    "Populated by Migration Impact Analysis.",
    )

    # ── Migration roadmap fields (populated by Migration Impact Analysis, Day 8) ─
    priority_order: Optional[int] = Field(
        default=None,
        ge=1,
        description="Relative migration priority order across all assets "
                    "(1 = migrate first). Assigned by Migration Impact Analysis.",
    )
    validation_steps: Optional[list[str]] = Field(
        default=None,
        description="Ordered list of validation steps required after migration "
                    "(e.g. ['Run interoperability test suite', 'Verify TLS handshake']). "
                    "Part of the roadmap-style output (PRD §5 stage 11).",
    )

    # ── Advisory note ─────────────────────────────────────────────────────────
    advisory_note: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="Free-text advisory context for this recommendation. "
                    "This field is read-only advisory output — ECDAT never "
                    "automatically applies changes (PRD §4 Non-Goals).",
    )

    model_config = {"frozen": True}
