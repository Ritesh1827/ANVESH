"""
CryptoAsset schema — the master inventory record (PRD §5 stage 5).

This is the central data model of the entire ECDAT system. Every pipeline
stage either produces, enriches, or reads CryptoAsset records. The schema
preserves all contextual information mandated by the PRD:

  "A cryptographic asset should not merely be represented as 'RSA-2048 detected.'
   ECDAT associates the cryptographic primitive with its purpose, code location,
   dependency, protocol, protected data, reachability, business criticality,
   lifetime, and migration constraints."
                                              — PRD §13 (Positioning Statement)

Field names, nesting, and terminology match PRD §9 sample JSON exactly.
No business logic (Mosca calculations, PQC mapping, reachability scoring)
belongs here — those live in their respective engine modules.

Reference: PRD §5 stages 4–11, §6, §9 sample output, §13.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, field_validator

from .enums import (
    AssetClassification,
    BusinessCriticality,
    CryptoPurpose,
    LifecycleStage,
    SensitivityLevel,
)
from .evidence import Evidence
from .risk import Risk
from .recommendation import Recommendation


class CryptoAsset(BaseModel):
    """
    Master record for a single cryptographic asset in the ECDAT inventory.

    One CryptoAsset represents one unique cryptographic primitive after
    deduplication and correlation by the Crypto Asset Inventory stage
    (PRD §5 stage 5).

    PRD §9 sample maps to fields as follows:
      "asset"               → algorithm
      "purpose"             → purpose
      "location"            → evidence.location.file_path + line_number
      "library"             → library
      "protocol"            → protocol
      "classification"      → classification
      "sensitivity"         → sensitivity
      "business_criticality"→ business_criticality
      "owner"               → owner
      "reachable"           → reachable
      "evidence"            → evidence (Evidence model)
      "risk"                → risk (Risk model)
      "recommendation"      → recommendation (Recommendation model)
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    asset_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this asset record. "
                    "Generated on creation; stable across updates to the same asset.",
    )
    scan_id: Optional[str] = Field(
        default=None,
        description="Identifier of the scan run that produced this record. "
                    "Allows correlating assets across multiple scan runs.",
    )

    # ── Algorithm ─────────────────────────────────────────────────────────────
    algorithm: str = Field(
        description="Cryptographic algorithm name including key size where applicable. "
                    "PRD §9 sample: 'RSA-2048'. "
                    "Must be a recognisable algorithm identifier, not a library name.",
    )
    key_size_bits: Optional[int] = Field(
        default=None,
        ge=0,
        description="Key size in bits extracted from the finding. "
                    "None when not determinable (e.g. a hash function).",
    )
    variant: Optional[str] = Field(
        default=None,
        description="Algorithm variant or mode, e.g. 'CBC', 'GCM', 'PKCS1v15'. "
                    "None when no variant is specified.",
    )

    # ── Purpose ───────────────────────────────────────────────────────────────
    purpose: CryptoPurpose = Field(
        description="Cryptographic purpose of this asset. "
                    "Critical for correct PQC mapping (PRD §5 stage 10): "
                    "key_establishment → ML-KEM; digital_signature → ML-DSA/SLH-DSA. "
                    "PRD §9 sample: 'key_establishment'.",
    )

    # ── Location & context (flattened from PRD §9 'location' string) ─────────
    location: str = Field(
        description="Human-readable location string for display and reporting. "
                    "PRD §9 sample: 'auth_service.py:143'. "
                    "Structured location is in evidence.location.",
    )
    library: Optional[str] = Field(
        default=None,
        description="Library or dependency through which this algorithm is used. "
                    "PRD §9 sample: 'OpenSSL 1.1.1'.",
    )
    protocol: Optional[str] = Field(
        default=None,
        description="Protocol in which this asset operates, if determinable. "
                    "PRD §9 sample: 'TLS 1.2'.",
    )

    # ── Classification & business context (PRD §5 stage 6) ───────────────────
    classification: AssetClassification = Field(
        description="TEC 910018:2025 classification: 'application' or 'infrastructure'. "
                    "PRD §9 sample: 'application'.",
    )
    sensitivity: SensitivityLevel = Field(
        description="Sensitivity level of the data protected by this asset. "
                    "PRD §9 sample: 'high'.",
    )
    business_criticality: BusinessCriticality = Field(
        description="Business impact if this asset were compromised. "
                    "PRD §9 sample: 'critical'.",
    )
    owner: Optional[str] = Field(
        default=None,
        description="Team, service, or individual responsible for this asset. "
                    "PRD §9 sample: 'Citizen Services Team'.",
    )
    lifecycle_stage: LifecycleStage = Field(
        default=LifecycleStage.ACTIVE,
        description="Current lifecycle stage of this cryptographic asset.",
    )

    # ── Reachability (PRD §5 stage 7) ─────────────────────────────────────────
    reachable: Optional[bool] = Field(
        default=None,
        description="Whether this asset is reachable from an entry point in the "
                    "call graph. None = reachability analysis not yet run. "
                    "PRD §9 sample: true.",
    )
    reachability_path: Optional[list[str]] = Field(
        default=None,
        description="Ordered list of functions/components from entry point to this "
                    "asset (PRD §5 stage 7 call-graph trace). "
                    "Populated by the Reachability engine (Day 5). "
                    "None if unreachable or analysis not run.",
    )
    exposure_context: Optional[str] = Field(
        default=None,
        description="Human-readable description of the exposure context, e.g. "
                    "'Called from public HTTP endpoint /api/auth/login → "
                    "generate_session_key() → RSA encrypt'. "
                    "Populated by Reachability engine.",
    )

    # ── Certificate-specific fields (PRD §5 stage 1, Day 6) ──────────────────
    certificate_subject: Optional[str] = Field(
        default=None,
        description="X.509 certificate subject DN. Populated for certificate surface only.",
    )
    certificate_issuer: Optional[str] = Field(
        default=None,
        description="X.509 certificate issuer DN. Populated for certificate surface only.",
    )
    certificate_expiry: Optional[datetime] = Field(
        default=None,
        description="Certificate expiry datetime (UTC). Populated for certificate surface only.",
    )
    certificate_serial: Optional[str] = Field(
        default=None,
        description="Certificate serial number (hex string). Populated for certificate surface only.",
    )

    # ── Source surface ────────────────────────────────────────────────────────
    source_surface: str = Field(
        description="Input surface this asset was discovered on. "
                    "Expected values: 'source_code', 'binary', 'container', "
                    "'certificate', 'infrastructure'. "
                    "Open string for extensibility.",
    )

    # ── Evidence (PRD §5 stage 4) ─────────────────────────────────────────────
    evidence: Evidence = Field(
        description="Evidence record linking this asset to its detection. "
                    "Required — every asset in the inventory must have evidence. "
                    "PRD §6: 'Every finding must be traceable to its evidence'.",
    )

    # ── Risk (PRD §5 stage 9) — None until Mosca engine runs ─────────────────
    risk: Optional[Risk] = Field(
        default=None,
        description="Risk record produced by the Mosca Risk Engine. "
                    "None until the Mosca engine has processed this asset (Day 4).",
    )

    # ── Recommendation (PRD §5 stage 10) — None until engine runs ────────────
    recommendation: Optional[Recommendation] = Field(
        default=None,
        description="PQC recommendation produced by the Recommendation Engine. "
                    "None until the engine has processed this asset (Day 4). "
                    "Read-only advisory output — ECDAT never auto-applies changes.",
    )

    # ── Audit / metadata ──────────────────────────────────────────────────────
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when this asset was first discovered.",
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of last update to this record.",
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Free-text analyst notes. Must not contain secrets.",
    )

    # ── Validation ────────────────────────────────────────────────────────────
    @field_validator("algorithm")
    @classmethod
    def algorithm_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("algorithm must not be an empty string.")
        return v

    @field_validator("location")
    @classmethod
    def location_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("location must not be an empty string.")
        return v

    @field_validator("source_surface")
    @classmethod
    def source_surface_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("source_surface must not be an empty string.")
        return v

    model_config = {
        "frozen": False,  # Assets are enriched progressively through the pipeline
        "json_schema_extra": {
            "example": {
                # Matches PRD §9 sample output exactly
                "algorithm": "RSA-2048",
                "purpose": "key_establishment",
                "location": "auth_service.py:143",
                "library": "OpenSSL 1.1.1",
                "protocol": "TLS 1.2",
                "classification": "application",
                "sensitivity": "high",
                "business_criticality": "critical",
                "owner": "Citizen Services Team",
                "reachable": True,
                "source_surface": "source_code",
                "evidence": {
                    "detection_method": "ast_rule",
                    "finding_type": "deterministic",
                    "rule_id": "R-014",
                    "location": {
                        "file_path": "auth_service.py",
                        "line_number": 143,
                    },
                    "source_surface": "source_code",
                    "confidence": 0.98,
                },
                "risk": {
                    "mosca_x_years": 15,
                    "mosca_y_years": 2,
                    "mosca_z_years": 12,
                    "urgency_flag": True,
                    "hndl_flag": True,
                    "priority": "P1",
                },
                "recommendation": {
                    "standardized_replacement": "ML-KEM (FIPS 203)",
                    "migration_path": "hybrid: X25519 + ML-KEM",
                    "status": "standardized",
                },
            }
        },
    }
