"""
Risk schema — PRD §5 stage 9 (Mosca Risk Engine).

This model is the data contract for Mosca risk output. It captures:
  - Mosca X, Y, Z values (data shelf life, migration time, threat timeline)
  - The urgency flag: True when X + Y > Z
  - HNDL (Harvest-Now-Decrypt-Later) exposure flag
  - Priority level (P1–P4)

IMPORTANT — schema vs. engine separation:
  This model ONLY validates and carries the risk output.
  The X + Y > Z calculation, HNDL determination, and priority assignment
  all belong to the Mosca Risk Engine (engines/mosca.py, Day 4).
  No risk logic lives here.

Reference: PRD §5 stage 9, §9 sample output.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field, model_validator

from .enums import RiskPriority


class MoscaParameters(BaseModel):
    """
    Mosca's theorem inputs for a single crypto asset.

    Mosca's theorem (PRD §5 stage 9):
      X = estimated years the protected data must remain secret
      Y = estimated years required to complete migration for this asset
      Z = estimated years until a cryptographically relevant quantum computer exists

    Urgency is flagged when X + Y > Z.
    These values are organisation/asset-specific and set by the Mosca engine;
    the schema just carries them.
    """

    mosca_x_years: float = Field(
        ge=0.0,
        description="X: Number of years the data protected by this asset must "
                    "remain confidential. PRD §9 sample: 15.",
    )
    mosca_y_years: float = Field(
        ge=0.0,
        description="Y: Number of years estimated to complete migration away "
                    "from this cryptographic asset. PRD §9 sample: 2.",
    )
    mosca_z_years: float = Field(
        ge=0.0,
        description="Z: Number of years until a cryptographically relevant "
                    "quantum computer is estimated to exist. PRD §9 sample: 12.",
    )

    model_config = {"frozen": True}


class Risk(BaseModel):
    """
    Risk record produced by the Mosca Risk Engine for a single crypto asset.

    Fields match the PRD §9 sample JSON exactly:
      {
        "mosca_x_years": 15,
        "mosca_y_years": 2,
        "mosca_z_years": 12,
        "urgency_flag": true,
        "hndl_flag": true,
        "priority": "P1"
      }

    The `urgency_flag` must be consistent with the Mosca parameters when all
    three are present (validated below). If only a subset of Mosca parameters
    is available (e.g. infrastructure asset with unknown data shelf life),
    mosca_parameters may be None and urgency_flag is set by the engine directly.
    """

    # ── Mosca parameters (may be None for assets where inputs are unknown) ───
    mosca_x_years: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="X: Years the protected data must remain confidential. "
                    "None if not determinable for this asset.",
    )
    mosca_y_years: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Y: Years estimated to complete migration. "
                    "None if not determinable.",
    )
    mosca_z_years: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Z: Years until a cryptographically relevant quantum computer. "
                    "None if not determinable.",
    )

    # ── Risk flags ────────────────────────────────────────────────────────────
    urgency_flag: bool = Field(
        description="True when X + Y > Z (Mosca's theorem) — migration is urgent. "
                    "Set by the Mosca Risk Engine; validated for consistency here.",
    )
    hndl_flag: bool = Field(
        description="True when there is evidence or strong likelihood that an attacker "
                    "could already be harvesting ciphertext for later decryption "
                    "(Harvest-Now-Decrypt-Later). Increases effective urgency even "
                    "when Mosca parameters alone do not trigger urgency_flag.",
    )

    # ── Priority ──────────────────────────────────────────────────────────────
    priority: RiskPriority = Field(
        description="Risk priority level assigned by the Mosca engine. "
                    "P1 = critical (immediate), P2 = high, P3 = medium, P4 = low.",
    )

    # ── Weighting context (set by engine, carried here for traceability) ─────
    reachability_weight: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Reachability factor applied by the engine when weighting this "
                    "asset's risk. 1.0 = fully reachable (highest weight). "
                    "None if reachability analysis has not yet run.",
    )
    classification_weight: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Classification weight applied by the engine (e.g. infrastructure "
                    "assets protecting critical data may receive higher weight). "
                    "None if not yet computed.",
    )

    # ── Validation: urgency_flag must be consistent with Mosca values ─────────
    @model_validator(mode="after")
    def urgency_flag_consistent_with_mosca(self) -> "Risk":
        """
        When all three Mosca parameters are present, the urgency_flag must
        match X + Y > Z. This catches engine bugs where the flag is set
        incorrectly relative to the stored parameters.

        If any parameter is None, the engine set urgency_flag based on
        available information — we trust it without cross-checking.
        """
        x = self.mosca_x_years
        y = self.mosca_y_years
        z = self.mosca_z_years

        if x is not None and y is not None and z is not None:
            expected = (x + y) > z
            if self.urgency_flag != expected:
                raise ValueError(
                    f"urgency_flag ({self.urgency_flag}) is inconsistent with "
                    f"Mosca parameters: X={x} + Y={y} = {x + y} "
                    f"{'>' if expected else '<='} Z={z}. "
                    f"Expected urgency_flag={expected}."
                )
        return self

    model_config = {"frozen": True}
