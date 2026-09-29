"""
Evidence schema — PRD §5 stage 4 (Evidence Engine).

Every finding, whether deterministic or LLM-enriched, must carry:
  - location (file, line, column)
  - source surface (what was scanned)
  - detection method
  - a weighted composite confidence score

The Evidence model is the "how do you know?" record attached to every
CryptoAsset. It must be populated before a finding can enter the inventory.

Reference: PRD §5 stage 4, §6 (Explainability), §9 sample output.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field, field_validator, model_validator

from .enums import DetectionMethod, FindingType


class SourceLocation(BaseModel):
    """
    Precise location of the finding within its source artefact.

    All fields after `file_path` are optional because not every surface
    provides line-level granularity (e.g. a binary symbol has a name but
    no source line; a certificate has no line number at all).
    """

    file_path: str = Field(
        description="Relative or absolute path to the scanned artefact "
                    "(source file, binary, certificate file, or endpoint identifier)."
    )
    line_number: Optional[int] = Field(
        default=None,
        ge=1,
        description="1-based line number within the source file. "
                    "None for binary/certificate/infrastructure surfaces.",
    )
    column_number: Optional[int] = Field(
        default=None,
        ge=0,
        description="0-based column offset on the line. None when not applicable.",
    )
    end_line_number: Optional[int] = Field(
        default=None,
        ge=1,
        description="Last line of a multi-line construct, if known.",
    )
    snippet: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Short code/config/cert excerpt that triggered the finding. "
                    "Secrets MUST be scrubbed before this field is populated "
                    "(enforced by the secret scrubber stage, not here).",
    )

    @model_validator(mode="after")
    def end_line_must_be_gte_start(self) -> "SourceLocation":
        if (
            self.line_number is not None
            and self.end_line_number is not None
            and self.end_line_number < self.line_number
        ):
            raise ValueError(
                f"end_line_number ({self.end_line_number}) must be >= "
                f"line_number ({self.line_number})"
            )
        return self

    model_config = {"frozen": True}


class Evidence(BaseModel):
    """
    Evidence record attached to every crypto-asset finding.

    Implements PRD §5 stage 4 requirements:
    - location: captured via SourceLocation
    - source surface: `source_surface` field
    - detection method: DetectionMethod enum
    - weighted composite confidence: float in [0.0, 1.0]

    The `rule_id` field carries the specific rule identifier (e.g. "R-014"
    from the PRD §9 sample). This allows traceability back to the detection
    ruleset without embedding rule logic here.
    """

    # ── Core provenance ──────────────────────────────────────────────────────
    detection_method: DetectionMethod = Field(
        description="How this finding was detected. "
                    "LLM_ENRICHMENT may only be used for ambiguous findings that "
                    "could not be resolved deterministically (PRD §5 stage 3b)."
    )
    finding_type: FindingType = Field(
        default=FindingType.DETERMINISTIC,
        description="Whether this finding was resolved deterministically or via "
                    "LLM enrichment. Deterministic findings are always the primary "
                    "source of truth (PRD §6).",
    )
    rule_id: Optional[str] = Field(
        default=None,
        description="Identifier of the detection rule that triggered this finding, "
                    "e.g. 'R-014'. Matches PRD §9 sample: 'AST rule R-014'.",
    )

    # ── Location ─────────────────────────────────────────────────────────────
    location: SourceLocation = Field(
        description="Precise location of the finding within its source artefact."
    )

    # ── Source surface ────────────────────────────────────────────────────────
    source_surface: str = Field(
        description="The input surface this finding came from. "
                    "Expected values: 'source_code', 'binary', 'container', "
                    "'certificate', 'infrastructure'. "
                    "Open string (not enum) to allow extensibility as surfaces are added.",
    )

    # ── Confidence ────────────────────────────────────────────────────────────
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Weighted composite confidence score in the range [0.0, 1.0]. "
                    "1.0 = fully deterministic high-confidence match (e.g. direct API call). "
                    "Scores below 0.5 should be treated as candidates for LLM enrichment "
                    "or manual review. The PRD §9 sample shows 0.98 for an AST rule match.",
    )

    # ── Observed evidence detail (Phase 4: evidence quality) ──────────────────
    # What was actually seen: the exact API/symbol text, sibling context
    # used for disambiguation, and whether the algorithm/purpose assignment
    # is directly observed or an inference awaiting enrichment.
    observed_symbol: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Exact API/symbol text observed in source (e.g. 'EVP_aes_256_gcm'). "
                    "Distinct from algorithm: the symbol is evidence, the algorithm is the conclusion.",
    )
    sibling_symbols: list[str] = Field(
        default_factory=list,
        description="Nearby identifiers in the same statement used to disambiguate "
                    "generic wrappers (e.g. the fetched cipher beside EVP_EncryptInit_ex). "
                    "Context only — never standalone findings.",
    )
    ambiguity_status: str = Field(
        default="resolved",
        description="'resolved' = algorithm+purpose directly observed; "
                    "'algorithm_inferred' = algorithm from sibling context; "
                    "'needs_enrichment' = purpose unknown, routed to LLM enrichment. "
                    "Never silently present an inference as a fact.",
    )

    # ── LLM-specific provenance (populated only when finding_type = LLM_ENRICHED) ──
    llm_prompt_version: Optional[str] = Field(
        default=None,
        description="Version identifier of the LLM prompt used, e.g. 'v1'. "
                    "Required when finding_type=LLM_ENRICHED for cache-key reproducibility "
                    "(PRD §6: Reproducibility).",
    )
    llm_model: Optional[str] = Field(
        default=None,
        description="LLM model identifier used for enrichment, e.g. 'claude-3-5-sonnet-20241022'.",
    )

    # ── Additional context ────────────────────────────────────────────────────
    notes: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="Free-text analyst notes or enrichment context. "
                    "Must not contain secrets.",
    )

    @field_validator("llm_prompt_version", "llm_model", mode="after")
    @classmethod
    def llm_fields_only_for_llm_findings(cls, value: Optional[str]) -> Optional[str]:
        # Cross-field validation is handled in model_validator below;
        # individual field validators just pass through.
        return value

    @model_validator(mode="after")
    def llm_fields_require_llm_finding_type(self) -> "Evidence":
        if self.finding_type == FindingType.LLM_ENRICHED:
            if not self.llm_prompt_version:
                raise ValueError(
                    "llm_prompt_version is required when finding_type is LLM_ENRICHED "
                    "(PRD §6: Reproducibility — prompt version must be tied to cache keys)."
                )
        return self

    model_config = {"frozen": True}
