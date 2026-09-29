"""
Evidence Engine — PRD §5 stage 4.

Converts raw AST matches (from the source scanner) into fully-formed
Evidence + CryptoAsset records. Every finding that enters the inventory
must pass through here.

Responsibilities:
  1. Build a SourceLocation from the AST match coordinates.
  2. Compute a weighted composite confidence score.
  3. Determine the algorithm canonical name (normalised with key size).
  4. Construct an Evidence object and a partial CryptoAsset object.

"Partial" means:
  - risk and recommendation are None (filled by Mosca + Recommendation engines)
  - classification, sensitivity, business_criticality hold STAGING DEFAULTS
    that will be overwritten by the ClassificationEngine (PRD §5 stage 6)
    before any downstream engine sees the values.

WHY STAGING DEFAULTS AND NOT THE OLD HEURISTICS:
  The three former heuristic functions (_infer_classification,
  _infer_sensitivity, _infer_criticality) have been removed and replaced
  by the dedicated ClassificationEngine (stage 6), which uses
  config/classification_rules.yaml for all decisions.
  The Evidence Engine runs at stage 4 (before inventory deduplication).
  The ClassificationEngine runs at stage 6 (after inventory, before
  reachability). The staging defaults below are intentionally conservative
  so that no downstream engine uses stale data if the ClassificationEngine
  is somehow skipped.

Staging defaults:
  classification:       APPLICATION  (the safer / less impactful assumption)
  sensitivity:          INTERNAL     (a neutral mid-tier default)
  business_criticality: LOW          (avoids inflating risk before classification)
  lifecycle_stage:      ACTIVE       (valid until ClassificationEngine runs)

These staging values are NOT read-only constants — the ClassificationEngine
produces the definitive values via model_copy(update={...}).

PRD §6 (Explainability): every asset must carry evidence that answers
"how do you know?" — location, detection method, confidence, rule_id.

PRD §5 stage 3a: deterministic findings pass through without LLM.
LLM enrichment path (stage 3b) is reserved for ambiguous findings,
handled separately (Day 7). Only DETERMINISTIC findings are produced here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    LifecycleStage,
    SensitivityLevel,
    SourceLocation,
)
from ecdat.discovery.ast_matchers import RawMatch
from ecdat.discovery.source_scanner import FileScanResult

logger = logging.getLogger(__name__)

# ── Staging defaults (overwritten by ClassificationEngine at stage 6) ─────────
_STAGING_CLASSIFICATION = AssetClassification.APPLICATION
_STAGING_SENSITIVITY = SensitivityLevel.INTERNAL
_STAGING_CRITICALITY = BusinessCriticality.LOW


# ── Algorithm name normalisation ──────────────────────────────────────────────

def _normalise_algorithm(base_algorithm: str, key_size_bits: Optional[int],
                          curve: Optional[str]) -> str:
    """
    Produce the canonical algorithm name including key size where available.

    Examples:
      "RSA" + 2048          → "RSA-2048"
      "RSA" + 4096          → "RSA-4096"
      "RSA" + None          → "RSA"
      "AES" + 128           → "AES-128"
      "ECDSA" + curve P-256 → "ECDSA-P256"
      "MD5" + None          → "MD5"
    """
    name = base_algorithm

    # EC curve takes precedence over key size for ECDSA/EC
    if curve:
        curve_short = (
            curve.replace("SECP256R1", "P256")
                 .replace("SECP384R1", "P384")
                 .replace("SECP521R1", "P521")
                 .replace("SECP256K1", "K256")
        )
        return f"{name}-{curve_short}"

    if key_size_bits is not None:
        return f"{name}-{key_size_bits}"

    return name


def _purpose_from_string(purpose_str: str) -> CryptoPurpose:
    """
    Convert the purpose string from a detection rule to a CryptoPurpose enum.
    Falls back to UNKNOWN if the value is not a valid enum member.
    """
    try:
        return CryptoPurpose(purpose_str)
    except ValueError:
        logger.warning(
            "Rule purpose '%s' is not a valid CryptoPurpose value — "
            "using UNKNOWN. Update detection_rules.yaml to fix this.",
            purpose_str,
        )
        return CryptoPurpose.UNKNOWN


# ── Confidence scoring ────────────────────────────────────────────────────────

def _compute_confidence(base_confidence: float, raw_match: RawMatch) -> float:
    """
    Compute the weighted composite confidence score for this finding.

    For deterministic AST findings in the prototype, the score is the rule's
    base confidence, optionally adjusted for:
      - Whether the key size was successfully extracted (+0.01 bonus)
      - Whether the file had parse errors (−0.05 penalty — partial AST)

    The score is clamped to [0.0, 1.0].
    """
    score = base_confidence

    if raw_match.extracted_key_size is not None:
        score = min(1.0, score + 0.01)

    return round(max(0.0, min(1.0, score)), 4)


# ── Core conversion ───────────────────────────────────────────────────────────

@dataclass
class EvidenceResult:
    """
    Fully-formed evidence + partial CryptoAsset produced by the Evidence Engine.

    "Partial" means classification fields hold staging defaults that are
    overwritten by ClassificationEngine (stage 6), and risk/recommendation
    are None until Mosca + Recommendation engines run.
    """
    evidence: Evidence
    asset: CryptoAsset


def raw_match_to_asset(
    raw_match: RawMatch,
    file_path: Path,
    scan_id: Optional[str] = None,
    relative_to: Optional[Path] = None,
    has_parse_error: bool = False,
) -> EvidenceResult:
    """
    Convert a single RawMatch into an Evidence + CryptoAsset record.

    This is the core Evidence Engine function (PRD §5 stage 4).
    All findings produced here are DETERMINISTIC (FindingType.DETERMINISTIC).
    LLM enrichment is applied separately for ambiguous findings (Day 7).

    Classification fields (classification, sensitivity, business_criticality,
    lifecycle_stage) are set to staging defaults here. The ClassificationEngine
    (stage 6) will overwrite these before any risk scoring occurs.

    Args:
        raw_match:       The RawMatch from the AST scanner.
        file_path:       Absolute path to the scanned file.
        scan_id:         Optional scan run identifier.
        relative_to:     Base path for producing relative display paths.
        has_parse_error: Whether the file had AST parse errors (affects confidence).

    Returns:
        EvidenceResult containing fully-formed Evidence and partial CryptoAsset.
    """
    rule = raw_match.rule

    # ── Display path ─────────────────────────────────────────────────────────
    display_path = (
        str(file_path.relative_to(relative_to))
        if relative_to and file_path.is_relative_to(relative_to)
        else str(file_path)
    )
    display_path = display_path.replace("\\", "/")

    # ── Location (0-based rows → 1-based lines) ───────────────────────────────
    line_number = raw_match.start_row + 1
    end_line = raw_match.end_row + 1
    column = raw_match.start_col

    location_str = f"{display_path}:{line_number}"

    source_location = SourceLocation(
        file_path=display_path,
        line_number=line_number,
        column_number=column,
        end_line_number=end_line if end_line >= line_number else line_number,
        snippet=raw_match.snippet,
    )

    # ── Confidence ────────────────────────────────────────────────────────────
    confidence = _compute_confidence(rule.confidence, raw_match)
    if has_parse_error:
        confidence = round(max(0.0, confidence - 0.05), 4)

    # ── Algorithm and purpose ──────────────────────────────────────────────────
    algorithm = _normalise_algorithm(
        rule.algorithm,
        raw_match.extracted_key_size,
        raw_match.extracted_curve,
    )
    purpose = _purpose_from_string(rule.purpose)

    # ── Evidence record ───────────────────────────────────────────────────────
    # Phase 4: carry what was actually observed (symbol + sibling context)
    # and whether this assignment is directly observed or needs enrichment.
    # unknown-purpose rules produce needs_enrichment so they flow into the
    # existing LLM path rather than being falsely classified.
    ambiguity = (
        "needs_enrichment"
        if purpose == CryptoPurpose.UNKNOWN
        else "resolved"
    )
    evidence = Evidence(
        detection_method=DetectionMethod.AST_RULE,
        finding_type=FindingType.DETERMINISTIC,
        rule_id=rule.rule_id,
        location=source_location,
        source_surface="source_code",
        confidence=confidence,
        observed_symbol=raw_match.observed_symbol,
        sibling_symbols=list(raw_match.sibling_symbols or ()),
        ambiguity_status=ambiguity,
    )

    # ── CryptoAsset with staging classification defaults ──────────────────────
    # Classification, sensitivity, criticality, and lifecycle_stage are staging
    # defaults. ClassificationEngine (PRD §5 stage 6) overwrites these via
    # model_copy before any risk scoring or reachability analysis runs.
    asset = CryptoAsset(
        scan_id=scan_id,
        algorithm=algorithm,
        key_size_bits=raw_match.extracted_key_size,
        purpose=purpose,
        location=location_str,
        source_surface="source_code",
        classification=_STAGING_CLASSIFICATION,
        sensitivity=_STAGING_SENSITIVITY,
        business_criticality=_STAGING_CRITICALITY,
        lifecycle_stage=LifecycleStage.ACTIVE,
        evidence=evidence,
        risk=None,
        recommendation=None,
    )

    return EvidenceResult(evidence=evidence, asset=asset)


def process_file_result(
    file_result: FileScanResult,
    scan_id: Optional[str] = None,
    relative_to: Optional[Path] = None,
) -> list[EvidenceResult]:
    """
    Process all raw matches from a FileScanResult into EvidenceResult objects.

    Args:
        file_result: Result from the source scanner for a single file.
        scan_id:     Optional scan run identifier.
        relative_to: Base path for relative display paths.

    Returns:
        List of EvidenceResult objects — one per raw match.
    """
    results: list[EvidenceResult] = []

    for raw_match in file_result.raw_matches:
        try:
            result = raw_match_to_asset(
                raw_match=raw_match,
                file_path=file_result.file_path,
                scan_id=scan_id,
                relative_to=relative_to,
                has_parse_error=file_result.parse_error,
            )
            results.append(result)
        except Exception as exc:
            logger.error(
                "Evidence engine failed for match in %s (rule %s): %s",
                file_result.file_path, raw_match.rule.rule_id, exc,
            )

    return results
