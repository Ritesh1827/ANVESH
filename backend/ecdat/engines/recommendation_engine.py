"""
PQC Recommendation Engine — PRD §5 stage 10.

Maps each CryptoAsset's algorithm + purpose to the correct NIST-standard
PQC replacement, enforcing all PRD constraints:

  1. Purpose-aware mapping is MANDATORY (PRD §5 stage 10):
       key_establishment → ML-KEM  (FIPS 203)
       digital_signature → ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)
     The engine NEVER maps an algorithm directly to a PQC replacement
     without determining its cryptographic purpose first.

  2. Standardization status separation (PRD §5 stage 10):
       Standardized (FIPS 203/204/205) are clearly labelled.
       Under-standardization algorithms (HQC, Falcon, BIKE) are NEVER
       recommended as primary replacements.

  3. Hybrid-first by default (PRD §5 stage 10):
       Hybrid (classical + PQC) is the default during migration.
       Pure-PQC is only recommended for greenfield systems.

  4. Read-only advisory output (PRD §4 Non-Goals):
       This engine produces recommendations only. It NEVER automatically
       applies changes, rotates keys, or patches code.

All mapping logic is driven by config/pqc_mappings.yaml.
No algorithm-to-PQC mapping is hardcoded in this module.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from ecdat.schemas import (
    CryptoAsset,
    CryptoPurpose,
    MigrationPathType,
    Recommendation,
    StandardizationStatus,
)
from ecdat.engines.pqc_loader import (
    PQCConfig,
    PQCMapping,
    find_pqc_mapping,
    load_pqc_config,
)

logger = logging.getLogger(__name__)


# ── Status / path type conversion ─────────────────────────────────────────────

def _to_standardization_status(status_str: str) -> StandardizationStatus:
    """Convert a YAML status string to StandardizationStatus enum."""
    try:
        return StandardizationStatus(status_str)
    except ValueError:
        logger.warning(
            "Unknown standardization_status '%s' in pqc_mappings.yaml — "
            "defaulting to STANDARDIZED. Fix the config.",
            status_str,
        )
        return StandardizationStatus.STANDARDIZED


def _to_migration_path_type(path_type_str: str) -> MigrationPathType:
    """Convert a YAML migration_path_type string to MigrationPathType enum."""
    try:
        return MigrationPathType(path_type_str)
    except ValueError:
        logger.warning(
            "Unknown migration_path_type '%s' — defaulting to HYBRID.",
            path_type_str,
        )
        return MigrationPathType.HYBRID


# ── No-action recommendation (safe algorithms) ───────────────────────────────

def _no_action_recommendation(mapping: PQCMapping) -> Recommendation:
    """
    Build a Recommendation for an algorithm that does not need migration.

    PRD §5 stage 10: algorithms that are quantum-safe should still receive
    an informational entry (no_action path type) so every asset has a
    recommendation record for completeness.
    """
    return Recommendation(
        standardized_replacement=mapping.primary_replacement,
        migration_path=mapping.migration_path_description,
        migration_path_type=MigrationPathType.NO_ACTION,
        status=_to_standardization_status(mapping.primary_status),
        advisory_note=mapping.notes,
    )


# ── Unknown algorithm fallback ────────────────────────────────────────────────

def _unknown_recommendation(algorithm: str, purpose: CryptoPurpose) -> Recommendation:
    """
    Fallback recommendation when no mapping is found for an algorithm.

    This should not occur for known algorithms — if it does, it indicates
    a gap in pqc_mappings.yaml that should be filled.
    """
    logger.warning(
        "No PQC mapping found for algorithm='%s' purpose='%s'. "
        "Add an entry to config/pqc_mappings.yaml.",
        algorithm, purpose.value,
    )
    return Recommendation(
        standardized_replacement="UNKNOWN — see config/pqc_mappings.yaml",
        migration_path="manual review required",
        migration_path_type=MigrationPathType.HYBRID,
        # CLASSICAL: source algorithm is classical; no standardized PQC
        # mapping is available yet. Using STANDARDIZED here would be
        # semantically incorrect since no recommendation has been made.
        status=StandardizationStatus.CLASSICAL,
        advisory_note=(
            f"No mapping found for {algorithm} ({purpose.value}). "
            "Add an entry to config/pqc_mappings.yaml to resolve this."
        ),
    )


# ── Purpose validation ────────────────────────────────────────────────────────

def _validate_purpose_mapping(
    purpose: CryptoPurpose,
    mapping: PQCMapping,
) -> None:
    """
    Assert that the mapping's purpose is consistent with the asset's purpose.

    PRD §5 stage 10: "Do not map an algorithm directly to a PQC replacement
    without determining its cryptographic purpose."

    This is a defensive check — the mapping lookup already filters by purpose,
    but we log a warning if there is any inconsistency.
    """
    if mapping.purpose.lower() not in ("any", purpose.value.lower()):
        logger.warning(
            "Purpose mismatch: asset purpose='%s' but mapping purpose='%s' "
            "for pattern='%s'. Check pqc_mappings.yaml.",
            purpose.value, mapping.purpose, mapping.algorithm_pattern,
        )


# ── Primary recommendation builder ───────────────────────────────────────────

def _build_recommendation(
    mapping: PQCMapping,
    purpose: CryptoPurpose,
    *,
    is_greenfield: bool = False,
) -> Recommendation:
    """
    Build a Recommendation from a PQCMapping entry.

    PRD §5 stage 10: hybrid is the default during migration.
    pure_pqc only for greenfield systems.

    Enforces that under-standardization algorithms are NEVER the primary
    recommendation (they may appear in advisory_note only).
    """
    _validate_purpose_mapping(purpose, mapping)

    status = _to_standardization_status(mapping.primary_status)

    # CRITICAL: never recommend under-standardization as primary
    # This constraint is defined in PRD §5 stage 10.
    if status == StandardizationStatus.UNDER_STANDARDIZATION:
        logger.error(
            "CONSTRAINT VIOLATION: pqc_mappings.yaml entry for '%s' has "
            "primary_status='under_standardization'. This algorithm must "
            "NEVER be the primary recommendation. Fix pqc_mappings.yaml.",
            mapping.algorithm_pattern,
        )
        # Fail safe — return an unknown recommendation rather than violating PRD
        return _unknown_recommendation(mapping.algorithm_pattern, purpose)

    # Determine migration path type
    if is_greenfield and mapping.migration_path_type == "hybrid":
        path_type = MigrationPathType.PURE_PQC
        path_desc = mapping.migration_path_description.replace(
            "hybrid:", "pure-pqc:"
        )
    else:
        path_type = _to_migration_path_type(mapping.migration_path_type)
        path_desc = mapping.migration_path_description

    return Recommendation(
        standardized_replacement=mapping.primary_replacement,
        migration_path=path_desc,
        migration_path_type=path_type,
        status=status,
        alternative_replacement=mapping.alternative_replacement,
        affected_protocols=list(mapping.affected_protocols) if mapping.affected_protocols else None,
        advisory_note=mapping.notes,
    )


# ── Engine ────────────────────────────────────────────────────────────────────

class RecommendationEngine:
    """
    PQC Recommendation Engine — annotates each CryptoAsset with a
    purpose-aware, standardization-status-checked Recommendation.

    All mapping logic is driven by config/pqc_mappings.yaml.

    Usage:
        engine = RecommendationEngine()
        assets_with_recs = engine.process(assets)
    """

    def __init__(
        self,
        pqc_mappings_path: Optional[Path] = None,
    ) -> None:
        self._pqc_config = load_pqc_config(pqc_mappings_path)

    def recommend_for_asset(
        self,
        asset: CryptoAsset,
        *,
        is_greenfield: bool = False,
    ) -> CryptoAsset:
        """
        Compute and attach a Recommendation to a single CryptoAsset.

        Returns a new CryptoAsset with the recommendation field populated.
        The original asset is NOT mutated.

        Args:
            asset:        The asset to recommend for.
            is_greenfield: If True, recommend pure-PQC instead of hybrid.
                           Default False (hybrid during migration per PRD).
        """
        mapping = find_pqc_mapping(
            self._pqc_config,
            asset.algorithm,
            asset.purpose.value,
        )

        if mapping is None:
            rec = _unknown_recommendation(asset.algorithm, asset.purpose)
        elif not mapping.quantum_vulnerable and not mapping.quantum_weakened:
            rec = _no_action_recommendation(mapping)
        else:
            rec = _build_recommendation(
                mapping=mapping,
                purpose=asset.purpose,
                is_greenfield=is_greenfield,
            )

        return asset.model_copy(update={"recommendation": rec})

    def process(
        self,
        assets: list[CryptoAsset],
        *,
        is_greenfield: bool = False,
    ) -> list[CryptoAsset]:
        """
        Generate recommendations for all assets in a list.

        Returns new CryptoAsset instances with recommendation records attached.
        """
        result: list[CryptoAsset] = []
        unknown_count = 0
        no_action_count = 0
        migration_count = 0

        for asset in assets:
            updated = self.recommend_for_asset(asset, is_greenfield=is_greenfield)
            result.append(updated)
            if updated.recommendation:
                if updated.recommendation.migration_path_type == MigrationPathType.NO_ACTION:
                    no_action_count += 1
                elif "UNKNOWN" in updated.recommendation.standardized_replacement:
                    unknown_count += 1
                else:
                    migration_count += 1

        logger.info(
            "Recommendation engine processed %d assets: "
            "%d require migration, %d no-action, %d unknown",
            len(result), migration_count, no_action_count, unknown_count,
        )
        return result

    def get_under_standardization_names(self) -> list[str]:
        """Return names of algorithms still under NIST standardization."""
        return [a.name for a in self._pqc_config.under_standardization]
