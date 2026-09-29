"""
PQC Mapping Loader — reads config/pqc_mappings.yaml and config/mosca_profiles.yaml
into typed dataclasses consumed by the Mosca and Recommendation engines.

This module is the boundary between editable YAML configuration and Python code.
NO algorithm-to-PQC mapping logic exists anywhere else in the codebase.

PRD §8: "Keeps algorithm-to-PQC mappings as editable data, not hardcoded logic."
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_DEFAULT_PQC_PATH = _REPO_ROOT / "config" / "pqc_mappings.yaml"
_DEFAULT_MOSCA_PATH = _REPO_ROOT / "config" / "mosca_profiles.yaml"


# ── PQC mapping types ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PQCMapping:
    """
    A single algorithm+purpose → PQC replacement mapping entry.

    Loaded from config/pqc_mappings.yaml.
    """
    algorithm_pattern: str       # prefix match (case-insensitive)
    purpose: str                 # CryptoPurpose value or "any"
    quantum_vulnerable: bool
    classical_broken: bool       # already broken without quantum
    quantum_weakened: bool       # weakened but not broken (e.g. AES-128)
    primary_replacement: str
    primary_fips: str
    primary_status: str          # StandardizationStatus value
    migration_path_type: str     # MigrationPathType value
    migration_path_description: str
    alternative_replacement: Optional[str] = None
    notes: Optional[str] = None
    hndl_risk: str = "none"      # none / low / medium / high / critical
    affected_protocols: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class UnderStandardizationAlgorithm:
    """An algorithm still under NIST standardization — must never be primary."""
    name: str
    nist_round: str
    purpose: str
    notes: Optional[str] = None


# ── Mosca profile types ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class DataShelfLifeEntry:
    classification: str   # "application" or "infrastructure"
    sensitivity: str      # SensitivityLevel value
    x_years: float


@dataclass(frozen=True)
class MigrationTimeEntry:
    algorithm_pattern: str   # prefix match or "*" for wildcard
    migration_type: str      # purpose or "*"
    y_years: float
    notes: Optional[str] = None


@dataclass(frozen=True)
class HNDLRules:
    threshold_x_years: float      # Minimum X to consider HNDL
    hndl_purposes: list[str]      # Purposes that are always HNDL candidates
    signature_threshold_x_years: float  # Higher threshold for digital_signature


@dataclass
class MoscaProfiles:
    z_years_default: float
    z_years_conservative: float
    z_years_moderate: float
    z_years_optimistic: float
    data_shelf_life: list[DataShelfLifeEntry]
    migration_time: list[MigrationTimeEntry]
    hndl_rules: HNDLRules


@dataclass
class PQCConfig:
    mappings: list[PQCMapping]
    under_standardization: list[UnderStandardizationAlgorithm]


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_pqc_config(path: Optional[Path] = None) -> PQCConfig:
    """Load and validate config/pqc_mappings.yaml."""
    p = Path(path) if path else _DEFAULT_PQC_PATH
    if not p.exists():
        raise FileNotFoundError(f"PQC mappings file not found: {p}")

    with open(p, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict) or "mappings" not in raw:
        raise ValueError(f"Invalid pqc_mappings.yaml — expected 'mappings' key: {p}")

    mappings: list[PQCMapping] = []
    for entry in raw["mappings"]:
        mappings.append(PQCMapping(
            algorithm_pattern=entry["algorithm_pattern"],
            purpose=entry.get("purpose", "any"),
            quantum_vulnerable=bool(entry.get("quantum_vulnerable", True)),
            classical_broken=bool(entry.get("classical_broken", False)),
            quantum_weakened=bool(entry.get("quantum_weakened", False)),
            primary_replacement=entry["primary_replacement"],
            primary_fips=entry.get("primary_fips", ""),
            primary_status=entry.get("primary_status", "standardized"),
            migration_path_type=entry.get("migration_path_type", "hybrid"),
            migration_path_description=entry.get("migration_path_description", ""),
            alternative_replacement=entry.get("alternative_replacement"),
            notes=entry.get("notes"),
            hndl_risk=entry.get("hndl_risk", "none"),
            affected_protocols=list(entry.get("affected_protocols", [])),
        ))

    under: list[UnderStandardizationAlgorithm] = []
    for entry in raw.get("under_standardization", []):
        under.append(UnderStandardizationAlgorithm(
            name=entry["name"],
            nist_round=str(entry.get("nist_round", "unknown")),
            purpose=entry.get("purpose", "unknown"),
            notes=entry.get("notes"),
        ))

    logger.info("Loaded %d PQC mappings, %d under-standardization entries from %s",
                len(mappings), len(under), p)
    return PQCConfig(mappings=mappings, under_standardization=under)


def load_mosca_profiles(path: Optional[Path] = None) -> MoscaProfiles:
    """Load and validate config/mosca_profiles.yaml."""
    p = Path(path) if path else _DEFAULT_MOSCA_PATH
    if not p.exists():
        raise FileNotFoundError(f"Mosca profiles file not found: {p}")

    with open(p, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    tt = raw.get("threat_timeline", {})
    dsl_entries = [
        DataShelfLifeEntry(
            classification=e["classification"],
            sensitivity=e["sensitivity"],
            x_years=float(e["x_years"]),
        )
        for e in raw.get("data_shelf_life", [])
    ]
    mt_entries = [
        MigrationTimeEntry(
            algorithm_pattern=e["algorithm_pattern"],
            migration_type=e.get("migration_type", "*"),
            y_years=float(e["y_years"]),
            notes=e.get("notes"),
        )
        for e in raw.get("migration_time", [])
    ]
    hndl_raw = raw.get("hndl_rules", {})
    hndl = HNDLRules(
        threshold_x_years=float(hndl_raw.get("hndl_threshold_x_years", 3)),
        hndl_purposes=list(hndl_raw.get("hndl_purposes", [])),
        signature_threshold_x_years=float(
            hndl_raw.get("hndl_signature_threshold_x_years", 5)
        ),
    )

    logger.info("Loaded Mosca profiles from %s (Z_default=%.0f yr)", p,
                tt.get("z_years_default", 10))
    return MoscaProfiles(
        z_years_default=float(tt.get("z_years_default", 10)),
        z_years_conservative=float(tt.get("z_years_conservative", 10)),
        z_years_moderate=float(tt.get("z_years_moderate", 15)),
        z_years_optimistic=float(tt.get("z_years_optimistic", 20)),
        data_shelf_life=dsl_entries,
        migration_time=mt_entries,
        hndl_rules=hndl,
    )


# ── Lookup helpers ─────────────────────────────────────────────────────────────

def find_pqc_mapping(
    pqc_config: PQCConfig,
    algorithm: str,
    purpose: str,
) -> Optional[PQCMapping]:
    """
    Find the best PQC mapping for an algorithm+purpose pair.

    Matching rules (in order of precedence):
      1. Exact algorithm prefix + exact purpose
      2. Exact algorithm prefix + purpose == "any"
      3. Partial algorithm prefix (longest match wins) + exact purpose
      4. Partial algorithm prefix + "any"

    Algorithm matching is case-insensitive prefix matching:
      "RSA" matches "RSA-2048", "RSA-4096"
      "AES-128" matches "AES-128-CBC-128", "AES-128-GCM"
    """
    alg_upper = algorithm.upper()
    purp_lower = purpose.lower()

    # Collect candidates with their match score (longer prefix = better)
    best: Optional[tuple[int, PQCMapping]] = None

    for mapping in pqc_config.mappings:
        pat_upper = mapping.algorithm_pattern.upper()

        # Prefix match
        if not alg_upper.startswith(pat_upper):
            continue

        match_len = len(pat_upper)

        # Purpose match
        purp_match = (
            mapping.purpose.lower() == purp_lower or
            mapping.purpose.lower() == "any"
        )
        if not purp_match:
            continue

        # Prefer exact purpose over "any", longer prefix over shorter
        exact_purpose_bonus = 1000 if mapping.purpose.lower() == purp_lower else 0
        score = match_len + exact_purpose_bonus

        if best is None or score > best[0]:
            best = (score, mapping)

    return best[1] if best else None


def get_x_years(
    profiles: MoscaProfiles,
    classification: str,
    sensitivity: str,
) -> float:
    """Look up the default X (data shelf life) for a classification + sensitivity pair."""
    for entry in profiles.data_shelf_life:
        if (entry.classification == classification and
                entry.sensitivity == sensitivity):
            return entry.x_years
    # Fallback: use the highest X for the classification
    matching = [e for e in profiles.data_shelf_life
                if e.classification == classification]
    if matching:
        return max(e.x_years for e in matching)
    return 10.0  # conservative default


def get_y_years(
    profiles: MoscaProfiles,
    algorithm: str,
    purpose: str,
) -> float:
    """Look up the default Y (migration time) for an algorithm + purpose pair."""
    alg_upper = algorithm.upper()
    purp_lower = purpose.lower()
    best: Optional[tuple[int, float]] = None

    for entry in profiles.migration_time:
        pat = entry.algorithm_pattern.upper()
        type_match = (
            entry.migration_type.lower() == purp_lower or
            entry.migration_type == "*"
        )
        # Wildcard pattern matches everything
        if pat == "*":
            score = 0
        elif alg_upper.startswith(pat):
            score = len(pat)
        else:
            continue

        if not type_match:
            continue

        type_bonus = 100 if entry.migration_type != "*" else 0
        final_score = score + type_bonus

        if best is None or final_score > best[0]:
            best = (final_score, entry.y_years)

    return best[1] if best else 2.0  # default 2 years
