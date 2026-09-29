"""
Migration Impact Analysis Engine — PRD §5 stage 11.

PRD §5 stage 11 requirement:
  "Score each recommendation against real migration factors (bandwidth,
   storage, latency, protocol, application software, hardware/HSM, vendor
   dependency, cost) and render the result as a roadmap-style sequence
   (current state → risk → recommendation → affected components →
   priority → validation steps), not a bare score."

This engine:
  1. Loads migration impact weights and factor scores from
     config/migration_weights.yaml (PRD §8: editable data, not hardcoded).
  2. For every asset that has a PQC recommendation, computes:
     a. A per-factor impact score (0.0–1.0)
     b. A weighted composite impact score (0.0–1.0)
     c. A roadmap-style narrative sequence
  3. Attaches the result to the CryptoAsset via model_copy().

The roadmap narrative follows the PRD §5 stage 11 format exactly:
  current state → risk → recommendation → affected components →
  priority → validation steps

PRD §4 Non-Goals: this engine is read-only and advisory. It never
automatically applies changes, rotates keys, or modifies systems.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from ecdat.schemas import CryptoAsset, MigrationPathType

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_DEFAULT_WEIGHTS_PATH = _REPO_ROOT / "config" / "migration_weights.yaml"

# The 8 PRD-mandated factors, in display order
FACTOR_NAMES = [
    "bandwidth", "storage", "latency", "protocol",
    "application_software", "hardware_hsm", "vendor_dependency", "cost",
]


# ── Config data structures ────────────────────────────────────────────────────

@dataclass(frozen=True)
class FactorDefinition:
    name: str
    weight: float
    description: str


@dataclass(frozen=True)
class AlgorithmImpactEntry:
    algorithm_prefix: str
    purpose: str          # "any" or a CryptoPurpose value
    scores: dict[str, float]


@dataclass
class MigrationWeightsConfig:
    factors: list[FactorDefinition]
    algorithm_impacts: list[AlgorithmImpactEntry]
    validation_steps: dict[str, list[str]]

    @property
    def factor_map(self) -> dict[str, FactorDefinition]:
        return {f.name: f for f in self.factors}


def load_migration_weights(path: Optional[Path] = None) -> MigrationWeightsConfig:
    """Load config/migration_weights.yaml."""
    p = Path(path) if path else _DEFAULT_WEIGHTS_PATH
    if not p.exists():
        raise FileNotFoundError(f"Migration weights not found: {p}")

    with open(p, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    factors: list[FactorDefinition] = []
    for name in FACTOR_NAMES:
        entry = raw["factors"].get(name, {})
        factors.append(FactorDefinition(
            name=name,
            weight=float(entry.get("weight", 0.0)),
            description=str(entry.get("description", "")),
        ))

    algorithm_impacts: list[AlgorithmImpactEntry] = []
    for entry in raw.get("algorithm_impacts", []):
        algorithm_impacts.append(AlgorithmImpactEntry(
            algorithm_prefix=str(entry["algorithm_prefix"]),
            purpose=str(entry.get("purpose", "any")),
            scores={k: float(v) for k, v in entry.get("scores", {}).items()},
        ))

    validation_steps = {
        k: list(v)
        for k, v in raw.get("validation_steps", {}).items()
    }

    return MigrationWeightsConfig(
        factors=factors,
        algorithm_impacts=algorithm_impacts,
        validation_steps=validation_steps,
    )


# ── Impact lookup ─────────────────────────────────────────────────────────────

def _find_impact_entry(
    config: MigrationWeightsConfig,
    algorithm: str,
    purpose: str,
) -> AlgorithmImpactEntry:
    """
    Find the best-matching algorithm impact entry (longest prefix + purpose match).
    Falls back to the "*" wildcard if nothing specific matches.
    """
    alg_upper = algorithm.upper()
    purp_lower = purpose.lower()

    best: Optional[tuple[int, AlgorithmImpactEntry]] = None

    for entry in config.algorithm_impacts:
        prefix = entry.algorithm_prefix.upper()
        if prefix == "*":
            score = 0
        elif alg_upper.startswith(prefix):
            score = len(prefix)
        else:
            continue

        purpose_match = (
            entry.purpose.lower() in ("any", purp_lower)
        )
        if not purpose_match:
            continue

        purpose_bonus = 100 if entry.purpose.lower() != "any" else 0
        final_score = score + purpose_bonus

        if best is None or final_score > best[0]:
            best = (final_score, entry)

    if best:
        return best[1]

    # Should never reach here since "*" wildcard always matches
    # Return a zero-impact default
    return AlgorithmImpactEntry(
        algorithm_prefix="*",
        purpose="any",
        scores={f: 0.0 for f in FACTOR_NAMES},
    )


# ── Migration roadmap result ──────────────────────────────────────────────────

@dataclass
class FactorScore:
    """Impact score for a single migration factor."""
    factor: str
    weight: float
    score: float               # 0.0 = minimal, 1.0 = maximum disruption
    weighted_contribution: float
    description: str


@dataclass
class MigrationRoadmap:
    """
    Full migration impact analysis for a single asset.

    PRD §5 stage 11 roadmap sequence:
      current_state → risk_context → recommendation → affected_components →
      priority → validation_steps
    """
    # ── Roadmap narrative ─────────────────────────────────────────────────────
    current_state: str
    risk_context: str
    recommendation_action: str
    affected_components: list[str]
    migration_priority: str       # "immediate" | "near-term" | "planned" | "monitor"
    validation_steps: list[str]

    # ── Impact scores (8 PRD factors) ────────────────────────────────────────
    factor_scores: list[FactorScore]
    composite_impact_score: float     # 0.0–1.0 weighted average
    impact_level: str                 # "low" | "moderate" | "high" | "critical"

    # ── Full narrative string ─────────────────────────────────────────────────
    narrative: str

    def summary(self) -> dict:
        """Serialisable summary for CBOM and reports."""
        return {
            "current_state": self.current_state,
            "risk_context": self.risk_context,
            "recommendation_action": self.recommendation_action,
            "affected_components": self.affected_components,
            "migration_priority": self.migration_priority,
            "validation_steps": self.validation_steps,
            "composite_impact_score": round(self.composite_impact_score, 3),
            "impact_level": self.impact_level,
            "factor_scores": [
                {
                    "factor": fs.factor,
                    "score": round(fs.score, 3),
                    "weighted_contribution": round(fs.weighted_contribution, 3),
                }
                for fs in self.factor_scores
            ],
            "narrative": self.narrative,
        }


# ── Narrative builders ────────────────────────────────────────────────────────

def _impact_level(composite: float) -> str:
    if composite < 0.25:
        return "low"
    elif composite < 0.50:
        return "moderate"
    elif composite < 0.75:
        return "high"
    return "critical"


def _migration_priority(asset: CryptoAsset) -> str:
    if asset.risk is None:
        return "planned"
    p = asset.risk.priority.value
    if p == "P1":
        return "immediate"
    if p == "P2":
        return "near-term"
    if p == "P3":
        return "planned"
    return "monitor"


def _build_current_state(asset: CryptoAsset) -> str:
    parts = [f"{asset.algorithm} used for {asset.purpose.value.replace('_', ' ')}"]
    if asset.location:
        parts.append(f"at {asset.location}")
    if asset.protocol:
        parts.append(f"via {asset.protocol}")
    if asset.library:
        parts.append(f"({asset.library})")
    return " ".join(parts)


def _build_risk_context(asset: CryptoAsset) -> str:
    if asset.risk is None:
        return "Risk not yet assessed."
    r = asset.risk
    parts = []
    if r.urgency_flag:
        parts.append(
            f"quantum-urgent (X={r.mosca_x_years:.0f}yr + "
            f"Y={r.mosca_y_years:.0f}yr > Z={r.mosca_z_years:.0f}yr threat timeline)"
        )
    if r.hndl_flag:
        parts.append("HNDL exposure: adversaries may already be harvesting ciphertext")
    if not parts:
        parts.append(f"priority {r.priority.value} — migration recommended")
    return "; ".join(parts)


def _build_recommendation_action(asset: CryptoAsset) -> str:
    if asset.recommendation is None:
        return "No recommendation available."
    rec = asset.recommendation
    path_type = rec.migration_path_type.value if rec.migration_path_type else "hybrid"
    return (
        f"Migrate to {rec.standardized_replacement} "
        f"[{rec.status.value}] via {rec.migration_path or path_type} strategy"
    )


def _build_affected_components(asset: CryptoAsset) -> list[str]:
    components = []
    # From recommendation
    if asset.recommendation:
        rec = asset.recommendation
        if rec.affected_protocols:
            components.extend(rec.affected_protocols)
        if rec.affected_libraries:
            components.extend(rec.affected_libraries)
    # From asset metadata
    if asset.protocol and asset.protocol not in components:
        components.append(asset.protocol)
    if asset.library and asset.library not in components:
        components.append(asset.library)
    # Classification hint
    if asset.classification.value == "infrastructure":
        if "TLS configuration" not in components:
            components.append("TLS configuration")
        if "Certificate infrastructure" not in components:
            components.append("Certificate infrastructure")
    if not components:
        components.append(f"{asset.source_surface} layer")
    return components


def _build_narrative(
    current_state: str,
    risk_context: str,
    recommendation_action: str,
    affected_components: list[str],
    migration_priority: str,
    impact_level: str,
    composite_score: float,
) -> str:
    """
    Build the full roadmap narrative string in PRD §5 stage 11 format:
      current state → risk → recommendation → affected components →
      priority → (implicit: see validation steps)
    """
    affected_str = " + ".join(affected_components) if affected_components else "application layer"
    return (
        f"{current_state} "
        f"→ {risk_context} "
        f"→ {recommendation_action} "
        f"→ affects: {affected_str} "
        f"→ migration priority: {migration_priority} "
        f"(impact: {impact_level}, composite score: {composite_score:.2f})"
    )


# ── Core computation ──────────────────────────────────────────────────────────

def compute_migration_roadmap(
    asset: CryptoAsset,
    config: MigrationWeightsConfig,
) -> MigrationRoadmap:
    """
    Compute the full migration impact roadmap for a single asset.

    Returns a MigrationRoadmap with narrative + factor scores.
    This function is pure — it does not modify the asset.
    """
    impact_entry = _find_impact_entry(config, asset.algorithm, asset.purpose.value)

    # Compute per-factor scores
    factor_scores: list[FactorScore] = []
    composite = 0.0

    for factor_def in config.factors:
        raw_score = impact_entry.scores.get(factor_def.name, 0.0)
        weighted = raw_score * factor_def.weight
        composite += weighted
        factor_scores.append(FactorScore(
            factor=factor_def.name,
            weight=factor_def.weight,
            score=raw_score,
            weighted_contribution=weighted,
            description=factor_def.description[:120],
        ))

    composite = round(min(1.0, composite), 4)
    level = _impact_level(composite)

    # Roadmap narrative components
    current_state = _build_current_state(asset)
    risk_context = _build_risk_context(asset)
    recommendation_action = _build_recommendation_action(asset)
    affected = _build_affected_components(asset)
    priority = _migration_priority(asset)

    # Validation steps from config
    path_type_key = "hybrid"
    if asset.recommendation and asset.recommendation.migration_path_type:
        path_type_key = asset.recommendation.migration_path_type.value.replace("-", "_")
        # Map "no_action" → "no_action", "classical_upgrade" → "classical_upgrade"
        if path_type_key not in config.validation_steps:
            path_type_key = "hybrid"

    steps = list(config.validation_steps.get(path_type_key, config.validation_steps.get("hybrid", [])))

    narrative = _build_narrative(
        current_state, risk_context, recommendation_action,
        affected, priority, level, composite,
    )

    return MigrationRoadmap(
        current_state=current_state,
        risk_context=risk_context,
        recommendation_action=recommendation_action,
        affected_components=affected,
        migration_priority=priority,
        validation_steps=steps,
        factor_scores=factor_scores,
        composite_impact_score=composite,
        impact_level=level,
        narrative=narrative,
    )


# ── Engine ────────────────────────────────────────────────────────────────────

@dataclass
class MigrationImpactStats:
    total: int = 0
    with_recommendation: int = 0
    immediate: int = 0
    near_term: int = 0
    planned: int = 0
    monitor: int = 0


class MigrationImpactEngine:
    """
    Migration Impact Analysis Engine — PRD §5 stage 11.

    Processes every asset that has a PQC recommendation and attaches a
    MigrationRoadmap. Assets without a recommendation are passed through.

    Usage:
        engine = MigrationImpactEngine()
        assets, roadmaps = engine.process(assets)
    """

    def __init__(self, weights_path: Optional[Path] = None) -> None:
        self._config = load_migration_weights(weights_path)
        self._stats = MigrationImpactStats()

    @property
    def stats(self) -> MigrationImpactStats:
        return self._stats

    @property
    def config(self) -> MigrationWeightsConfig:
        return self._config

    def process(
        self,
        assets: list[CryptoAsset],
    ) -> tuple[list[CryptoAsset], dict[str, MigrationRoadmap]]:
        """
        Compute migration roadmaps for all assets with recommendations.

        Returns:
          - assets: original list (unchanged — roadmaps are not stored on asset)
          - roadmaps: dict[asset_id → MigrationRoadmap]

        NOTE: PRD §5 stage 11 output is roadmap text, not a new asset field.
        The MigrationRoadmap is kept in a separate dict (keyed by asset_id) so
        it can be consumed by the CBOM exporter and report generator without
        modifying the CryptoAsset schema.
        """
        self._stats = MigrationImpactStats()
        roadmaps: dict[str, MigrationRoadmap] = {}

        for asset in assets:
            self._stats.total += 1

            if asset.recommendation is None:
                continue

            self._stats.with_recommendation += 1
            roadmap = compute_migration_roadmap(asset, self._config)
            roadmaps[asset.asset_id] = roadmap

            p = roadmap.migration_priority
            if p == "immediate":
                self._stats.immediate += 1
            elif p == "near-term":
                self._stats.near_term += 1
            elif p == "planned":
                self._stats.planned += 1
            else:
                self._stats.monitor += 1

            logger.debug(
                "Migration roadmap: %s @ %s — %s (score=%.2f, priority=%s)",
                asset.algorithm, asset.location,
                roadmap.impact_level, roadmap.composite_impact_score,
                roadmap.migration_priority,
            )

        logger.info(
            "Migration impact: %d/%d assets analysed — "
            "%d immediate, %d near-term, %d planned, %d monitor",
            self._stats.with_recommendation, self._stats.total,
            self._stats.immediate, self._stats.near_term,
            self._stats.planned, self._stats.monitor,
        )

        return assets, roadmaps
