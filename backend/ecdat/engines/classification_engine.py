"""
Classification Engine — PRD §5 stage 6: Classification & Business Context.

Tags each asset in the inventory with:
  - classification:       AssetClassification  (application | infrastructure)
  - sensitivity:          SensitivityLevel      (public | internal | confidential | high | critical)
  - business_criticality: BusinessCriticality   (low | medium | high | critical)
  - lifecycle_stage:      LifecycleStage        (active | deprecated | expired | rotation_pending | legacy | unknown)

All rules are loaded from config/classification_rules.yaml. No rule logic
is hardcoded in this module — consistent with PRD §8 ("editable data,
not hardcoded logic").

Pipeline position (PRD §7 architecture diagram):
  Inventory → Classification & Business Context → Reachability → … → Mosca

This engine runs AFTER inventory correlation and BEFORE reachability, so
every asset — regardless of which input surface produced it — is classified
by the same rules. Certificate assets arriving in Day 6 will use the same
engine without any changes to this module.

PRD §5 stage 6 requirements covered:
  ✓ TEC 910018:2025 taxonomy (application vs infrastructure)
  ✓ Sensitivity
  ✓ Business criticality
  ✓ Lifecycle stage (cert expiry-aware; ACTIVE default for others)

PRD §6 (Explainability): every classification decision records the rule_id
that produced it in the returned ClassificationResult, so the system can
always answer "why is this classified as infrastructure / high / critical?".

Read-only guarantee (PRD §6): this engine annotates CryptoAsset records only.
It never modifies source systems.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CryptoAsset,
    LifecycleStage,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_DEFAULT_RULES_PATH = _REPO_ROOT / "config" / "classification_rules.yaml"


# ══════════════════════════════════════════════════════════════════════════════
# Config data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ClassificationRule:
    """A single parsed rule from classification_rules.yaml."""
    priority: int
    description: str
    result: str                         # the value to assign when this rule fires

    # Match criteria (all present criteria are AND-ed)
    surface: Optional[list[str]]        # source_surface values
    purpose: Optional[list[str]]        # CryptoPurpose values
    algorithm_prefix: Optional[list[str]]   # case-insensitive prefix match
    file_path_contains: Optional[list[str]] # substring match on file_path
    key_size_lt: Optional[int]
    key_size_gte: Optional[int]
    # For criticality rules: can condition on classification already assigned
    classification_result: Optional[str]


@dataclass
class ClassificationConfig:
    """Fully loaded classification configuration."""
    classification_rules: list[ClassificationRule]
    classification_fallback: str

    sensitivity_rules: list[ClassificationRule]
    sensitivity_fallback: str

    criticality_rules: list[ClassificationRule]
    criticality_fallback: str

    rotation_pending_days: int
    default_lifecycle_stage: str
    legacy_algorithm_prefixes: list[str]


# ══════════════════════════════════════════════════════════════════════════════
# Config loader
# ══════════════════════════════════════════════════════════════════════════════

def _parse_rules(raw_list: list[dict]) -> list[ClassificationRule]:
    rules: list[ClassificationRule] = []
    for entry in raw_list:
        match = entry.get("match", {})

        # surface: accept string or list
        surface_raw = match.get("surface")
        if isinstance(surface_raw, str):
            surface = [surface_raw]
        elif isinstance(surface_raw, list):
            surface = [str(s) for s in surface_raw]
        else:
            surface = None

        # purpose: accept string or list
        purpose_raw = match.get("purpose")
        if isinstance(purpose_raw, str):
            purpose = [purpose_raw]
        elif isinstance(purpose_raw, list):
            purpose = [str(p) for p in purpose_raw]
        else:
            purpose = None

        # algorithm_prefix: accept string or list
        alg_raw = match.get("algorithm_prefix")
        if isinstance(alg_raw, str):
            alg_prefix = [alg_raw]
        elif isinstance(alg_raw, list):
            alg_prefix = [str(a) for a in alg_raw]
        else:
            alg_prefix = None

        # file_path_contains: accept string or list
        fp_raw = match.get("file_path_contains")
        if isinstance(fp_raw, str):
            fp_contains = [fp_raw]
        elif isinstance(fp_raw, list):
            fp_contains = [str(s) for s in fp_raw]
        else:
            fp_contains = None

        rules.append(ClassificationRule(
            priority=int(entry.get("priority", 0)),
            description=str(entry.get("description", "")),
            result=str(entry["result"]),
            surface=surface,
            purpose=purpose,
            algorithm_prefix=alg_prefix,
            file_path_contains=fp_contains,
            key_size_lt=entry.get("key_size_lt"),
            key_size_gte=entry.get("key_size_gte"),
            classification_result=match.get("classification_result"),
        ))

    # Sort descending by priority so first match = highest priority
    rules.sort(key=lambda r: r.priority, reverse=True)
    return rules


def load_classification_config(
    path: Optional[Path] = None,
) -> ClassificationConfig:
    """Load and validate config/classification_rules.yaml."""
    p = Path(path) if path else _DEFAULT_RULES_PATH
    if not p.exists():
        raise FileNotFoundError(f"Classification rules not found: {p}")

    with open(p, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError(f"Invalid classification_rules.yaml: expected dict at top level")

    for key in ("classification_rules", "sensitivity_rules", "criticality_rules"):
        if key not in raw:
            raise ValueError(f"classification_rules.yaml missing required section: '{key}'")

    lifecycle = raw.get("lifecycle", {})

    config = ClassificationConfig(
        classification_rules=_parse_rules(raw["classification_rules"]),
        classification_fallback=raw.get("classification_fallback", "application"),
        sensitivity_rules=_parse_rules(raw["sensitivity_rules"]),
        sensitivity_fallback=raw.get("sensitivity_fallback", "internal"),
        criticality_rules=_parse_rules(raw["criticality_rules"]),
        criticality_fallback=raw.get("criticality_fallback", "low"),
        rotation_pending_days=int(lifecycle.get("rotation_pending_days_before_expiry", 90)),
        default_lifecycle_stage=str(lifecycle.get("default_stage", "active")),
        legacy_algorithm_prefixes=[
            str(s) for s in lifecycle.get("legacy_algorithm_prefixes", [])
        ],
    )

    logger.info(
        "Loaded classification config: %d classification rules, "
        "%d sensitivity rules, %d criticality rules",
        len(config.classification_rules),
        len(config.sensitivity_rules),
        len(config.criticality_rules),
    )
    return config


# ══════════════════════════════════════════════════════════════════════════════
# Rule matching
# ══════════════════════════════════════════════════════════════════════════════

def _matches_rule(
    rule: ClassificationRule,
    asset: CryptoAsset,
    assigned_classification: Optional[str] = None,
) -> bool:
    """
    Return True if ALL criteria in the rule match this asset.

    `assigned_classification` is the classification already assigned by
    the classification_rules pass — needed for criticality rules that
    condition on classification (e.g. "key_establishment AND infrastructure").
    """
    file_path = asset.evidence.location.file_path.lower()
    algorithm = asset.algorithm.upper()
    purpose = asset.purpose.value
    surface = asset.source_surface

    # ── surface ────────────────────────────────────────────────────────────
    if rule.surface is not None:
        if surface not in rule.surface:
            return False

    # ── purpose ────────────────────────────────────────────────────────────
    if rule.purpose is not None:
        if purpose not in rule.purpose:
            return False

    # ── algorithm_prefix ───────────────────────────────────────────────────
    if rule.algorithm_prefix is not None:
        if not any(algorithm.startswith(p.upper()) for p in rule.algorithm_prefix):
            return False

    # ── file_path_contains ─────────────────────────────────────────────────
    if rule.file_path_contains is not None:
        if not any(kw.lower() in file_path for kw in rule.file_path_contains):
            return False

    # ── key_size_lt ────────────────────────────────────────────────────────
    if rule.key_size_lt is not None:
        if asset.key_size_bits is None or asset.key_size_bits >= rule.key_size_lt:
            return False

    # ── key_size_gte ───────────────────────────────────────────────────────
    if rule.key_size_gte is not None:
        if asset.key_size_bits is None or asset.key_size_bits < rule.key_size_gte:
            return False

    # ── classification_result (cross-field dependency for criticality) ─────
    if rule.classification_result is not None:
        if assigned_classification != rule.classification_result:
            return False

    return True


def _apply_rules(
    rules: list[ClassificationRule],
    fallback: str,
    asset: CryptoAsset,
    assigned_classification: Optional[str] = None,
) -> tuple[str, str]:
    """
    Find the first matching rule and return (result_value, rule_description).
    Returns (fallback, "fallback") if no rule matches.
    Rules must already be sorted by priority descending.
    """
    for rule in rules:
        if _matches_rule(rule, asset, assigned_classification):
            return rule.result, rule.description
    return fallback, "fallback — no rule matched"


# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle stage resolution
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_lifecycle(
    asset: CryptoAsset,
    config: ClassificationConfig,
) -> LifecycleStage:
    """
    Determine the lifecycle stage for an asset.

    Certificate surface:
      - If certificate_expiry is in the past → EXPIRED
      - If certificate_expiry is within rotation_pending_days → ROTATION_PENDING
      - Otherwise → ACTIVE

    All other surfaces:
      - Algorithm is in legacy_algorithm_prefixes → LEGACY
      - Otherwise → ACTIVE (explicit documented default)

    Precedence note: the LEGACY rule only applies to non-certificate sources
    because certificates already have expiry-based stage determination.
    """
    if asset.source_surface == "certificate":
        expiry = asset.certificate_expiry
        if expiry is None:
            # Certificate with no expiry parsed → unknown lifecycle
            return LifecycleStage.UNKNOWN
        now = datetime.now(timezone.utc)
        # Make expiry timezone-aware if naive
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry < now:
            return LifecycleStage.EXPIRED
        days_remaining = (expiry - now).days
        if days_remaining <= config.rotation_pending_days:
            return LifecycleStage.ROTATION_PENDING
        return LifecycleStage.ACTIVE

    # Non-certificate surface: check for legacy algorithms
    alg_upper = asset.algorithm.upper()
    for prefix in config.legacy_algorithm_prefixes:
        if alg_upper.startswith(prefix.upper()):
            return LifecycleStage.LEGACY

    # Explicit default — not a silent assumption
    return LifecycleStage.ACTIVE


# ══════════════════════════════════════════════════════════════════════════════
# Per-asset result
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ClassificationResult:
    """
    Classification result for a single asset, with provenance.

    The `*_rule` fields record the description of the rule that fired,
    fulfilling PRD §6 (Explainability): the system can always answer
    "why is this classified as X?"
    """
    classification: AssetClassification
    sensitivity: SensitivityLevel
    business_criticality: BusinessCriticality
    lifecycle_stage: LifecycleStage

    classification_rule: str    # description of the matched rule
    sensitivity_rule: str
    criticality_rule: str


# ══════════════════════════════════════════════════════════════════════════════
# ClassificationEngine
# ══════════════════════════════════════════════════════════════════════════════

class ClassificationEngine:
    """
    Classification & Business Context Engine — PRD §5 stage 6.

    Runs after the Crypto Asset Inventory stage and before Reachability.
    Classifies every asset using config/classification_rules.yaml.

    Usage:
        engine = ClassificationEngine()
        assets = engine.process(assets)

    Every CryptoAsset returned by process() has its classification,
    sensitivity, business_criticality, and lifecycle_stage fields set.
    Original assets are NOT mutated (model_copy pattern).
    """

    def __init__(self, rules_path: Optional[Path] = None) -> None:
        self._config = load_classification_config(rules_path)

    @property
    def config(self) -> ClassificationConfig:
        return self._config

    def classify_asset(self, asset: CryptoAsset) -> ClassificationResult:
        """
        Classify a single CryptoAsset.

        Returns a ClassificationResult with full provenance.
        The three rule passes are run sequentially — criticality can
        condition on the classification already assigned.
        """
        # Pass 1: classification (application / infrastructure)
        cls_value, cls_rule = _apply_rules(
            self._config.classification_rules,
            self._config.classification_fallback,
            asset,
        )
        try:
            classification = AssetClassification(cls_value)
        except ValueError:
            logger.error(
                "Rule returned invalid AssetClassification '%s' — using fallback 'application'",
                cls_value,
            )
            classification = AssetClassification.APPLICATION
            cls_rule = f"ERROR: invalid value '{cls_value}' from rule, fell back"

        # Pass 2: sensitivity
        sens_value, sens_rule = _apply_rules(
            self._config.sensitivity_rules,
            self._config.sensitivity_fallback,
            asset,
        )
        try:
            sensitivity = SensitivityLevel(sens_value)
        except ValueError:
            logger.error(
                "Rule returned invalid SensitivityLevel '%s' — using fallback 'internal'",
                sens_value,
            )
            sensitivity = SensitivityLevel.INTERNAL
            sens_rule = f"ERROR: invalid value '{sens_value}' from rule, fell back"

        # Pass 3: criticality — can use the classification we just assigned
        crit_value, crit_rule = _apply_rules(
            self._config.criticality_rules,
            self._config.criticality_fallback,
            asset,
            assigned_classification=classification.value,
        )
        try:
            criticality = BusinessCriticality(crit_value)
        except ValueError:
            logger.error(
                "Rule returned invalid BusinessCriticality '%s' — using fallback 'low'",
                crit_value,
            )
            criticality = BusinessCriticality.LOW
            crit_rule = f"ERROR: invalid value '{crit_value}' from rule, fell back"

        # Pass 4: lifecycle
        lifecycle = _resolve_lifecycle(asset, self._config)

        return ClassificationResult(
            classification=classification,
            sensitivity=sensitivity,
            business_criticality=criticality,
            lifecycle_stage=lifecycle,
            classification_rule=cls_rule,
            sensitivity_rule=sens_rule,
            criticality_rule=crit_rule,
        )

    def process(self, assets: list[CryptoAsset]) -> list[CryptoAsset]:
        """
        Classify all assets in the list.

        Returns new CryptoAsset instances with classification fields updated.
        Original assets are NOT mutated.

        PRD §5 stage 6: "Tag each asset as application or infrastructure
        cryptography (TEC 910018:2025 taxonomy), with sensitivity, business
        criticality, and lifecycle stage."
        """
        result: list[CryptoAsset] = []
        infra_count = 0
        app_count = 0

        for asset in assets:
            cr = self.classify_asset(asset)

            updated = asset.model_copy(update={
                "classification": cr.classification,
                "sensitivity": cr.sensitivity,
                "business_criticality": cr.business_criticality,
                "lifecycle_stage": cr.lifecycle_stage,
            })
            result.append(updated)

            if cr.classification == AssetClassification.INFRASTRUCTURE:
                infra_count += 1
            else:
                app_count += 1

            logger.debug(
                "Classified %s @ %s: %s / %s / %s / %s  [cls: %s | sens: %s | crit: %s]",
                asset.algorithm, asset.location,
                cr.classification.value, cr.sensitivity.value,
                cr.business_criticality.value, cr.lifecycle_stage.value,
                cr.classification_rule[:60],
                cr.sensitivity_rule[:60],
                cr.criticality_rule[:60],
            )

        logger.info(
            "Classification complete: %d assets — %d application, %d infrastructure",
            len(assets), app_count, infra_count,
        )
        return result
