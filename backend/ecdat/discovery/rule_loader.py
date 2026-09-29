"""
Rule loader — loads and validates detection_rules.yaml into typed dataclasses.

The rule configuration is the single source of truth for what patterns the
discovery engine detects. No algorithm mappings live here — only structural
pattern descriptions (what AST shape to look for, with what confidence).

Reference: PRD §8 — "Keeps algorithm-to-PQC mappings as editable data".
           config/detection_rules.yaml is the authoritative rule file.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from ecdat.schemas import CryptoPurpose

logger = logging.getLogger(__name__)

# Default path — resolved relative to this file's location so it works
# regardless of working directory.
_DEFAULT_RULES_PATH = (
    Path(__file__).parent.parent.parent.parent / "config" / "detection_rules.yaml"
)


@dataclass(frozen=True)
class MatchSpec:
    """
    Structural match specification for a detection rule.

    Depending on match_type:
      call_chain:    module (optional) + function name must appear as a call
      call_with_arg: function called with a specific string literal argument
      c_symbol:      any bare C identifier occurrence (function call,
                     macro use, NID/OBJ constant, dispatch-table reference).
                     Used for OpenSSL-style code where the evidence is a
                     symbol, not necessarily a direct call.
    """
    function: str
    module: Optional[str] = None           # e.g. "hashlib", "RSA", "ec"
    arg_index: Optional[int] = None        # positional arg index for call_with_arg
    arg_values: list[str] = field(default_factory=list)  # expected string literal values
    kwarg_name: Optional[str] = None       # keyword arg name for key extraction
    symbol_kind: Optional[str] = None      # c_symbol only: call | macro | constant | any


@dataclass(frozen=True)
class KeySizeExtraction:
    """Spec for extracting a key size from a function call argument."""
    arg_index: Optional[int] = None    # positional arg index
    kwarg_name: Optional[str] = None   # keyword arg name (alternative to positional)
    arg_type: str = "integer"          # "integer" only for now


@dataclass(frozen=True)
class DetectionRule:
    """
    A single loaded and validated detection rule.

    Immutable once loaded — the rule set does not change at runtime.
    """
    rule_id: str
    description: str
    algorithm: str
    purpose: str                    # must be a valid CryptoPurpose enum value
    confidence: float               # base confidence [0.0, 1.0]
    severity: str                   # advisory severity hint
    languages: list[str]            # e.g. ["python"], ["java", "kotlin"]
    match_type: str                 # "call_chain" | "call_with_arg"
    match: MatchSpec
    key_size_bits: Optional[int] = None
    key_size_extraction: Optional[KeySizeExtraction] = None
    notes: Optional[str] = None


def load_rules(rules_path: Optional[Path] = None) -> list[DetectionRule]:
    """
    Load and validate detection rules from YAML.

    Args:
        rules_path: Path to the rules YAML file. Defaults to
                    config/detection_rules.yaml relative to the repo root.

    Returns:
        List of validated DetectionRule objects.

    Raises:
        FileNotFoundError: If the rules file does not exist.
        ValueError: If the YAML structure is invalid.
    """
    path = Path(rules_path) if rules_path else _DEFAULT_RULES_PATH

    if not path.exists():
        raise FileNotFoundError(
            f"Detection rules file not found: {path}\n"
            f"Expected at: {_DEFAULT_RULES_PATH}"
        )

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict) or "rules" not in raw:
        raise ValueError(f"Invalid rules file — expected top-level 'rules' key: {path}")

    rules: list[DetectionRule] = []
    seen_ids: set[str] = set()

    for i, entry in enumerate(raw["rules"]):
        rule_id = entry.get("rule_id", f"UNKNOWN-{i}")

        if rule_id in seen_ids:
            raise ValueError(f"Duplicate rule_id '{rule_id}' in {path}")
        seen_ids.add(rule_id)

        # Validate required fields
        for required in ("rule_id", "description", "algorithm", "purpose",
                         "confidence", "languages", "match_type", "match"):
            if required not in entry:
                raise ValueError(f"Rule {rule_id} is missing required field '{required}'")

        confidence = float(entry["confidence"])
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(
                f"Rule {rule_id}: confidence {confidence} is outside [0.0, 1.0]"
            )

        match_type = entry["match_type"]
        if match_type not in ("call_chain", "call_with_arg", "c_symbol"):
            raise ValueError(
                f"Rule {rule_id}: unknown match_type '{match_type}'. "
                f"Expected 'call_chain', 'call_with_arg', or 'c_symbol'."
            )

        # Validate purpose (unknown allowed — feeds LLM enrichment, Phase 3)
        try:
            CryptoPurpose(entry["purpose"])
        except ValueError:
            raise ValueError(
                f"Rule {rule_id}: unknown purpose '{entry['purpose']}'. "
                f"Must be a CryptoPurpose enum value."
            ) from None

        # Build MatchSpec
        m = entry["match"]
        if "function" not in m:
            raise ValueError(f"Rule {rule_id}: match spec missing 'function'")
        match_spec = MatchSpec(
            function=m["function"],
            module=m.get("module"),
            arg_index=m.get("arg_index"),
            arg_values=list(m.get("arg_values", [])),
            kwarg_name=m.get("kwarg_name"),
            symbol_kind=m.get("symbol_kind"),
        )

        # Build KeySizeExtraction if present
        kse_raw = entry.get("key_size_extraction")
        kse: Optional[KeySizeExtraction] = None
        if kse_raw:
            kse = KeySizeExtraction(
                arg_index=kse_raw.get("arg_index"),
                kwarg_name=kse_raw.get("kwarg_name"),
                arg_type=kse_raw.get("arg_type", "integer"),
            )

        rules.append(DetectionRule(
            rule_id=rule_id,
            description=entry["description"],
            algorithm=entry["algorithm"],
            purpose=entry["purpose"],
            confidence=confidence,
            severity=entry.get("severity", "info"),
            languages=[lang.lower() for lang in entry["languages"]],
            match_type=match_type,
            match=match_spec,
            key_size_bits=entry.get("key_size_bits"),
            key_size_extraction=kse,
            notes=entry.get("notes"),
        ))

    logger.info("Loaded %d detection rules from %s", len(rules), path)
    return rules


def rules_for_language(rules: list[DetectionRule], language: str) -> list[DetectionRule]:
    """Return only rules applicable to the given language."""
    lang = language.lower()
    return [r for r in rules if lang in r.languages]
