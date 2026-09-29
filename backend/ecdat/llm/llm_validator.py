"""
LLM Output Validator — PRD §5 stage 3b, step 5.

PRD §5 stage 3b requirement (fifth and final step):
  "JSON-schema validation of the output before it is accepted"

PRD §6:
  "All LLM output is constrained to structured JSON and validated against
   a schema before being merged into the inventory; malformed or
   out-of-schema output is rejected, not coerced."

This module is the hard gate between the LLM and the inventory.
No LLM output enters the pipeline without passing this validator.

Rejection behaviour (PRD mandate):
  - Malformed JSON → REJECT (return None, log error)
  - Schema violation → REJECT (return None, log specific violation)
  - Prohibited field present → REJECT (belt-and-suspenders check)
  - confidence out of [0.0, 1.0] → REJECT (schema enforces this)
  - purpose not in allowed enum → REJECT (schema enforces this)
  - Output too large (> 2KB) → REJECT (prevents context stuffing)

There is NO coercion path. If output is invalid, the finding is
dropped from LLM enrichment and the original UNKNOWN purpose is
preserved. This is explicitly better than accepting a wrong classification.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

import jsonschema
from jsonschema import validate, ValidationError

from ecdat.llm.llm_output_schema import (
    LLM_OUTPUT_SCHEMA,
    PROHIBITED_OUTPUT_FIELDS,
    SCHEMA_VERSION,
)

logger = logging.getLogger(__name__)

# Maximum raw LLM response size to accept (bytes)
_MAX_RESPONSE_BYTES = 2048

# Minimum confidence we trust the LLM's classification at all.
# Below this threshold the result is accepted but flagged as low-confidence.
MIN_ACCEPTABLE_CONFIDENCE = 0.4


@dataclass
class ValidationResult:
    """
    Result of validating a raw LLM output string.

    valid=True means the output passed ALL checks and is safe to use.
    valid=False means the output was REJECTED — reason is in error_message.
    """
    valid: bool
    parsed: Optional[dict]       # The parsed dict if valid; None if rejected
    error_message: Optional[str] # Rejection reason if not valid
    low_confidence: bool = False  # True when valid but confidence < threshold


def validate_llm_output(raw_output: str) -> ValidationResult:
    """
    Validate raw LLM output string against the ECDAT LLM output schema.

    PRD mandate: malformed or out-of-schema output is REJECTED, not coerced.

    Steps:
      1. Size check (prevent memory issues from huge responses)
      2. JSON parse (malformed JSON → reject)
      3. Prohibited field check (belt-and-suspenders for security verdict fields)
      4. JSON schema validation (purpose enum, confidence bounds, additionalProperties)
      5. Confidence threshold flag (warn but don't reject)

    Args:
        raw_output: The raw string returned by the LLM.

    Returns:
        ValidationResult with valid=True if all checks pass, False otherwise.
    """
    # ── Step 1: Size check ───────────────────────────────────────────────────
    if len(raw_output.encode("utf-8")) > _MAX_RESPONSE_BYTES:
        msg = (
            f"LLM response too large ({len(raw_output)} chars > "
            f"{_MAX_RESPONSE_BYTES} byte limit) — rejected"
        )
        logger.error(msg)
        return ValidationResult(valid=False, parsed=None, error_message=msg)

    # ── Step 2: JSON parse ────────────────────────────────────────────────────
    try:
        parsed = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        msg = f"LLM output is not valid JSON: {exc}"
        logger.error(msg)
        return ValidationResult(valid=False, parsed=None, error_message=msg)

    if not isinstance(parsed, dict):
        msg = f"LLM output is JSON but not an object (got {type(parsed).__name__})"
        logger.error(msg)
        return ValidationResult(valid=False, parsed=None, error_message=msg)

    # ── Step 3: Prohibited field check ────────────────────────────────────────
    # Belt-and-suspenders: explicitly reject any response containing fields
    # that express a security verdict, even if the schema were relaxed later.
    found_prohibited = set(parsed.keys()) & PROHIBITED_OUTPUT_FIELDS
    if found_prohibited:
        msg = (
            f"LLM output contains prohibited fields {found_prohibited} — "
            "the LLM attempted to issue a security verdict, which is forbidden. "
            "Output rejected per PRD §5 stage 3b and §6."
        )
        logger.error(msg)
        return ValidationResult(valid=False, parsed=None, error_message=msg)

    # ── Step 4: JSON schema validation ────────────────────────────────────────
    try:
        validate(instance=parsed, schema=LLM_OUTPUT_SCHEMA)
    except ValidationError as exc:
        msg = (
            f"LLM output failed schema validation "
            f"(schema {SCHEMA_VERSION}): {exc.message}"
        )
        logger.error(msg)
        return ValidationResult(valid=False, parsed=None, error_message=msg)

    # ── Step 5: Low-confidence flag ───────────────────────────────────────────
    confidence = parsed.get("confidence", 0.0)
    low_confidence = confidence < MIN_ACCEPTABLE_CONFIDENCE
    if low_confidence:
        logger.warning(
            "LLM output accepted but LOW confidence (%.2f < %.2f) — "
            "manual review recommended for this finding.",
            confidence, MIN_ACCEPTABLE_CONFIDENCE,
        )

    logger.debug(
        "LLM output validated OK: purpose='%s', confidence=%.2f",
        parsed.get("purpose"), confidence,
    )
    return ValidationResult(
        valid=True,
        parsed=parsed,
        error_message=None,
        low_confidence=low_confidence,
    )
