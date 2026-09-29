"""
LLM Output Schema — the narrow contract for what the LLM may return.

PRD §5 stage 3b:
  "JSON-schema validation of the output before it is accepted"

PRD §6:
  "All LLM output is constrained to structured JSON and validated against
   a schema before being merged into the inventory; malformed or
   out-of-schema output is rejected, not coerced."

  "The LLM must never issue a final security verdict — only classification
   of ambiguous purpose/context."

The schema is NARROW by design. The LLM may only return:
  - purpose: one of the CryptoPurpose enum values
  - confidence: float in [0.0, 1.0]
  - algorithm_hint: optional string hint (advisory only)
  - context_notes: optional explanation (not a verdict)

PROHIBITED fields that the schema explicitly forbids:
  risk, priority, recommendation, verdict, severity, urgency, score,
  mosca, hndl — any field expressing a security decision.

These are exclusively the domain of the deterministic Mosca engine and
Recommendation engine. The schema validation gate enforces this boundary.

The schema is defined as a Python dict here (not a .json file) to keep
all Python code in .py files for easier import and tooling support.
The validator (llm_validator.py) imports this dict directly.
"""

# Version string embedded in the schema for traceability.
# Increment when the schema changes — this also changes cache keys
# (cache key = SHA-256(snippet + "|" + PROMPT_VERSION), and prompt
# version is tied to schema version per PRD §6 Reproducibility).
SCHEMA_VERSION = "v1"

# The JSON Schema defining the allowed LLM output structure.
LLM_OUTPUT_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": f"ecdat-llm-output-{SCHEMA_VERSION}",
    "title": "ECDAT LLM Enrichment Output",
    "description": (
        "Schema for LLM classification of ambiguous cryptographic code snippets. "
        "The LLM may ONLY classify cryptographic purpose and context. "
        "It may NOT issue security verdicts, risk scores, or recommendations."
    ),
    "type": "object",
    "required": ["purpose", "confidence"],
    "additionalProperties": False,
    "properties": {
        "purpose": {
            "type": "string",
            "enum": [
                "key_establishment",
                "digital_signature",
                "encryption",
                "hashing",
                "mac",
                "key_derivation",
                "random_generation",
                "certificate",
                "unknown",
            ],
            "description": (
                "The cryptographic purpose classified by the LLM. "
                "Must be one of the CryptoPurpose enum values. "
                "The LLM classifies PURPOSE ONLY — not risk, priority, or recommendation."
            ),
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
            "description": "LLM confidence in its purpose classification. Range [0.0, 1.0].",
        },
        "algorithm_hint": {
            "type": ["string", "null"],
            "description": (
                "Optional: algorithm hint from the LLM. Advisory only. "
                "Must be validated before use."
            ),
            "maxLength": 100,
        },
        "context_notes": {
            "type": ["string", "null"],
            "description": (
                "Optional: LLM explanation of its classification. "
                "Must NOT contain security verdicts or recommendations. "
                "Max 500 chars."
            ),
            "maxLength": 500,
        },
    },
}

# Explicit list of prohibited field names — used by the validator for
# a belt-and-suspenders check even when additionalProperties=False
# (in case a future schema relaxation inadvertently allows them).
PROHIBITED_OUTPUT_FIELDS: frozenset[str] = frozenset({
    "risk", "priority", "recommendation", "verdict",
    "severity", "urgency", "score", "mosca", "hndl",
    "p1", "p2", "p3", "p4",  # priority level shortcuts
})
