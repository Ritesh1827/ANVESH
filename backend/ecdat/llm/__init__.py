"""
ecdat.llm — LLM Enrichment Pipeline (PRD §5 stage 3b).

Pipeline order (PRD §5 stage 3b):
  secret scrubbing
  → prompt-injection stripping
  → Redis cache lookup (keyed by snippet_hash + prompt_version)
  → LLM call (temperature=0, versioned prompt)
  → JSON-schema validation gate
  → CryptoAsset annotation

The LLM is ONLY for ambiguous semantic classification.
The LLM MUST NEVER issue a final security verdict.
All LLM output MUST be schema-validated before acceptance.
Malformed or out-of-schema output MUST be rejected, not coerced.

Reference: PRD §5 stage 3b, §6 (non-functional requirements).
"""
