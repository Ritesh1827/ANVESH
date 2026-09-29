"""
LLM Client — PRD §5 stage 3b, step 4.

PRD §5 stage 3b requirement (fourth step):
  "LLM call (temperature = 0, versioned prompt)"

PRD §8 Technology Stack:
  "LLM enrichment: Claude/GPT API, temperature = 0, versioned prompts"

PRD §6 (Reproducibility):
  "LLM prompt versions must be tied to cache keys, so a prompt update
   never silently mixes old and new cached results."

Design decisions:
  - Temperature is ALWAYS forced to 0 — not configurable per call.
    This minimises non-determinism. Any code path that tries to pass
    a non-zero temperature will be overridden.
  - The prompt template is VERSIONED. The version string is embedded in
    the system prompt and is used as part of the Redis cache key.
  - The system prompt explicitly forbids the LLM from issuing security
    verdicts, risk scores, or recommendations (PRD §5 stage 3b + §6).
  - Provider abstraction: supports Anthropic Claude and OpenAI GPT.
    Provider is selected from env var LLM_PROVIDER.
  - The client returns raw text only. JSON parsing and schema validation
    are the responsibility of llm_validator.py — separation of concerns.

This module does NOT make the LLM call directly in tests — the
LLMClient.call() method is the only entry point that touches the network,
making it easy to mock in unit and integration tests.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ── Prompt versioning ─────────────────────────────────────────────────────────

# Increment PROMPT_VERSION whenever the system prompt changes.
# This version string is also used in the Redis cache key (via llm_cache.py),
# so changing it effectively invalidates all cached results for the old prompt.
PROMPT_VERSION = "v1"

# ── System prompt (versioned) ─────────────────────────────────────────────────
# This prompt is FIXED for this version. Do not modify without bumping PROMPT_VERSION.
# The prompt is deliberately narrow:
#   - Instructs the LLM to classify cryptographic PURPOSE only
#   - Explicitly forbids security verdicts, risk scores, recommendations
#   - Requires structured JSON output matching LLM_OUTPUT_SCHEMA
#   - References the schema version to tie prompt to schema

_SYSTEM_PROMPT_V1 = f"""You are a cryptographic code analysis assistant for ECDAT (version {PROMPT_VERSION}).

Your ONLY task is to classify the cryptographic PURPOSE of the provided code snippet.

STRICT RULES — violation of any rule means you must return purpose="unknown":
1. Return ONLY a JSON object. No prose, no markdown, no code blocks.
2. The JSON must contain exactly these fields:
   - "purpose": one of: key_establishment, digital_signature, encryption, hashing, mac, key_derivation, random_generation, certificate, unknown
   - "confidence": a float between 0.0 and 1.0
   - "algorithm_hint": (optional) the algorithm name if identifiable, or null
   - "context_notes": (optional) a brief explanation under 200 chars, or null
3. FORBIDDEN: do not include any field named risk, priority, recommendation, verdict, severity, urgency, score, mosca, hndl, or any variant.
4. FORBIDDEN: do not assess whether the algorithm is secure, quantum-safe, or vulnerable. That is not your job.
5. FORBIDDEN: do not recommend a replacement algorithm. That is not your job.
6. If you cannot determine the purpose with reasonable confidence, return purpose="unknown" with confidence=0.1.
7. Your role is classification only. Risk assessment and recommendations are handled by separate deterministic engines.

Example valid output:
{{"purpose": "hashing", "confidence": 0.85, "algorithm_hint": "SHA-256", "context_notes": "Function applies digest to input data before storage."}}

Example INVALID output (contains forbidden field):
{{"purpose": "hashing", "confidence": 0.85, "risk": "low"}}"""

# Map from PROMPT_VERSION to system prompt string.
# When a new prompt version is created, add it here.
PROMPT_REGISTRY: dict[str, str] = {
    "v1": _SYSTEM_PROMPT_V1,
}


def get_system_prompt(version: str = PROMPT_VERSION) -> str:
    """Return the system prompt for the given version."""
    if version not in PROMPT_REGISTRY:
        raise ValueError(
            f"Unknown prompt version '{version}'. "
            f"Available: {list(PROMPT_REGISTRY.keys())}"
        )
    return PROMPT_REGISTRY[version]


# ── Provider configuration ────────────────────────────────────────────────────

@dataclass
class LLMConfig:
    """
    LLM provider configuration loaded from environment variables.

    Provider-agnostic: LLM_PROVIDER names a registry entry in
    ecdat.llm.providers (currently "anthropic", "openai", "gemini").
    Adding a provider means registering it there — this class, the
    client, and every downstream step stay untouched.

    Environment variables:
      LLM_PROVIDER:    registry key (default: "anthropic")
      <PROVIDER>_API_KEY: per-provider key (ANTHROPIC_API_KEY,
        OPENAI_API_KEY, GEMINI_API_KEY)
      LLM_MODEL:       model identifier (default per provider)
      LLM_PROMPT_VERSION: override prompt version (default: PROMPT_VERSION)
    """
    provider: str
    api_key: str
    model: str
    prompt_version: str
    max_tokens: int = 256   # Short responses expected — JSON object only

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Load configuration from environment variables via the registry."""
        from ecdat.llm.providers import LLMProviderConfig

        resolved = LLMProviderConfig.from_env(PROMPT_VERSION)
        return cls(
            provider=resolved.provider,
            api_key=resolved.api_key,
            model=resolved.model,
            prompt_version=resolved.prompt_version,
        )

    @property
    def is_configured(self) -> bool:
        """Return True if an API key is available."""
        return bool(self.api_key)


# ── LLM Client ────────────────────────────────────────────────────────────────

class LLMClient:
    """
    LLM API client — thin wrapper around the provider SDK.

    Temperature is ALWAYS 0 (PRD §8). No caller can override this.
    The client returns raw text. Parsing and validation are separate.

    Usage:
        config = LLMConfig.from_env()
        client = LLMClient(config)
        raw_text = client.call(snippet)
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._prompt = get_system_prompt(config.prompt_version)

    @property
    def prompt_version(self) -> str:
        return self._config.prompt_version

    def call(self, scrubbed_stripped_snippet: str) -> Optional[str]:
        """
        Call the configured provider with the given (already scrubbed +
        stripped) snippet.

        Temperature is forced to 0 — non-negotiable per PRD §8.
        Returns the raw response text, or None on API error.

        The caller is responsible for passing only a scrubbed+stripped snippet.
        This method does NOT scrub or strip — that is the responsibility of
        the upstream pipeline steps.
        """
        if not self._config.is_configured:
            from ecdat.llm.providers import PROVIDERS

            env_var = PROVIDERS.get(self._config.provider).env_key_var \
                if self._config.provider in PROVIDERS else "API key"
            logger.error(
                "LLM API key not configured (LLM_PROVIDER=%s). "
                "Set %s in .env to enable LLM enrichment.",
                self._config.provider,
                env_var,
            )
            return None

        try:
            from ecdat.llm.providers import PROVIDERS

            spec = PROVIDERS.get(self._config.provider)
            if spec is None:
                logger.error("Unknown provider: %s", self._config.provider)
                return None
            # Only the underlying model call changes per provider: prompt,
            # temperature=0 contract, and raw-text return are uniform.
            return spec.caller(
                self._config.api_key,
                self._config.model,
                self._prompt,
                scrubbed_stripped_snippet,
                self._config.max_tokens,
            )
        except Exception as exc:
            logger.error("LLM API call failed: %s", exc)
            return None
