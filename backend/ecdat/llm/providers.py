"""LLM provider registry — swappable model backends behind one interface.

Adding a new provider means registering one entry here (name → config
keys + caller) and nothing else. No caller conditions on provider names:
`LLMConfig.from_env()` reads LLM_PROVIDER, looks it up in PROVIDERS, and
`LLMClient.call()` dispatches through the registered caller. The prompt,
temperature=0 contract, schema validation, and caching layers above this
module never see which provider served the call.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ── Retry policy for rate limits ─────────────────────────────────────────────

# 429 / quota / overloaded responses degrade per snippet, never per scan:
# bounded retries with exponential backoff, then None (the enrichment
# orchestrator keeps the UNKNOWN purpose — see llm_enrichment.py).
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 2.0

_RETRY_MARKERS = (
    "429", "rate limit", "rate-limit", "ratelimit", "quota",
    "resource_exhausted", "resource exhausted", "overloaded", "overload",
    "too many requests", "retry", "temporarily unavailable", "timeout",
    "timed out", "deadline", "service unavailable", "503", "500",
)

_AUTH_FAILURE_MARKERS = (
    "api key", "apikey", "api-key", "unauthorized", "unauthenticated",
    "permission denied", "forbidden", "invalid key", "401", "403",
)


def _is_auth_failure(message: str) -> bool:
    """Auth failures must fail fast — retrying never helps."""
    lowered = message.lower()
    return any(marker in lowered for marker in _AUTH_FAILURE_MARKERS)


def _is_retryable(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _RETRY_MARKERS)


_MODEL_FAMILY_MARKERS: dict[str, tuple[str, ...]] = {
    "anthropic": ("claude",),
    "openai": ("gpt-", "o1", "o3", "o4"),
    "gemini": ("gemini",),
}


def _model_belongs_to_provider(model: str, provider: str) -> bool:
    """Guard against a stale cross-provider LLM_MODEL override."""
    lowered = model.lower()
    markers = _MODEL_FAMILY_MARKERS.get(provider, ())
    return any(marker in lowered for marker in markers)


def call_with_backoff(
    name: str, func: Callable[[], Optional[str]]
) -> Optional[str]:
    """Call func with bounded retry on rate-limit/transient errors."""
    last_error: Optional[str] = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return func()
        except Exception as exc:  # noqa: BLE001 — classified below
            last_error = str(exc)[:300]
            if _is_auth_failure(last_error):
                logger.error("%s auth failure (not retried): %s", name, last_error)
                return None
            if not _is_retryable(last_error) or attempt == MAX_ATTEMPTS:
                logger.error("%s call failed (attempt %d/%d): %s",
                             name, attempt, MAX_ATTEMPTS, last_error)
                return None
            delay = BACKOFF_BASE_S * (2 ** (attempt - 1))
            logger.warning("%s throttled (attempt %d/%d) — retrying in %.1fs: %s",
                           name, attempt, MAX_ATTEMPTS, delay, last_error)
            time.sleep(delay)
    logger.error("%s call failed after %d attempts: %s",
                 name, MAX_ATTEMPTS, last_error)
    return None


# ── Provider registry ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProviderSpec:
    """How to configure and call one LLM provider."""

    name: str
    env_key_var: str          # env var holding the API key
    default_model: str        # fast/cheap default for classification tasks
    caller: Callable[[str, str, str, str, int], Optional[str]]
    # caller(api_key, model, system_prompt, snippet, max_tokens) -> raw text|None


def _call_anthropic(api_key: str, model: str, prompt: str,
                    snippet: str, max_tokens: int) -> Optional[str]:
    try:
        import anthropic
    except ImportError:
        logger.error("anthropic package not installed. Install with: pip install anthropic")
        return None
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0,
        system=prompt,
        messages=[{"role": "user", "content": f"Classify this code snippet:\n\n{snippet}"}],
    )
    text = message.content[0].text if message.content else None
    logger.debug("Anthropic response (%d chars)", len(text or ""))
    return text


def _call_openai(api_key: str, model: str, prompt: str,
                 snippet: str, max_tokens: int) -> Optional[str]:
    try:
        from openai import OpenAI
    except ImportError:
        logger.error("openai package not installed. Install with: pip install openai")
        return None
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"Classify this code snippet:\n\n{snippet}"},
        ],
    )
    text = response.choices[0].message.content if response.choices else None
    logger.debug("OpenAI response (%d chars)", len(text or ""))
    return text


def _call_gemini(api_key: str, model: str, prompt: str,
                 snippet: str, max_tokens: int) -> Optional[str]:
    """Call Gemini with deterministic JSON output and crypto-safe filters.

    Safety: ECDAT's input domain IS weak/vulnerable crypto, exploits, and
    security terminology. The Dangerous-content filter would otherwise flag
    exactly the snippets we must classify, so all four adjustable
    categories are set to BLOCK_NONE. This is legitimate use, not evasion:
    the model only returns a purpose label from a closed enum — it cannot
    emit exploits, instructions, or verdicts, and the schema validator
    rejects anything outside that contract. Non-adjustable core-harm
    protections (e.g. child safety) stay on — BLOCK_NONE cannot disable
    them.
    """
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        logger.error(
            "google-genai package not installed. Install with: pip install google-genai")
        return None

    def _once() -> Optional[str]:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model,
            contents=f"Classify this code snippet:\n\n{snippet}",
            config=types.GenerateContentConfig(
                system_instruction=prompt,
                temperature=0.0,
                max_output_tokens=max_tokens,
                response_mime_type="application/json",
                safety_settings=[
                    types.SafetySetting(
                        category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                        threshold=types.HarmBlockThreshold.BLOCK_NONE,
                    ),
                    types.SafetySetting(
                        category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                        threshold=types.HarmBlockThreshold.BLOCK_NONE,
                    ),
                    types.SafetySetting(
                        category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                        threshold=types.HarmBlockThreshold.BLOCK_NONE,
                    ),
                    types.SafetySetting(
                        category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                        threshold=types.HarmBlockThreshold.BLOCK_NONE,
                    ),
                ],
            ),
        )
        text = (response.text or "").strip()
        if not text:
            finish = getattr(response.candidates[0], "finish_reason", None) \
                if response.candidates else None
            raise RuntimeError(f"Gemini returned no text (finish_reason={finish})")
        logger.debug("Gemini response (%d chars)", len(text))
        return text

    return call_with_backoff("gemini", _once)


PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        name="anthropic",
        env_key_var="ANTHROPIC_API_KEY",
        default_model="claude-3-5-sonnet-20241022",
        caller=_call_anthropic,
    ),
    "openai": ProviderSpec(
        name="openai",
        env_key_var="OPENAI_API_KEY",
        default_model="gpt-4o-mini",
        caller=_call_openai,
    ),
    "gemini": ProviderSpec(
        name="gemini",
        env_key_var="GEMINI_API_KEY",
        default_model="gemini-3.1-flash-lite",
        caller=_call_gemini,
    ),
}


@dataclass
class LLMProviderConfig:
    """Resolved provider configuration (registry-backed)."""

    provider: str
    api_key: str
    model: str
    prompt_version: str
    max_tokens: int = 256
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls, prompt_version: str) -> "LLMProviderConfig":
        provider = os.environ.get("LLM_PROVIDER", "anthropic").lower().strip()
        spec = PROVIDERS.get(provider)
        if spec is None:
            raise ValueError(
                f"Unknown LLM_PROVIDER '{provider}'. "
                f"Available: {sorted(PROVIDERS)}."
            )
        # LLM_MODEL is namespaced per provider in practice: a stale model
        # from another provider (e.g. a Claude id while on gemini) would
        # otherwise produce a confusing 404 from the wrong API. Fall back
        # to the provider default unless the override names this family.
        model_override = os.environ.get("LLM_MODEL", "").strip()
        model = spec.default_model
        if model_override and _model_belongs_to_provider(model_override, provider):
            model = model_override
        elif model_override:
            logger.warning(
                "Ignoring LLM_MODEL=%r: not a %s model — using default %r.",
                model_override, provider, spec.default_model,
            )
        return cls(
            provider=provider,
            api_key=os.environ.get(spec.env_key_var, ""),
            model=model,
            prompt_version=prompt_version,
        )

    @property
    def spec(self) -> ProviderSpec:
        return PROVIDERS[self.provider]

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def call(self, system_prompt: str, snippet: str) -> Optional[str]:
        if not self.is_configured:
            logger.error(
                "LLM API key not configured (LLM_PROVIDER=%s). Set %s to enable.",
                self.provider, self.spec.env_key_var,
            )
            return None
        try:
            return self.spec.caller(
                self.api_key, self.model, system_prompt, snippet, self.max_tokens)
        except Exception as exc:  # noqa: BLE001 — per-snippet degradation
            logger.error("LLM API call failed: %s", exc)
            return None
