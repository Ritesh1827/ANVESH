"""
LLM Cache — PRD §5 stage 3b, step 3.

PRD §5 stage 3b requirement (third step):
  "cache lookup by snippet hash"

PRD §6 (Reproducibility):
  "LLM prompt versions must be tied to cache keys, so a prompt update
   never silently mixes old and new cached results."

Cache key design:
  SHA-256( scrubbed_snippet + "|" + prompt_version )

  The prompt_version component is MANDATORY. This prevents a prompt
  update from silently serving stale cached results from the old prompt.
  When the prompt changes, the version string changes, and all previously
  cached results for that snippet are effectively invalidated (new key).

  The snippet used in the key is the SCRUBBED snippet (post secret-scrubbing),
  not the raw snippet, so identical scrubbed snippets get the same cache entry
  even if their raw forms contained different but equivalent secrets.

Storage:
  Redis key:   "ecdat:llm:{cache_key}"
  Redis value: JSON string (the raw LLM response object)
  Redis TTL:   configurable, default 7 days

The cache is a performance optimisation. Cache misses are always safe
— the pipeline simply makes the LLM call. The cache MUST NOT be treated
as a fallback source of truth: if a cached entry is invalid JSON or fails
schema validation, it must be treated as a miss (not a source of truth).

This module has NO dependency on the LLM client or validator — it is a
pure cache layer that stores and retrieves raw JSON strings.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Default TTL for cache entries: 7 days (in seconds)
_DEFAULT_TTL_SECONDS = 7 * 24 * 3600

# Redis key prefix
_KEY_PREFIX = "ecdat:llm:"


def _build_cache_key(scrubbed_snippet: str, prompt_version: str) -> str:
    """
    Compute the Redis cache key for a (snippet, prompt_version) pair.

    Key format: SHA-256(scrubbed_snippet + "|" + prompt_version)
    The pipe separator prevents collisions between inputs where concatenation
    would otherwise be ambiguous.

    PRD §6: "prompt versions must be tied to cache keys."
    """
    raw = scrubbed_snippet + "|" + prompt_version
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return _KEY_PREFIX + digest


class LLMCache:
    """
    Redis-backed LLM response cache.

    Usage:
        cache = LLMCache(redis_client)
        hit = cache.get(snippet, prompt_version)
        if hit is None:
            response = call_llm(...)
            cache.set(snippet, prompt_version, response)
    """

    def __init__(
        self,
        redis_client,       # redis.Redis or redis.asyncio.Redis instance
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds

    def _key(self, scrubbed_snippet: str, prompt_version: str) -> str:
        return _build_cache_key(scrubbed_snippet, prompt_version)

    def get(
        self,
        scrubbed_snippet: str,
        prompt_version: str,
    ) -> Optional[dict]:
        """
        Look up a cached LLM response.

        Returns the parsed JSON dict if a valid cache entry exists,
        or None on miss, connection error, or invalid cached JSON.

        PRD guarantee: if the cached entry is not valid JSON, it is
        treated as a miss rather than raising an error.
        """
        key = self._key(scrubbed_snippet, prompt_version)
        try:
            raw = self._redis.get(key)
        except Exception as exc:
            logger.warning("Redis GET failed (treating as cache miss): %s", exc)
            return None

        if raw is None:
            return None

        try:
            result = json.loads(raw)
            logger.debug("Cache HIT for key %s", key[-8:])
            return result
        except json.JSONDecodeError:
            logger.warning(
                "Cached value for key %s is not valid JSON — treating as miss",
                key[-8:],
            )
            return None

    def set(
        self,
        scrubbed_snippet: str,
        prompt_version: str,
        response_dict: dict,
    ) -> bool:
        """
        Store a validated LLM response in the cache.

        The caller must pass a VALIDATED response dict — this method does
        not re-validate. Only call this after the schema validation gate passes.

        Returns True if stored successfully, False on error.
        """
        key = self._key(scrubbed_snippet, prompt_version)
        try:
            serialised = json.dumps(response_dict)
            self._redis.setex(key, self._ttl, serialised)
            logger.debug("Cache SET for key %s (TTL %ds)", key[-8:], self._ttl)
            return True
        except Exception as exc:
            logger.warning("Redis SET failed (continuing without cache): %s", exc)
            return False

    def delete(self, scrubbed_snippet: str, prompt_version: str) -> None:
        """Explicitly evict a cache entry (e.g. after schema changes)."""
        key = self._key(scrubbed_snippet, prompt_version)
        try:
            self._redis.delete(key)
        except Exception as exc:
            logger.warning("Redis DELETE failed: %s", exc)

    def is_connected(self) -> bool:
        """Quick connectivity check. Returns False if Redis is unavailable."""
        try:
            self._redis.ping()
            return True
        except Exception:
            return False


def make_cache_key(scrubbed_snippet: str, prompt_version: str) -> str:
    """
    Public helper to compute a cache key without a LLMCache instance.
    Useful for testing and introspection.
    """
    return _build_cache_key(scrubbed_snippet, prompt_version)
