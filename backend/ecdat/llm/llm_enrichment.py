"""
LLM Enrichment Orchestrator — PRD §5 stage 3b.

Implements the complete LLM enrichment pipeline in the exact order
mandated by PRD §5 stage 3b:

  1. secret scrubbing         (secret_scrubber.py)
  2. prompt-injection stripping (prompt_injection_stripper.py)
  3. cache lookup              (llm_cache.py)
  4. LLM call                  (llm_client.py)  [only on cache miss]
  5. JSON-schema validation    (llm_validator.py)
  6. CryptoAsset annotation    (this module)

PRD constraints enforced here:
  - LLM is ONLY invoked for ambiguous findings (purpose == CryptoPurpose.UNKNOWN)
  - LLM NEVER issues a final security verdict (enforced by schema + validator)
  - Deterministic findings bypass LLM entirely (PRD §5 stage 3a)
  - LLM output that fails validation is REJECTED — the finding retains
    UNKNOWN purpose rather than receiving an unvalidated classification
  - All LLM-annotated assets carry finding_type=LLM_ENRICHED and
    llm_prompt_version in the Evidence record (PRD §6 Reproducibility)

Grace-degradation: every failure mode in this pipeline degrades gracefully:
  - Redis unavailable      → treat as cache miss, continue
  - LLM API unavailable    → return original asset unchanged
  - LLM validation failure → return original asset unchanged
  - Any unexpected error   → return original asset unchanged

The original asset is NEVER mutated. All updates use model_copy().
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ecdat.schemas import (
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    SourceLocation,
)
from ecdat.llm.secret_scrubber import scrub_snippet
from ecdat.llm.prompt_injection_stripper import strip_prompt_injection
from ecdat.llm.llm_cache import LLMCache
from ecdat.llm.llm_client import LLMClient, LLMConfig, PROMPT_VERSION
from ecdat.llm.llm_validator import validate_llm_output

logger = logging.getLogger(__name__)


# ── Enrichment result ─────────────────────────────────────────────────────────

@dataclass
class EnrichmentResult:
    """
    Result of attempting LLM enrichment on a single asset.

    The asset field is always populated — either with the enriched version
    (if enrichment succeeded) or the original (if it was skipped or failed).
    """
    asset: CryptoAsset
    enriched: bool           # True if LLM successfully classified the purpose
    cache_hit: bool          # True if the result came from Redis cache
    skipped: bool            # True if LLM was not invoked (deterministic finding)
    failure_reason: Optional[str]  # Non-None if enrichment was attempted but failed


# ── Ambiguity detection ────────────────────────────────────────────────────────

def _is_ambiguous(asset: CryptoAsset) -> bool:
    """
    Determine whether an asset requires LLM enrichment.

    PRD §5 stage 3a/3b: only AMBIGUOUS findings go through LLM enrichment.
    An asset is ambiguous when:
      - Its purpose is UNKNOWN (deterministic rules could not classify it), AND
      - Its finding_type is DETERMINISTIC (not already LLM-enriched), AND
      - It has a snippet to send to the LLM

    Deterministic findings with a known purpose NEVER go through the LLM.
    This preserves PRD §6 "Determinism first" — the deterministic engine
    is always the primary source of truth.
    """
    return (
        asset.purpose == CryptoPurpose.UNKNOWN and
        asset.evidence.finding_type == FindingType.DETERMINISTIC and
        bool(asset.evidence.location.snippet)
    )


# ── Evidence update ────────────────────────────────────────────────────────────

def _build_enriched_evidence(
    original_evidence: Evidence,
    prompt_version: str,
    llm_model: str,
    new_confidence: float,
) -> Evidence:
    """
    Build a new Evidence record marking this finding as LLM-enriched.

    PRD §6 (Reproducibility): the llm_prompt_version field ties the result
    to the specific prompt version used, so cache keys and audit trails
    are consistent.
    """
    return Evidence(
        detection_method=DetectionMethod.LLM_ENRICHMENT,
        finding_type=FindingType.LLM_ENRICHED,
        rule_id=original_evidence.rule_id,
        location=original_evidence.location,
        source_surface=original_evidence.source_surface,
        confidence=round(min(1.0, max(0.0, new_confidence)), 4),
        llm_prompt_version=prompt_version,
        llm_model=llm_model,
        notes=original_evidence.notes,
    )


# ── Core enrichment function ──────────────────────────────────────────────────

def enrich_asset(
    asset: CryptoAsset,
    llm_client: LLMClient,
    cache: Optional[LLMCache] = None,
) -> EnrichmentResult:
    """
    Attempt LLM enrichment on a single CryptoAsset.

    If the asset is not ambiguous (known purpose), returns it unchanged.
    If LLM enrichment fails at any step, returns the original asset unchanged.
    Original asset is NEVER mutated.

    Args:
        asset:       The CryptoAsset to potentially enrich.
        llm_client:  Configured LLM client.
        cache:       Optional Redis cache. None means no caching.

    Returns:
        EnrichmentResult with the final asset and metadata about what happened.
    """
    # ── Gate: skip non-ambiguous findings ─────────────────────────────────────
    if not _is_ambiguous(asset):
        return EnrichmentResult(
            asset=asset,
            enriched=False,
            cache_hit=False,
            skipped=True,
            failure_reason=None,
        )

    snippet = asset.evidence.location.snippet or ""
    prompt_version = llm_client.prompt_version

    # ── Step 1: Secret scrubbing ──────────────────────────────────────────────
    scrub_result = scrub_snippet(snippet)
    if scrub_result.redactions:
        logger.info(
            "Scrubbed %d secret(s) from snippet for %s @ %s",
            len(scrub_result.redactions), asset.algorithm, asset.location,
        )
    safe_snippet = scrub_result.scrubbed

    # ── Step 2: Prompt-injection stripping ────────────────────────────────────
    strip_result = strip_prompt_injection(safe_snippet)
    if strip_result.injections_found:
        logger.warning(
            "Stripped %d injection pattern(s) from snippet for %s @ %s",
            len(strip_result.injections_found), asset.algorithm, asset.location,
        )
    clean_snippet = strip_result.stripped

    # ── Step 3: Cache lookup ──────────────────────────────────────────────────
    cached_response: Optional[dict] = None
    if cache is not None:
        cached_response = cache.get(clean_snippet, prompt_version)
        if cached_response is not None:
            logger.debug(
                "LLM cache HIT for %s @ %s (prompt=%s)",
                asset.algorithm, asset.location, prompt_version,
            )
            # Re-validate the cached response (defensive — schema may have changed)
            validation = validate_llm_output(
                __import__("json").dumps(cached_response)
            )
            if not validation.valid:
                logger.warning(
                    "Cached LLM response failed re-validation — treating as miss: %s",
                    validation.error_message,
                )
                cached_response = None

    # ── Step 4: LLM call (only on cache miss) ─────────────────────────────────
    raw_response: Optional[str] = None
    if cached_response is None:
        raw_response = llm_client.call(clean_snippet)
        if raw_response is None:
            logger.warning(
                "LLM call returned None for %s @ %s — keeping UNKNOWN purpose",
                asset.algorithm, asset.location,
            )
            return EnrichmentResult(
                asset=asset,
                enriched=False,
                cache_hit=False,
                skipped=False,
                failure_reason="LLM call returned no response",
            )

    # ── Step 5: JSON-schema validation ────────────────────────────────────────
    import json as _json

    if cached_response is not None:
        # Already validated above; use directly
        validated = cached_response
        is_cache_hit = True
    else:
        validation = validate_llm_output(raw_response)
        if not validation.valid:
            logger.error(
                "LLM output rejected by validator for %s @ %s: %s",
                asset.algorithm, asset.location, validation.error_message,
            )
            return EnrichmentResult(
                asset=asset,
                enriched=False,
                cache_hit=False,
                skipped=False,
                failure_reason=f"Validation failed: {validation.error_message}",
            )
        validated = validation.parsed
        is_cache_hit = False

        # Store validated response in cache for future calls
        if cache is not None:
            cache.set(clean_snippet, prompt_version, validated)

    # ── Step 6: Annotate the asset ────────────────────────────────────────────
    new_purpose_str = validated["purpose"]
    new_confidence = float(validated.get("confidence", 0.5))
    algorithm_hint = validated.get("algorithm_hint")

    # Convert purpose string to enum (validated already confirmed it's in the enum)
    try:
        new_purpose = CryptoPurpose(new_purpose_str)
    except ValueError:
        # Should be impossible after schema validation, but be defensive
        logger.error("Validated purpose '%s' is not a valid CryptoPurpose", new_purpose_str)
        return EnrichmentResult(
            asset=asset,
            enriched=False,
            cache_hit=is_cache_hit,
            skipped=False,
            failure_reason=f"Invalid purpose value after validation: {new_purpose_str}",
        )

    # Build new evidence record with LLM provenance
    new_evidence = _build_enriched_evidence(
        original_evidence=asset.evidence,
        prompt_version=prompt_version,
        llm_model=llm_client._config.model,
        new_confidence=new_confidence,
    )

    # Build update dict — only purpose, evidence, and optionally algorithm_hint
    updates: dict = {
        "purpose": new_purpose,
        "evidence": new_evidence,
    }

    # Apply algorithm hint if provided and asset has no extracted key size
    if algorithm_hint and not asset.algorithm:
        updates["algorithm"] = algorithm_hint

    enriched_asset = asset.model_copy(update=updates)

    logger.info(
        "LLM enrichment: %s @ %s → purpose=%s (confidence=%.2f, cache=%s)",
        asset.algorithm, asset.location,
        new_purpose.value, new_confidence, is_cache_hit,
    )

    return EnrichmentResult(
        asset=enriched_asset,
        enriched=True,
        cache_hit=is_cache_hit,
        skipped=False,
        failure_reason=None,
    )


# ── Batch processing ──────────────────────────────────────────────────────────

@dataclass
class BatchEnrichmentStats:
    """Statistics from a batch enrichment run."""
    total: int = 0
    skipped_deterministic: int = 0
    enriched: int = 0
    cache_hits: int = 0
    failed: int = 0

    @property
    def ambiguous_attempted(self) -> int:
        return self.enriched + self.failed

    @property
    def success_rate(self) -> float:
        if self.ambiguous_attempted == 0:
            return 1.0
        return round(self.enriched / self.ambiguous_attempted, 4)


class LLMEnrichmentEngine:
    """
    LLM Enrichment Engine — PRD §5 stage 3b.

    Processes a list of CryptoAssets and enriches ambiguous findings
    through the safeguarded LLM pipeline.

    Usage:
        engine = LLMEnrichmentEngine.from_env()
        assets = engine.process(assets)
        print(engine.stats)

    Deterministic assets pass through unchanged (PRD §5 stage 3a/3b).
    Only assets with purpose=UNKNOWN are sent to the LLM.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        cache: Optional[LLMCache] = None,
    ) -> None:
        self._client = llm_client
        self._cache = cache
        self._stats = BatchEnrichmentStats()

    @classmethod
    def from_env(cls, redis_client=None) -> "LLMEnrichmentEngine":
        """
        Construct from environment variables.

        Args:
            redis_client: Optional Redis client. If None, cache is disabled.
        """
        config = LLMConfig.from_env()
        client = LLMClient(config)
        cache = LLMCache(redis_client) if redis_client is not None else None
        return cls(llm_client=client, cache=cache)

    @property
    def stats(self) -> BatchEnrichmentStats:
        return self._stats

    def process(self, assets: list[CryptoAsset]) -> list[CryptoAsset]:
        """
        Enrich ambiguous assets through the LLM pipeline.

        Deterministic assets are passed through unchanged.
        Returns the complete list with ambiguous assets enriched where possible.
        """
        self._stats = BatchEnrichmentStats()
        result: list[CryptoAsset] = []

        for asset in assets:
            self._stats.total += 1
            enrichment = enrich_asset(asset, self._client, self._cache)

            if enrichment.skipped:
                self._stats.skipped_deterministic += 1
            elif enrichment.enriched:
                self._stats.enriched += 1
                if enrichment.cache_hit:
                    self._stats.cache_hits += 1
            else:
                self._stats.failed += 1

            result.append(enrichment.asset)

        logger.info(
            "LLM enrichment batch: %d total — %d deterministic (skipped), "
            "%d ambiguous: %d enriched (%d cache hits), %d failed",
            self._stats.total,
            self._stats.skipped_deterministic,
            self._stats.ambiguous_attempted,
            self._stats.enriched,
            self._stats.cache_hits,
            self._stats.failed,
        )
        return result
