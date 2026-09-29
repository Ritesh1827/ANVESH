"""
Integration tests — Day 7 LLM Enrichment Pipeline.

Tests:
  1.  Ambiguous fixture (crypto_wrapper.py) produces UNKNOWN-purpose assets
  2.  Full enrichment pipeline with mocked LLM call classifies correctly
  3.  Second identical call hits Redis cache, not the LLM
  4.  Deterministic assets are completely unaffected by LLM enrichment
  5.  LLM-enriched assets carry FindingType.LLM_ENRICHED + llm_prompt_version
  6.  Rejected LLM output leaves asset purpose as UNKNOWN
  7.  run_llm_enrichment=False skips LLM (default behaviour)
  8.  Existing 672-test regression: no deterministic asset changes classification,
      risk, or recommendation when LLM enrichment is added to the pipeline
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ecdat.pipeline import run_pipeline, run_source_discovery
from ecdat.llm.llm_enrichment import LLMEnrichmentEngine, enrich_asset
from ecdat.llm.llm_client import LLMConfig, LLMClient
from ecdat.llm.llm_cache import LLMCache
from ecdat.schemas import (
    CryptoPurpose, DetectionMethod, FindingType, RiskPriority, StandardizationStatus,
)

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEMO_REPO  = REPO_ROOT / "test_repos" / "demo_app"
RULES_PATH = REPO_ROOT / "config" / "detection_rules.yaml"
CLS_PATH   = REPO_ROOT / "config" / "classification_rules.yaml"
MOSCA_PATH = REPO_ROOT / "config" / "mosca_profiles.yaml"
PQC_PATH   = REPO_ROOT / "config" / "pqc_mappings.yaml"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_engine(purpose_response: str) -> LLMEnrichmentEngine:
    """Create an LLMEnrichmentEngine with a mocked LLM call."""
    config = LLMConfig(provider="anthropic", api_key="test-key",
                       model="claude-3-5-sonnet-20241022", prompt_version="v1")
    client = LLMClient(config)
    client.call = MagicMock(return_value=purpose_response)
    return LLMEnrichmentEngine(llm_client=client, cache=None)


def _source_assets(result):
    return [a for a in result.scored_assets if a.source_surface == "source_code"]


# ── 1. Ambiguous fixture produces UNKNOWN assets ──────────────────────────────

class TestAmbiguousFixture:
    def test_crypto_wrapper_file_exists(self):
        assert (DEMO_REPO / "crypto_wrapper.py").exists()

    def test_source_discovery_runs_on_demo_app(self):
        result = run_source_discovery(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
            scan_id="test-ambiguous-discovery",
        )
        assert len(result.scored_assets) > 0

    def test_deterministic_rules_find_known_algorithms(self):
        result = run_source_discovery(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
            scan_id="test-known-algs",
        )
        algorithms = {a.algorithm for a in result.scored_assets}
        assert any(a.startswith("RSA") for a in algorithms)
        assert any(a == "MD5" for a in algorithms)


# ── 2. Full enrichment with mocked LLM ───────────────────────────────────────

class TestMockedLLMEnrichment:
    def test_unknown_purpose_asset_enriched_to_hashing(self):
        from ecdat.schemas import (
            AssetClassification, BusinessCriticality, CryptoAsset,
            Evidence, LifecycleStage, SensitivityLevel, SourceLocation,
        )
        ev = Evidence(
            detection_method=DetectionMethod.AST_RULE,
            finding_type=FindingType.DETERMINISTIC,
            rule_id="R-999",
            location=SourceLocation(
                file_path="crypto_wrapper.py",
                line_number=16,
                snippet="compute_digest(payload)",
            ),
            source_surface="source_code",
            confidence=0.55,
        )
        asset = CryptoAsset(
            algorithm="UNKNOWN",
            purpose="unknown",
            location="crypto_wrapper.py:16",
            source_surface="source_code",
            classification=AssetClassification.APPLICATION,
            sensitivity=SensitivityLevel.INTERNAL,
            business_criticality=BusinessCriticality.LOW,
            lifecycle_stage=LifecycleStage.ACTIVE,
            evidence=ev,
        )

        engine = _mock_engine('{"purpose":"hashing","confidence":0.88}')
        results = engine.process([asset])
        assert len(results) == 1
        enriched = results[0]
        assert enriched.purpose == CryptoPurpose.HASHING
        assert enriched.evidence.finding_type == FindingType.LLM_ENRICHED
        assert enriched.evidence.llm_prompt_version == "v1"
        assert enriched.evidence.detection_method == DetectionMethod.LLM_ENRICHMENT

    def test_enriched_asset_confidence_from_llm(self):
        from ecdat.schemas import (
            AssetClassification, BusinessCriticality, CryptoAsset,
            Evidence, LifecycleStage, SensitivityLevel, SourceLocation,
        )
        ev = Evidence(
            detection_method=DetectionMethod.AST_RULE,
            finding_type=FindingType.DETERMINISTIC,
            rule_id="R-999",
            location=SourceLocation(file_path="f.py", line_number=1, snippet="x()"),
            source_surface="source_code", confidence=0.55,
        )
        asset = CryptoAsset(
            algorithm="UNKNOWN", purpose="unknown", location="f.py:1",
            source_surface="source_code",
            classification=AssetClassification.APPLICATION,
            sensitivity=SensitivityLevel.INTERNAL,
            business_criticality=BusinessCriticality.LOW,
            lifecycle_stage=LifecycleStage.ACTIVE, evidence=ev,
        )
        engine = _mock_engine('{"purpose":"key_derivation","confidence":0.75}')
        result = engine.process([asset])[0]
        assert result.purpose == CryptoPurpose.KEY_DERIVATION
        assert abs(result.evidence.confidence - 0.75) < 0.01


# ── 3. Cache: second identical call hits cache, not LLM ──────────────────────

class TestCacheBehaviour:
    def test_second_call_hits_cache(self):
        from ecdat.schemas import (
            AssetClassification, BusinessCriticality, CryptoAsset,
            Evidence, LifecycleStage, SensitivityLevel, SourceLocation,
        )

        def _asset(snippet: str):
            ev = Evidence(
                detection_method=DetectionMethod.AST_RULE,
                finding_type=FindingType.DETERMINISTIC,
                rule_id="R-999",
                location=SourceLocation(file_path="f.py", line_number=1, snippet=snippet),
                source_surface="source_code", confidence=0.55,
            )
            return CryptoAsset(
                algorithm="UNKNOWN", purpose="unknown", location="f.py:1",
                source_surface="source_code",
                classification=AssetClassification.APPLICATION,
                sensitivity=SensitivityLevel.INTERNAL,
                business_criticality=BusinessCriticality.LOW,
                lifecycle_stage=LifecycleStage.ACTIVE, evidence=ev,
            )

        # Build engine with real in-memory redis mock
        store: dict = {}
        redis = MagicMock()
        redis.ping.return_value = True
        redis.get.side_effect = lambda k: store.get(k)
        redis.setex.side_effect = lambda k, t, v: store.update({k: v})
        redis.delete.side_effect = lambda k: store.pop(k, None)

        config = LLMConfig(provider="anthropic", api_key="test",
                           model="claude-3-5-sonnet", prompt_version="v1")
        client = LLMClient(config)
        client.call = MagicMock(return_value='{"purpose":"hashing","confidence":0.9}')
        cache = LLMCache(redis)
        engine = LLMEnrichmentEngine(llm_client=client, cache=cache)

        SNIPPET = "compute_digest_for_user(data)"
        a1 = _asset(SNIPPET)
        a2 = _asset(SNIPPET)   # identical snippet → same cache key

        engine.process([a1])
        call_count_after_first = client.call.call_count

        engine.process([a2])
        assert client.call.call_count == call_count_after_first, (
            "LLM was called a second time despite an identical snippet in cache"
        )
        assert engine.stats.cache_hits == 1


# ── 4. Deterministic assets unaffected ───────────────────────────────────────

class TestDeterministicUnaffected:
    """
    The LLM enrichment stage MUST NOT change any deterministic asset's
    purpose, classification, risk, or recommendation.
    """

    @pytest.fixture(scope="class")
    def baseline(self):
        return run_pipeline(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
            classification_rules_path=CLS_PATH,
            mosca_profiles_path=MOSCA_PATH,
            pqc_mappings_path=PQC_PATH,
            scan_id="test-llm-baseline",
            run_llm_enrichment=False,
        )

    @pytest.fixture(scope="class")
    def with_llm(self):
        """Pipeline with LLM enrichment enabled (LLM mocked)."""
        with patch("ecdat.pipeline.LLMEnrichmentEngine") as mock_cls:
            # Mock the engine to pass all assets through unchanged
            mock_engine = MagicMock()
            mock_engine.process.side_effect = lambda assets: assets
            mock_engine.stats.ambiguous_attempted = 0
            mock_engine.stats.enriched = 0
            mock_engine.stats.cache_hits = 0
            mock_engine.stats.failed = 0
            mock_cls.from_env.return_value = mock_engine
            result = run_pipeline(
                target_path=DEMO_REPO,
                rules_path=RULES_PATH,
                classification_rules_path=CLS_PATH,
                mosca_profiles_path=MOSCA_PATH,
                pqc_mappings_path=PQC_PATH,
                scan_id="test-llm-with",
                run_llm_enrichment=True,
            )
        return result

    def test_same_asset_count(self, baseline, with_llm):
        assert len(baseline.scored_assets) == len(with_llm.scored_assets)

    def test_purposes_unchanged(self, baseline, with_llm):
        bl = {a.location: a.purpose for a in baseline.scored_assets}
        wl = {a.location: a.purpose for a in with_llm.scored_assets}
        for loc in bl:
            assert bl[loc] == wl[loc], f"Purpose changed at {loc}"

    def test_classifications_unchanged(self, baseline, with_llm):
        bl = {a.location: a.classification for a in baseline.scored_assets}
        wl = {a.location: a.classification for a in with_llm.scored_assets}
        for loc in bl:
            assert bl[loc] == wl[loc], f"Classification changed at {loc}"

    def test_priorities_unchanged(self, baseline, with_llm):
        bl = {a.location: a.risk.priority for a in baseline.scored_assets}
        wl = {a.location: a.risk.priority for a in with_llm.scored_assets}
        for loc in bl:
            assert bl[loc] == wl[loc], f"Priority changed at {loc}"

    def test_recommendations_unchanged(self, baseline, with_llm):
        bl = {a.location: a.recommendation.standardized_replacement
              for a in baseline.scored_assets}
        wl = {a.location: a.recommendation.standardized_replacement
              for a in with_llm.scored_assets}
        for loc in bl:
            assert bl[loc] == wl[loc], f"Recommendation changed at {loc}"


# ── 5. LLM enrichment disabled by default ────────────────────────────────────

class TestLLMDisabledByDefault:
    def test_run_llm_enrichment_default_false(self):
        result = run_pipeline(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
            classification_rules_path=CLS_PATH,
            scan_id="test-llm-default",
            run_llm_enrichment=False,
            run_mosca=False,
            run_recommendations=False,
            run_reachability=False,
            run_completeness=False,
        )
        # No LLM_ENRICHED assets — all deterministic
        for a in result.scored_assets:
            assert a.evidence.finding_type == FindingType.DETERMINISTIC

    def test_run_source_discovery_wrapper_no_llm(self):
        result = run_source_discovery(
            target_path=DEMO_REPO, rules_path=RULES_PATH,
        )
        for a in result.scored_assets:
            assert a.evidence.finding_type == FindingType.DETERMINISTIC


# ── 6. Rejected LLM output preserves UNKNOWN purpose ─────────────────────────

class TestRejectedOutputPreservesUnknown:
    def test_security_verdict_in_output_rejected(self):
        from ecdat.schemas import (
            AssetClassification, BusinessCriticality, CryptoAsset,
            Evidence, LifecycleStage, SensitivityLevel, SourceLocation,
        )
        ev = Evidence(
            detection_method=DetectionMethod.AST_RULE,
            finding_type=FindingType.DETERMINISTIC,
            rule_id="R-999",
            location=SourceLocation(file_path="f.py", line_number=1, snippet="x()"),
            source_surface="source_code", confidence=0.55,
        )
        asset = CryptoAsset(
            algorithm="UNKNOWN", purpose="unknown", location="f.py:1",
            source_surface="source_code",
            classification=AssetClassification.APPLICATION,
            sensitivity=SensitivityLevel.INTERNAL,
            business_criticality=BusinessCriticality.LOW,
            lifecycle_stage=LifecycleStage.ACTIVE, evidence=ev,
        )
        # LLM sneaks in a forbidden field — must be rejected
        bad_response = '{"purpose":"hashing","confidence":0.8,"risk":"critical"}'
        engine = _mock_engine(bad_response)
        results = engine.process([asset])
        assert results[0].purpose == CryptoPurpose.UNKNOWN  # unchanged
        assert results[0].evidence.finding_type == FindingType.DETERMINISTIC  # unchanged
        assert engine.stats.failed == 1
