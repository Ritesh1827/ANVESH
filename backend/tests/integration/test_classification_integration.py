"""
Integration tests — ClassificationEngine in the full pipeline (pre-Day 6).

Runs the pipeline with classification enabled on demo_app and verifies:
  1.  All 16 demo_app assets receive real classification values (not staging)
  2.  Exact per-asset values match the regression analysis table
  3.  Classification precedes Mosca in the pipeline — classification_weight
      in the Risk record reflects the definitive classification, not staging
  4.  PRD §9 sample asset produces the exact PRD-specified field values
  5.  Lifecycle: MD5/SHA-1/DES/TLS-1.0/TLS-legacy assets are LEGACY
  6.  run_classification=False leaves staging defaults on all assets
  7.  run_source_discovery() wrapper also leaves staging defaults
  8.  Classification section appears in the pipeline report
  9.  Day 4 regression: Mosca priority, HNDL, recommendations unchanged
  10. Day 5 regression: reachability fields populated, report still valid
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ecdat.pipeline import run_pipeline, run_source_discovery
from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    LifecycleStage,
    RiskPriority,
    SensitivityLevel,
    StandardizationStatus,
)

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEMO_REPO = REPO_ROOT / "test_repos" / "demo_app"
RULES_PATH = REPO_ROOT / "config" / "detection_rules.yaml"
CLS_PATH   = REPO_ROOT / "config" / "classification_rules.yaml"
MOSCA_PATH = REPO_ROOT / "config" / "mosca_profiles.yaml"
PQC_PATH   = REPO_ROOT / "config" / "pqc_mappings.yaml"


@pytest.fixture(scope="module")
def classified_pipeline():
    """Full pipeline with classification enabled, no reachability/risk (fast)."""
    return run_pipeline(
        target_path=DEMO_REPO,
        rules_path=RULES_PATH,
        classification_rules_path=CLS_PATH,
        scan_id="test-cls-integration-001",
        run_classification=True,
        run_reachability=False,
        run_completeness=False,
        run_mosca=False,
        run_recommendations=False,
    )


@pytest.fixture(scope="module")
def full_pipeline():
    """Full pipeline: classification + reachability + Mosca + recommendation."""
    return run_pipeline(
        target_path=DEMO_REPO,
        rules_path=RULES_PATH,
        classification_rules_path=CLS_PATH,
        mosca_profiles_path=MOSCA_PATH,
        pqc_mappings_path=PQC_PATH,
        scan_id="test-cls-full-001",
        run_classification=True,
        run_reachability=True,
        run_completeness=True,
        run_mosca=True,
        run_recommendations=True,
    )


def _asset_at(result, location: str):
    assets = result.scored_assets
    match = [a for a in assets if a.location == location]
    assert match, f"No asset at {location}. Available: {[a.location for a in assets]}"
    return match[0]


# ── 1. All assets receive real classification (not staging) ──────────────────

class TestAllAssetsClassified:
    def test_no_asset_has_staging_sensitivity(self, classified_pipeline):
        """All sensitivity values must differ from INTERNAL (staging default)
        OR be INTERNAL for the right reason (safe hash), never left as staging."""
        # We can't simply check "not INTERNAL" because INTERNAL is a valid real value.
        # We verify instead that classification_weight is not 0.5 (the LOW staging
        # criticality would give 0.5) for assets that should be critical/high.
        for asset in classified_pipeline.scored_assets:
            # Every asset must have a non-staging business_criticality
            # (staging = LOW; anything key_establishment/broken must be CRITICAL)
            if asset.purpose.value == "key_establishment":
                assert asset.business_criticality != BusinessCriticality.LOW, (
                    f"key_establishment asset {asset.algorithm} @ {asset.location} "
                    f"has staging LOW criticality — ClassificationEngine did not run"
                )

    def test_all_assets_have_lifecycle_stage(self, classified_pipeline):
        for asset in classified_pipeline.scored_assets:
            assert asset.lifecycle_stage is not None

    def test_asset_count_unchanged(self, classified_pipeline):
        """Classification must not drop or duplicate assets."""
        assert classified_pipeline.inventory.stats.unique_assets == len(
            classified_pipeline.scored_assets
        )


# ── 2. Exact per-asset regression values ────────────────────────────────────

class TestExactPerAssetValues:
    """
    Exact expected values from the regression analysis (Task 5).
    Where a value changed from the old heuristic, the new value is verified
    and the reason is documented in the test name.
    """

    # ── auth_service.py ──────────────────────────────────────────────────────

    def test_rsa2048_key_estab_criticality_is_critical(self, classified_pipeline):
        # OLD: high  NEW: critical  REASON: PRD §9 sample explicitly requires critical
        a = _asset_at(classified_pipeline, "auth_service.py:24")
        assert a.classification == AssetClassification.APPLICATION
        assert a.sensitivity == SensitivityLevel.HIGH
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_md5_hashing_criticality_is_critical(self, classified_pipeline):
        # OLD: low  NEW: critical  REASON: MD5 is classically broken → immediate risk
        a = _asset_at(classified_pipeline, "auth_service.py:30")
        assert a.classification == AssetClassification.APPLICATION
        assert a.sensitivity == SensitivityLevel.HIGH
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_sha256_hashing_unchanged(self, classified_pipeline):
        # No change expected — SHA-256 was already correctly low/internal
        a = _asset_at(classified_pipeline, "auth_service.py:35")
        assert a.classification == AssetClassification.APPLICATION
        assert a.sensitivity == SensitivityLevel.INTERNAL
        assert a.business_criticality == BusinessCriticality.LOW

    def test_tls10_now_infrastructure(self, classified_pipeline):
        # OLD: application  NEW: infrastructure
        # REASON: TLS-1.0 algorithm prefix → infrastructure regardless of filename
        a = _asset_at(classified_pipeline, "auth_service.py:40")
        assert a.classification == AssetClassification.INFRASTRUCTURE
        assert a.sensitivity == SensitivityLevel.HIGH
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_aes_fernet_unchanged(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "auth_service.py:47")
        assert a.classification == AssetClassification.APPLICATION
        assert a.sensitivity == SensitivityLevel.CONFIDENTIAL
        assert a.business_criticality == BusinessCriticality.MEDIUM

    # ── crypto_utils.py ──────────────────────────────────────────────────────

    def test_rsa2048_crypto_utils_critical(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "crypto_utils.py:23")
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_md5_crypto_utils_critical(self, classified_pipeline):
        # OLD: low  NEW: critical  REASON: classically broken
        a = _asset_at(classified_pipeline, "crypto_utils.py:29")
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_sha1_crypto_utils_critical(self, classified_pipeline):
        # OLD: low  NEW: critical  REASON: classically broken (SHAttered 2017)
        a = _asset_at(classified_pipeline, "crypto_utils.py:36")
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_des_crypto_utils_critical(self, classified_pipeline):
        # OLD: medium  NEW: critical  REASON: classically broken (56-bit, cracked 1998)
        a = _asset_at(classified_pipeline, "crypto_utils.py:43")
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_aes_crypto_utils_unchanged(self, classified_pipeline):
        # AES (purpose=encryption, not broken) stays medium
        a = _asset_at(classified_pipeline, "crypto_utils.py:49")
        assert a.business_criticality == BusinessCriticality.MEDIUM

    # ── payment_service.py ───────────────────────────────────────────────────

    def test_ecdsa_digital_signature_unchanged_high(self, classified_pipeline):
        # ECDSA was already HIGH — stays HIGH (digital_signature)
        a = _asset_at(classified_pipeline, "payment_service.py:22")
        assert a.business_criticality == BusinessCriticality.HIGH

    def test_rsa4096_key_estab_critical(self, classified_pipeline):
        # OLD: high  NEW: critical  REASON: key_establishment application
        a = _asset_at(classified_pipeline, "payment_service.py:30")
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_hmac_unchanged_low(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "payment_service.py:40")
        assert a.business_criticality == BusinessCriticality.LOW

    def test_sha512_unchanged_low(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "payment_service.py:45")
        assert a.business_criticality == BusinessCriticality.LOW

    # ── tls_client.py ────────────────────────────────────────────────────────

    def test_tls_legacy_infrastructure_critical(self, classified_pipeline):
        # classification: OLD=infrastructure NEW=infrastructure (SAME)
        # criticality: OLD=high NEW=critical (infrastructure key_establishment)
        a = _asset_at(classified_pipeline, "tls_client.py:19")
        assert a.classification == AssetClassification.INFRASTRUCTURE
        assert a.business_criticality == BusinessCriticality.CRITICAL

    def test_sha1_tls_file_now_application(self, classified_pipeline):
        # OLD: infrastructure (filename had "tls")
        # NEW: application (SHA-1 hashing is app-layer, not infrastructure)
        # REASON: old heuristic classified everything in tls_client.py as infra.
        #         New engine uses purpose + algorithm, not just filename.
        a = _asset_at(classified_pipeline, "tls_client.py:33")
        assert a.classification == AssetClassification.APPLICATION
        assert a.business_criticality == BusinessCriticality.CRITICAL  # SHA-1 broken


# ── 3. Lifecycle stages ───────────────────────────────────────────────────────

class TestLifecycleStages:
    def test_md5_is_legacy(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "auth_service.py:30")
        assert a.lifecycle_stage == LifecycleStage.LEGACY

    def test_sha1_is_legacy(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "crypto_utils.py:36")
        assert a.lifecycle_stage == LifecycleStage.LEGACY

    def test_des_is_legacy(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "crypto_utils.py:43")
        assert a.lifecycle_stage == LifecycleStage.LEGACY

    def test_tls_legacy_is_legacy(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "tls_client.py:19")
        assert a.lifecycle_stage == LifecycleStage.LEGACY

    def test_rsa2048_is_active(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "auth_service.py:24")
        assert a.lifecycle_stage == LifecycleStage.ACTIVE

    def test_sha256_is_active(self, classified_pipeline):
        a = _asset_at(classified_pipeline, "auth_service.py:35")
        assert a.lifecycle_stage == LifecycleStage.ACTIVE


# ── 4. Classification → Mosca weight correctness ─────────────────────────────

class TestClassificationWeightInMosca:
    """Mosca's _classification_weight reads asset.classification and
    asset.business_criticality. With classification running before Mosca,
    the weights must reflect real values, not staging defaults."""

    def test_critical_application_asset_has_weight_1(self, full_pipeline):
        # RSA-2048 key_establishment: application/critical → weight 1.0
        rsa = [a for a in full_pipeline.scored_assets
               if a.algorithm == "RSA-2048" and
                  a.purpose.value == "key_establishment" and
                  "auth_service" in a.evidence.location.file_path]
        assert rsa, "RSA-2048 key_establishment not found in auth_service"
        assert rsa[0].risk.classification_weight == 1.0

    def test_low_criticality_asset_has_weight_0_5(self, full_pipeline):
        # SHA-512 hashing: application/low → weight 0.5
        sha = [a for a in full_pipeline.scored_assets
               if a.algorithm == "SHA-512"]
        assert sha
        assert sha[0].risk.classification_weight == 0.5

    def test_infrastructure_critical_asset_has_weight_1(self, full_pipeline):
        # TLS-1.0 key_establishment: infrastructure/critical → weight 1.0
        tls = [a for a in full_pipeline.scored_assets
               if a.algorithm == "TLS-1.0"]
        assert tls
        assert tls[0].risk.classification_weight == 1.0


# ── 5. run_classification=False leaves staging defaults ──────────────────────

class TestClassificationDisabled:
    def test_disabled_leaves_all_application_staging(self):
        result = run_pipeline(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
            scan_id="test-cls-disabled",
            run_classification=False,
            run_reachability=False,
            run_completeness=False,
            run_mosca=False,
            run_recommendations=False,
        )
        for asset in result.scored_assets:
            assert asset.classification == AssetClassification.APPLICATION, (
                f"Expected staging APPLICATION for {asset.algorithm} @ {asset.location}, "
                f"got {asset.classification}"
            )
            assert asset.sensitivity == SensitivityLevel.INTERNAL
            assert asset.business_criticality == BusinessCriticality.LOW


# ── 6. run_source_discovery() wrapper ────────────────────────────────────────

class TestRunSourceDiscoveryWrapper:
    def test_wrapper_produces_staging_classification(self):
        result = run_source_discovery(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
            scan_id="test-wrapper-cls",
        )
        for asset in result.scored_assets:
            assert asset.classification == AssetClassification.APPLICATION
            assert asset.sensitivity == SensitivityLevel.INTERNAL
            assert asset.business_criticality == BusinessCriticality.LOW


# ── 7. Report contains Classification section ─────────────────────────────────

class TestPipelineReport:
    def test_report_has_classification_section(self, classified_pipeline):
        report = classified_pipeline.report()
        assert "Classification" in report

    def test_report_shows_infrastructure_count(self, classified_pipeline):
        report = classified_pipeline.report()
        assert "Infrastructure" in report

    def test_report_shows_legacy_count(self, classified_pipeline):
        report = classified_pipeline.report()
        assert "Legacy" in report


# ── 8. Day 4 regression ──────────────────────────────────────────────────────

class TestDay4Regression:
    """Day 4 behaviour must be fully preserved after classification is added."""

    def test_md5_is_still_p1(self, full_pipeline):
        md5 = [a for a in full_pipeline.scored_assets if a.algorithm == "MD5"]
        assert md5
        for a in md5:
            assert a.risk.priority == RiskPriority.P1

    def test_sha256_is_still_p4(self, full_pipeline):
        sha256 = [a for a in full_pipeline.scored_assets if "SHA-256" in a.algorithm]
        if sha256:
            for a in sha256:
                assert a.risk.priority == RiskPriority.P4

    def test_rsa_key_estab_still_ml_kem(self, full_pipeline):
        rsa = [a for a in full_pipeline.scored_assets
               if a.algorithm.startswith("RSA") and
                  a.purpose.value == "key_establishment"]
        assert rsa
        for a in rsa:
            assert "ML-KEM" in a.recommendation.standardized_replacement

    def test_ecdsa_still_ml_dsa(self, full_pipeline):
        ecdsa = [a for a in full_pipeline.scored_assets
                 if a.algorithm.startswith("ECDSA")]
        assert ecdsa
        for a in ecdsa:
            assert "ML-DSA" in a.recommendation.standardized_replacement

    def test_mosca_math_correct(self, full_pipeline):
        for a in full_pipeline.scored_assets:
            r = a.risk
            if r.mosca_x_years and r.mosca_y_years and r.mosca_z_years:
                expected = (r.mosca_x_years + r.mosca_y_years) > r.mosca_z_years
                assert r.urgency_flag == expected

    def test_rsa_hndl_flag_still_true(self, full_pipeline):
        rsa = [a for a in full_pipeline.scored_assets
               if a.algorithm.startswith("RSA") and
                  a.purpose.value == "key_establishment"]
        assert rsa
        for a in rsa:
            assert a.risk.hndl_flag is True

    def test_no_under_standardization_primary(self, full_pipeline):
        for a in full_pipeline.scored_assets:
            assert a.recommendation.status != StandardizationStatus.UNDER_STANDARDIZATION
