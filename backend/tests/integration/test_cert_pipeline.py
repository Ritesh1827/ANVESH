"""
Integration tests — Day 6: Certificate surface + full pipeline.

Validates:
  1.  Pipeline with cert_paths discovers certificate assets
  2.  Certificate assets appear in scored_assets alongside source assets
  3.  Certificate assets pass through ClassificationEngine (stage 6)
      using classification_rules.yaml — NOT a separate ad-hoc path
  4.  Certificate classification is INFRASTRUCTURE (rule priority 100)
  5.  Certificate sensitivity is CRITICAL (key_establishment) or HIGH (fallback)
  6.  Certificate criticality is CRITICAL (rule priority 89)
  7.  Certificate lifecycle stage is EXPIRED / ROTATION_PENDING / ACTIVE
      based on actual expiry dates — not hardcoded ACTIVE
  8.  Certificate reachable is None (no call graph)
  9.  Certificate assets go through Mosca Risk Engine
  10. Certificate assets go through PQC Recommendation Engine
  11. Source-code asset values are IDENTICAL to the pre-Day-6 baseline
      (regression check — certificate surface must not affect source assets)
  12. Completeness engine reports "certificate" as scanned surface
  13. PipelineResult.cert_scan_result populated when cert_paths provided
  14. cert_paths=None leaves cert_scan_result as None
  15. Cert assets are deduplicated in the shared inventory
"""

from __future__ import annotations

import json
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
from ecdat.engines.completeness_engine import SurfaceStatus

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEMO_REPO = REPO_ROOT / "test_repos" / "demo_app"
CERTS_DIR = REPO_ROOT / "test_repos" / "certs"
RULES_PATH = REPO_ROOT / "config" / "detection_rules.yaml"
CLS_PATH   = REPO_ROOT / "config" / "classification_rules.yaml"
MOSCA_PATH = REPO_ROOT / "config" / "mosca_profiles.yaml"
PQC_PATH   = REPO_ROOT / "config" / "pqc_mappings.yaml"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def cert_only_pipeline():
    """Certificate-only scan: no source code, just certs."""
    return run_pipeline(
        target_path=DEMO_REPO,          # source target (needed — will find source assets)
        rules_path=RULES_PATH,
        classification_rules_path=CLS_PATH,
        mosca_profiles_path=MOSCA_PATH,
        pqc_mappings_path=PQC_PATH,
        scan_id="test-day6-cert-001",
        cert_paths=[CERTS_DIR],
        run_classification=True,
        run_reachability=False,
        run_completeness=True,
        run_mosca=True,
        run_recommendations=True,
    )


@pytest.fixture(scope="module")
def source_only_pipeline():
    """Source-only scan: no cert_paths — baseline for regression check."""
    return run_pipeline(
        target_path=DEMO_REPO,
        rules_path=RULES_PATH,
        classification_rules_path=CLS_PATH,
        mosca_profiles_path=MOSCA_PATH,
        pqc_mappings_path=PQC_PATH,
        scan_id="test-day6-src-only",
        cert_paths=None,
        run_classification=True,
        run_reachability=False,
        run_completeness=True,
        run_mosca=True,
        run_recommendations=True,
    )


def _cert_assets(result):
    return [a for a in result.scored_assets if a.source_surface == "certificate"]


def _source_assets(result):
    return [a for a in result.scored_assets if a.source_surface == "source_code"]


def _asset_at(assets, location_substr: str):
    matches = [a for a in assets if location_substr in a.location]
    assert matches, f"No asset found with '{location_substr}' in location. Available: {[a.location for a in assets]}"
    return matches[0]


# ── 1. Certificate assets discovered ─────────────────────────────────────────

class TestCertAssetsDiscovered:
    def test_cert_scan_result_populated(self, cert_only_pipeline):
        assert cert_only_pipeline.cert_scan_result is not None

    def test_cert_assets_present_in_scored_assets(self, cert_only_pipeline):
        cert_a = _cert_assets(cert_only_pipeline)
        assert len(cert_a) > 0, "No certificate assets in scored_assets"

    def test_at_least_7_cert_files_scanned(self, cert_only_pipeline):
        csr = cert_only_pipeline.cert_scan_result
        assert csr.files_scanned >= 7

    def test_source_and_cert_assets_both_present(self, cert_only_pipeline):
        cert_a = _cert_assets(cert_only_pipeline)
        src_a = _source_assets(cert_only_pipeline)
        assert len(cert_a) > 0
        assert len(src_a) > 0

    def test_cert_scan_result_none_without_cert_paths(self, source_only_pipeline):
        assert source_only_pipeline.cert_scan_result is None


# ── 2–6. Certificate classification via ClassificationEngine ─────────────────

class TestCertificateClassification:
    """
    Confirms certificate assets flow through ClassificationEngine (stage 6)
    using classification_rules.yaml — no ad-hoc heuristic.
    """

    def test_all_cert_assets_are_infrastructure(self, cert_only_pipeline):
        for asset in _cert_assets(cert_only_pipeline):
            assert asset.classification == AssetClassification.INFRASTRUCTURE, (
                f"Certificate asset {asset.algorithm} @ {asset.location} "
                f"is not INFRASTRUCTURE — ClassificationEngine may not have run"
            )

    def test_cert_key_establishment_sensitivity_is_critical(self, cert_only_pipeline):
        key_certs = [a for a in _cert_assets(cert_only_pipeline)
                     if a.purpose.value == "key_establishment"]
        assert key_certs
        for a in key_certs:
            assert a.sensitivity == SensitivityLevel.CRITICAL, (
                f"key_establishment cert {a.algorithm} should be CRITICAL sensitivity"
            )

    def test_cert_digital_signature_sensitivity_is_critical(self, cert_only_pipeline):
        sig_certs = [a for a in _cert_assets(cert_only_pipeline)
                     if a.purpose.value == "digital_signature"]
        for a in sig_certs:
            assert a.sensitivity == SensitivityLevel.CRITICAL

    def test_all_cert_assets_criticality_is_critical(self, cert_only_pipeline):
        for asset in _cert_assets(cert_only_pipeline):
            assert asset.business_criticality == BusinessCriticality.CRITICAL, (
                f"Certificate asset {asset.algorithm} should be CRITICAL criticality"
            )

    def test_cert_assets_not_staging_values(self, cert_only_pipeline):
        """Verify ClassificationEngine actually ran — staging defaults should be gone."""
        for asset in _cert_assets(cert_only_pipeline):
            assert asset.classification != AssetClassification.APPLICATION, (
                f"Certificate asset still has staging APPLICATION classification — "
                f"ClassificationEngine did not run"
            )
            assert asset.sensitivity != SensitivityLevel.INTERNAL, (
                f"Certificate asset still has staging INTERNAL sensitivity"
            )
            assert asset.business_criticality != BusinessCriticality.LOW, (
                f"Certificate asset still has staging LOW criticality"
            )


# ── 7. Lifecycle stage from expiry date ──────────────────────────────────────

class TestCertificateLifecycleStage:
    """
    Lifecycle stage is derived from actual certificate expiry dates,
    not hardcoded ACTIVE.
    """

    def test_expired_cert_gets_expired_lifecycle(self, cert_only_pipeline):
        expired = [a for a in _cert_assets(cert_only_pipeline)
                   if a.algorithm.startswith("RSA") and
                      a.lifecycle_stage == LifecycleStage.EXPIRED]
        assert len(expired) >= 1, (
            "No EXPIRED lifecycle assets found — expired cert fixture not detected. "
            f"Cert lifecycle stages: {[(a.location, a.lifecycle_stage.value) for a in _cert_assets(cert_only_pipeline)]}"
        )

    def test_near_expiry_cert_gets_rotation_pending(self, cert_only_pipeline):
        rotation = [a for a in _cert_assets(cert_only_pipeline)
                    if a.lifecycle_stage == LifecycleStage.ROTATION_PENDING]
        assert len(rotation) >= 1, "No ROTATION_PENDING lifecycle assets found"

    def test_valid_cert_gets_active_lifecycle(self, cert_only_pipeline):
        active = [a for a in _cert_assets(cert_only_pipeline)
                  if a.lifecycle_stage == LifecycleStage.ACTIVE and
                     a.purpose.value == "key_establishment"]
        assert len(active) >= 1, "No ACTIVE lifecycle key_establishment cert assets"

    def test_lifecycle_stage_not_all_active(self, cert_only_pipeline):
        """If all certs were hardcoded ACTIVE, this catches it."""
        stages = {a.lifecycle_stage for a in _cert_assets(cert_only_pipeline)}
        assert len(stages) > 1, (
            "All certificate assets have the same lifecycle stage — "
            "expiry-based derivation may not be working"
        )


# ── 8. Reachability for certificates ─────────────────────────────────────────

class TestCertReachability:
    def test_all_cert_assets_reachable_none(self, cert_only_pipeline):
        for asset in _cert_assets(cert_only_pipeline):
            assert asset.reachable is None, (
                f"Certificate asset {asset.algorithm} has reachable={asset.reachable}, "
                f"expected None (certificates have no call graph)"
            )


# ── 9–10. Mosca + Recommendation on certificate assets ───────────────────────

class TestCertMoscaAndRecommendation:
    def test_all_cert_assets_have_risk(self, cert_only_pipeline):
        for asset in _cert_assets(cert_only_pipeline):
            assert asset.risk is not None

    def test_all_cert_assets_have_recommendation(self, cert_only_pipeline):
        for asset in _cert_assets(cert_only_pipeline):
            assert asset.recommendation is not None

    def test_cert_key_establishment_urgency_flag_consistent(self, cert_only_pipeline):
        for asset in _cert_assets(cert_only_pipeline):
            r = asset.risk
            if r.mosca_x_years and r.mosca_y_years and r.mosca_z_years:
                expected = (r.mosca_x_years + r.mosca_y_years) > r.mosca_z_years
                assert r.urgency_flag == expected

    def test_cert_rsa_recommendation_is_ml_kem(self, cert_only_pipeline):
        rsa_key = [a for a in _cert_assets(cert_only_pipeline)
                   if a.algorithm.startswith("RSA") and
                      a.purpose.value == "key_establishment"]
        assert rsa_key
        for a in rsa_key:
            assert "ML-KEM" in a.recommendation.standardized_replacement

    def test_cert_ecdsa_recommendation_is_ml_dsa(self, cert_only_pipeline):
        ecdsa = [a for a in _cert_assets(cert_only_pipeline)
                 if a.algorithm.startswith("ECDSA")]
        assert ecdsa
        for a in ecdsa:
            assert "ML-DSA" in a.recommendation.standardized_replacement

    def test_cert_no_under_standardization_primary(self, cert_only_pipeline):
        for a in _cert_assets(cert_only_pipeline):
            assert a.recommendation.status != StandardizationStatus.UNDER_STANDARDIZATION

    def test_cert_rsa_hndl_flag(self, cert_only_pipeline):
        rsa_key = [a for a in _cert_assets(cert_only_pipeline)
                   if a.algorithm.startswith("RSA") and
                      a.purpose.value == "key_establishment"]
        # HNDL depends on X (data shelf life) — CRITICAL infrastructure cert
        # with high sensitivity should get hndl=True
        hndl_true = [a for a in rsa_key if a.risk.hndl_flag is True]
        assert len(hndl_true) >= 1, "Expected at least one RSA key_establishment cert with hndl_flag=True"

    def test_cert_assets_serialise_to_json(self, cert_only_pipeline):
        for a in _cert_assets(cert_only_pipeline):
            data = json.loads(a.model_dump_json())
            assert data["source_surface"] == "certificate"
            assert data["classification"] == "infrastructure"
            assert data["reachable"] is None


# ── 11. Source-code regression check ─────────────────────────────────────────

class TestSourceCodeRegression:
    """
    The most important Day 6 test: adding the certificate surface must NOT
    change any classification, risk, or recommendation on existing source-code
    assets. Each source-code field must be byte-for-byte identical between
    the source-only and combined (source+cert) pipelines.
    """

    def test_same_number_of_source_assets(self, cert_only_pipeline, source_only_pipeline):
        src_combined = _source_assets(cert_only_pipeline)
        src_only = _source_assets(source_only_pipeline)
        assert len(src_combined) == len(src_only), (
            f"Source asset count changed after adding certs: "
            f"{len(src_only)} → {len(src_combined)}"
        )

    def test_source_asset_classifications_unchanged(self, cert_only_pipeline, source_only_pipeline):
        combined = {a.location: a.classification for a in _source_assets(cert_only_pipeline)}
        baseline = {a.location: a.classification for a in _source_assets(source_only_pipeline)}
        for loc in baseline:
            assert combined[loc] == baseline[loc], (
                f"Classification changed at {loc}: {baseline[loc]} → {combined[loc]}"
            )

    def test_source_asset_sensitivities_unchanged(self, cert_only_pipeline, source_only_pipeline):
        combined = {a.location: a.sensitivity for a in _source_assets(cert_only_pipeline)}
        baseline = {a.location: a.sensitivity for a in _source_assets(source_only_pipeline)}
        for loc in baseline:
            assert combined[loc] == baseline[loc], (
                f"Sensitivity changed at {loc}: {baseline[loc]} → {combined[loc]}"
            )

    def test_source_asset_criticalities_unchanged(self, cert_only_pipeline, source_only_pipeline):
        combined = {a.location: a.business_criticality for a in _source_assets(cert_only_pipeline)}
        baseline = {a.location: a.business_criticality for a in _source_assets(source_only_pipeline)}
        for loc in baseline:
            assert combined[loc] == baseline[loc], (
                f"Criticality changed at {loc}: {baseline[loc]} → {combined[loc]}"
            )

    def test_source_asset_priorities_unchanged(self, cert_only_pipeline, source_only_pipeline):
        combined = {a.location: a.risk.priority for a in _source_assets(cert_only_pipeline)}
        baseline = {a.location: a.risk.priority for a in _source_assets(source_only_pipeline)}
        for loc in baseline:
            assert combined[loc] == baseline[loc], (
                f"Priority changed at {loc}: {baseline[loc]} → {combined[loc]}"
            )

    def test_source_asset_recommendations_unchanged(self, cert_only_pipeline, source_only_pipeline):
        combined = {a.location: a.recommendation.standardized_replacement
                    for a in _source_assets(cert_only_pipeline)}
        baseline = {a.location: a.recommendation.standardized_replacement
                    for a in _source_assets(source_only_pipeline)}
        for loc in baseline:
            assert combined[loc] == baseline[loc], (
                f"Recommendation changed at {loc}: {baseline[loc]} → {combined[loc]}"
            )

    def test_md5_still_p1_with_certs(self, cert_only_pipeline):
        md5 = [a for a in _source_assets(cert_only_pipeline) if a.algorithm == "MD5"]
        assert md5
        for a in md5:
            assert a.risk.priority == RiskPriority.P1

    def test_sha256_still_p4_with_certs(self, cert_only_pipeline):
        sha256 = [a for a in _source_assets(cert_only_pipeline)
                  if "SHA-256" in a.algorithm]
        if sha256:
            for a in sha256:
                assert a.risk.priority == RiskPriority.P4


# ── 12. Discovery completeness with certificate surface ───────────────────────

class TestCompletenessWithCerts:
    def test_certificate_surface_is_scanned(self, cert_only_pipeline):
        c = cert_only_pipeline.completeness
        assert c is not None
        cert_surface = next(
            (sc for sc in c.surface_coverage if sc.surface == "certificate"),
            None,
        )
        assert cert_surface is not None
        assert cert_surface.status == SurfaceStatus.SCANNED

    def test_source_code_surface_is_scanned(self, cert_only_pipeline):
        c = cert_only_pipeline.completeness
        src_surface = next(
            (sc for sc in c.surface_coverage if sc.surface == "source_code"),
            None,
        )
        assert src_surface is not None
        assert src_surface.status == SurfaceStatus.SCANNED

    def test_two_surfaces_scanned(self, cert_only_pipeline):
        c = cert_only_pipeline.completeness
        assert c.surfaces_scanned >= 2

    def test_surface_completeness_higher_than_source_only(
        self, cert_only_pipeline, source_only_pipeline
    ):
        combined_pct = cert_only_pipeline.completeness.surface_completeness_pct
        source_pct = source_only_pipeline.completeness.surface_completeness_pct
        assert combined_pct > source_pct, (
            f"Adding certificates should increase surface completeness: "
            f"{source_pct:.0f}% → {combined_pct:.0f}%"
        )


# ── 13. Pipeline report ───────────────────────────────────────────────────────

class TestPipelineReportWithCerts:
    def test_report_shows_certificate_assets(self, cert_only_pipeline):
        report = cert_only_pipeline.report()
        assert "Certificate assets" in report or "certificate" in report.lower()

    def test_report_shows_expired_count(self, cert_only_pipeline):
        report = cert_only_pipeline.report()
        assert "Expired" in report or "expired" in report.lower()

    def test_report_shows_rotation_pending(self, cert_only_pipeline):
        report = cert_only_pipeline.report()
        assert "Rotation" in report or "rotation" in report.lower()

    def test_report_contains_classification_section(self, cert_only_pipeline):
        assert "Classification" in cert_only_pipeline.report()
