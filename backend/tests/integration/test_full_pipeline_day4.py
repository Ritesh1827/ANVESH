"""
Integration tests — Full pipeline through Mosca + Recommendation (Day 4).

Runs run_pipeline() on the demo repo and verifies:
  1.  All assets receive a Risk record (Mosca ran)
  2.  All assets receive a Recommendation record (Recommendation engine ran)
  3.  Mosca calculations are mathematically consistent (urgency_flag = X+Y>Z)
  4.  HNDL flags are set correctly for key_establishment assets with long X
  5.  Purpose-aware mapping: RSA key_establishment → ML-KEM, not ML-DSA
  6.  Purpose-aware mapping: ECDSA digital_signature → ML-DSA, not ML-KEM
  7.  No primary recommendation has under_standardization status
  8.  Classical-broken algorithms (MD5, SHA-1, DES) get P1 priority
  9.  Safe algorithms (SHA-256, SHA-512) get P4 priority
  10. PipelineResult.report() includes risk summary section
  11. All assets serialise to valid JSON after full pipeline
  12. Backwards-compatible run_source_discovery() skips risk/recommendation
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from ecdat.pipeline import run_pipeline, run_source_discovery
from ecdat.schemas import (
    MigrationPathType,
    RiskPriority,
    StandardizationStatus,
)

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEMO_REPO = REPO_ROOT / "test_repos" / "demo_app"
RULES_PATH = REPO_ROOT / "config" / "detection_rules.yaml"
MOSCA_PATH = REPO_ROOT / "config" / "mosca_profiles.yaml"
PQC_PATH = REPO_ROOT / "config" / "pqc_mappings.yaml"


@pytest.fixture(scope="module")
def full_pipeline_result():
    return run_pipeline(
        target_path=DEMO_REPO,
        rules_path=RULES_PATH,
        mosca_profiles_path=MOSCA_PATH,
        pqc_mappings_path=PQC_PATH,
        scan_id="test-day4-integration-001",
    )


# ── 1–2: All assets scored ────────────────────────────────────────────────────

class TestAllAssetsScored:
    def test_scored_assets_not_empty(self, full_pipeline_result):
        assert len(full_pipeline_result.scored_assets) > 0

    def test_all_assets_have_risk(self, full_pipeline_result):
        for asset in full_pipeline_result.scored_assets:
            assert asset.risk is not None, (
                f"Asset {asset.algorithm} @ {asset.location} has no risk record"
            )

    def test_all_assets_have_recommendation(self, full_pipeline_result):
        for asset in full_pipeline_result.scored_assets:
            assert asset.recommendation is not None, (
                f"Asset {asset.algorithm} @ {asset.location} has no recommendation"
            )

    def test_asset_count_matches_inventory(self, full_pipeline_result):
        inv_count = full_pipeline_result.inventory.stats.unique_assets
        scored_count = len(full_pipeline_result.scored_assets)
        assert scored_count == inv_count


# ── 3: Mosca mathematical consistency ────────────────────────────────────────

class TestMoscaMathConsistency:
    def test_urgency_flag_consistent_with_xyz(self, full_pipeline_result):
        """X + Y > Z ↔ urgency_flag for every asset where all three are present."""
        for asset in full_pipeline_result.scored_assets:
            r = asset.risk
            if r.mosca_x_years is not None and r.mosca_y_years is not None \
                    and r.mosca_z_years is not None:
                expected = (r.mosca_x_years + r.mosca_y_years) > r.mosca_z_years
                assert r.urgency_flag == expected, (
                    f"urgency_flag mismatch for {asset.algorithm}: "
                    f"X={r.mosca_x_years}+Y={r.mosca_y_years}="
                    f"{r.mosca_x_years+r.mosca_y_years} vs Z={r.mosca_z_years}, "
                    f"flag={r.urgency_flag} expected={expected}"
                )

    def test_all_risk_priorities_are_valid(self, full_pipeline_result):
        valid = {RiskPriority.P1, RiskPriority.P2, RiskPriority.P3,
                 RiskPriority.P4, RiskPriority.UNKNOWN}
        for asset in full_pipeline_result.scored_assets:
            assert asset.risk.priority in valid

    def test_z_years_is_consistent_across_assets(self, full_pipeline_result):
        """All assets should have the same Z (from config) unless overridden."""
        z_values = {
            a.risk.mosca_z_years
            for a in full_pipeline_result.scored_assets
            if a.risk.mosca_z_years is not None
        }
        # All should use the same default Z from mosca_profiles.yaml
        assert len(z_values) == 1
        assert 10.0 in z_values   # default Z from config


# ── 4: HNDL flags ─────────────────────────────────────────────────────────────

class TestHNDLFlags:
    def test_rsa_key_establishment_has_hndl(self, full_pipeline_result):
        rsa_key = [
            a for a in full_pipeline_result.scored_assets
            if a.algorithm.startswith("RSA") and
               a.purpose.value == "key_establishment"
        ]
        assert rsa_key, "No RSA key_establishment assets found"
        for asset in rsa_key:
            assert asset.risk.hndl_flag is True, (
                f"RSA key_establishment at {asset.location} should have hndl_flag=True"
            )

    def test_md5_hashing_no_hndl(self, full_pipeline_result):
        md5 = [a for a in full_pipeline_result.scored_assets
               if a.algorithm == "MD5"]
        assert md5
        for asset in md5:
            assert asset.risk.hndl_flag is False

    def test_sha256_no_hndl(self, full_pipeline_result):
        sha256 = [a for a in full_pipeline_result.scored_assets
                  if "SHA-256" in a.algorithm]
        if sha256:
            for asset in sha256:
                assert asset.risk.hndl_flag is False

    def test_at_least_one_hndl_asset_exists(self, full_pipeline_result):
        hndl_assets = [a for a in full_pipeline_result.scored_assets
                       if a.risk.hndl_flag]
        assert len(hndl_assets) > 0, "Expected at least one HNDL-flagged asset"


# ── 5–6: Purpose-aware mapping ────────────────────────────────────────────────

class TestPurposeAwareMappingIntegration:
    def test_rsa_key_estab_gets_ml_kem_not_ml_dsa(self, full_pipeline_result):
        rsa_key = [
            a for a in full_pipeline_result.scored_assets
            if a.algorithm.startswith("RSA") and
               a.purpose.value == "key_establishment"
        ]
        assert rsa_key
        for asset in rsa_key:
            rec = asset.recommendation.standardized_replacement
            assert "ML-KEM" in rec, (
                f"RSA key_establishment should get ML-KEM, got: {rec}"
            )
            assert "ML-DSA" not in rec

    def test_ecdsa_gets_ml_dsa_not_ml_kem(self, full_pipeline_result):
        ecdsa = [
            a for a in full_pipeline_result.scored_assets
            if a.algorithm.startswith("ECDSA")
        ]
        assert ecdsa
        for asset in ecdsa:
            rec = asset.recommendation.standardized_replacement
            assert "ML-DSA" in rec, (
                f"ECDSA should get ML-DSA, got: {rec}"
            )
            assert "ML-KEM" not in rec


# ── 7: No under-standardization as primary ────────────────────────────────────

class TestNoUnderStandardizationPrimary:
    def test_no_asset_has_under_standardization_status(self, full_pipeline_result):
        for asset in full_pipeline_result.scored_assets:
            rec = asset.recommendation
            assert rec.status != StandardizationStatus.UNDER_STANDARDIZATION, (
                f"{asset.algorithm} @ {asset.location} received "
                f"under_standardization primary recommendation — "
                f"violates PRD §5 stage 10"
            )

    def test_hqc_falcon_not_in_any_primary(self, full_pipeline_result):
        forbidden = ["HQC", "FALCON", "BIKE"]
        for asset in full_pipeline_result.scored_assets:
            rec = asset.recommendation.standardized_replacement.upper()
            for name in forbidden:
                assert name not in rec, (
                    f"Under-standardization algorithm '{name}' found as "
                    f"primary recommendation for {asset.algorithm}"
                )


# ── 8–9: Priority assignment ──────────────────────────────────────────────────

class TestPriorityAssignmentIntegration:
    def test_md5_is_p1(self, full_pipeline_result):
        md5_assets = [a for a in full_pipeline_result.scored_assets
                      if a.algorithm == "MD5"]
        assert md5_assets
        for a in md5_assets:
            assert a.risk.priority == RiskPriority.P1, (
                f"MD5 should be P1 (classically broken), got {a.risk.priority}"
            )

    def test_sha1_is_p1(self, full_pipeline_result):
        sha1_assets = [a for a in full_pipeline_result.scored_assets
                       if a.algorithm == "SHA-1"]
        assert sha1_assets
        for a in sha1_assets:
            assert a.risk.priority == RiskPriority.P1

    def test_des_is_p1(self, full_pipeline_result):
        des_assets = [a for a in full_pipeline_result.scored_assets
                      if a.algorithm.startswith("DES")]
        assert des_assets
        for a in des_assets:
            assert a.risk.priority == RiskPriority.P1

    def test_sha256_is_p4(self, full_pipeline_result):
        sha256 = [a for a in full_pipeline_result.scored_assets
                  if "SHA-256" in a.algorithm]
        if sha256:
            for a in sha256:
                assert a.risk.priority == RiskPriority.P4

    def test_sha512_is_p4(self, full_pipeline_result):
        sha512 = [a for a in full_pipeline_result.scored_assets
                  if "SHA-512" in a.algorithm]
        if sha512:
            for a in sha512:
                assert a.risk.priority == RiskPriority.P4

    def test_p1_assets_exist(self, full_pipeline_result):
        p1 = [a for a in full_pipeline_result.scored_assets
              if a.risk.priority == RiskPriority.P1]
        assert len(p1) > 0, "Expected at least one P1 asset in the demo repo"

    def test_no_assets_without_priority(self, full_pipeline_result):
        for a in full_pipeline_result.scored_assets:
            assert a.risk.priority is not None


# ── 10: Report ────────────────────────────────────────────────────────────────

class TestPipelineReport:
    def test_report_contains_risk_summary(self, full_pipeline_result):
        report = full_pipeline_result.report()
        assert "Risk Summary" in report
        assert "P1" in report
        assert "HNDL" in report

    def test_report_contains_recommendations(self, full_pipeline_result):
        report = full_pipeline_result.report()
        assert "ML-KEM" in report or "ML-DSA" in report or "SHA-256" in report

    def test_report_scan_id_present(self, full_pipeline_result):
        report = full_pipeline_result.report()
        assert "test-day4-integration-001" in report


# ── 11: JSON serialisation ────────────────────────────────────────────────────

class TestFullPipelineSerialisation:
    def test_all_assets_serialise_to_json(self, full_pipeline_result):
        for asset in full_pipeline_result.scored_assets:
            data = json.loads(asset.model_dump_json())
            assert "risk" in data
            assert "recommendation" in data
            assert data["risk"]["urgency_flag"] is not None
            assert data["risk"]["priority"] in ("P1", "P2", "P3", "P4", "UNKNOWN")
            assert data["recommendation"]["status"] in (
                "standardized", "under_standardization", "classical", "deprecated"
            )


# ── 12: Backwards compatibility ───────────────────────────────────────────────

class TestBackwardsCompatibility:
    def test_run_source_discovery_skips_risk(self):
        result = run_source_discovery(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
            scan_id="test-compat-001",
        )
        # scored_assets should be from inventory (no risk)
        for asset in result.scored_assets:
            assert asset.risk is None

    def test_run_source_discovery_skips_recommendation(self):
        result = run_source_discovery(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
        )
        for asset in result.scored_assets:
            assert asset.recommendation is None
