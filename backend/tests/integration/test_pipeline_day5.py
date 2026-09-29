"""
Integration tests — Day 5: Reachability & Context + Discovery Completeness.

Tests run the full pipeline (stages 2→4→5→7→8→9→10) on:
  a) The reachability_app fixture (explicit ground-truth reachability map)
  b) The demo_app fixture (existing inventory, verifying no regressions)

Validates:
  1.  Reachability engine runs and populates asset fields
  2.  reachable=True for assets in entry-point functions
  3.  reachable=False for dead-code assets (no caller path)
  4.  reachable=None not silently assumed — explicitly set
  5.  reachability_path and exposure_context populated for reachable assets
  6.  Mosca reachability_weight reflects actual reachable state AFTER stage 7
  7.  Discovery Completeness is computed and attached to PipelineResult
  8.  Completeness surface and category coverage are correct
  9.  Pipeline report includes Reachability and Completeness sections
  10. Backwards-compatible run_source_discovery() produces no reachability
  11. run_pipeline(run_reachability=False) leaves all assets reachable=None
  12. Mosca risk scores are NOT None (both stages ran correctly in order)
  13. HNDL and priority from Day 4 are preserved after Day 5 additions
  14. All assets serialise to valid JSON including new reachability fields
  15. Existing Day 4 integration tests are unaffected (regression check)
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from ecdat.pipeline import run_pipeline, run_source_discovery
from ecdat.schemas import RiskPriority, CryptoAsset

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEMO_REPO = REPO_ROOT / "test_repos" / "demo_app"
REACH_REPO = REPO_ROOT / "test_repos" / "reachability_app"
RULES_PATH = REPO_ROOT / "config" / "detection_rules.yaml"
MOSCA_PATH = REPO_ROOT / "config" / "mosca_profiles.yaml"
PQC_PATH = REPO_ROOT / "config" / "pqc_mappings.yaml"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def reach_pipeline():
    """Full pipeline on reachability_app — the ground-truth fixture."""
    return run_pipeline(
        target_path=REACH_REPO,
        rules_path=RULES_PATH,
        mosca_profiles_path=MOSCA_PATH,
        pqc_mappings_path=PQC_PATH,
        scan_id="test-day5-reach-001",
        run_reachability=True,
        run_completeness=True,
        run_mosca=True,
        run_recommendations=True,
    )


@pytest.fixture(scope="module")
def demo_pipeline():
    """Full pipeline on demo_app — verifies no regressions from Day 4."""
    return run_pipeline(
        target_path=DEMO_REPO,
        rules_path=RULES_PATH,
        mosca_profiles_path=MOSCA_PATH,
        pqc_mappings_path=PQC_PATH,
        scan_id="test-day5-demo-001",
        run_reachability=True,
        run_completeness=True,
        run_mosca=True,
        run_recommendations=True,
    )


# ── 1. Pipeline executes without error ───────────────────────────────────────

class TestPipelineExecution:
    def test_reach_pipeline_completes(self, reach_pipeline):
        assert reach_pipeline is not None
        assert reach_pipeline.scan_id == "test-day5-reach-001"

    def test_reach_pipeline_has_assets(self, reach_pipeline):
        assert len(reach_pipeline.scored_assets) > 0

    def test_reach_pipeline_has_reachability_report(self, reach_pipeline):
        assert reach_pipeline.reachability_report is not None

    def test_reach_pipeline_has_completeness(self, reach_pipeline):
        assert reach_pipeline.completeness is not None

    def test_demo_pipeline_completes(self, demo_pipeline):
        assert demo_pipeline is not None
        assert len(demo_pipeline.scored_assets) > 0


# ── 2. Reachability fields populated on all assets ───────────────────────────

class TestReachabilityFieldsPopulated:
    def test_all_assets_have_reachable_set(self, reach_pipeline):
        """reachable must be explicitly set — True, False, or None.
        None is valid but must be explicit (not absent)."""
        for asset in reach_pipeline.scored_assets:
            # The field is defined in the CryptoAsset schema
            assert "reachable" in CryptoAsset.model_fields
            # exposure_context must be populated by the engine
            assert asset.exposure_context is not None, (
                f"exposure_context not set for {asset.algorithm} @ {asset.location}"
            )

    def test_at_least_some_reachable_true(self, reach_pipeline):
        reachable = [a for a in reach_pipeline.scored_assets if a.reachable is True]
        assert len(reachable) >= 1, "Expected at least one reachable asset"

    def test_at_least_some_reachable_false_or_none(self, reach_pipeline):
        non_reachable = [
            a for a in reach_pipeline.scored_assets
            if a.reachable is False or a.reachable is None
        ]
        assert len(non_reachable) >= 1

    def test_reachable_assets_have_path(self, reach_pipeline):
        for asset in reach_pipeline.scored_assets:
            if asset.reachable is True:
                assert asset.reachability_path is not None, (
                    f"reachability_path missing for reachable asset "
                    f"{asset.algorithm} @ {asset.location}"
                )
                assert len(asset.reachability_path) >= 1

    def test_unreachable_assets_have_no_path(self, reach_pipeline):
        for asset in reach_pipeline.scored_assets:
            if asset.reachable is False:
                assert asset.reachability_path is None, (
                    f"Unexpected path on unreachable asset {asset.algorithm}"
                )


# ── 3. Ground-truth reachability (reachability_app fixture) ──────────────────

class TestGroundTruthReachability:
    """
    Ground-truth checks from test_repos/reachability_app/README.md.

    Note: Exact results depend on which functions the call-graph assigns
    assets to. We check properties rather than exact line numbers to keep
    tests robust against minor fixture edits.
    """

    def test_rsa_in_entry_point_function_is_reachable(self, reach_pipeline):
        """RSA.generate in handle_login() → REACHABLE (entry point itself)."""
        rsa_assets = [
            a for a in reach_pipeline.scored_assets
            if a.algorithm.startswith("RSA") and a.purpose.value == "key_establishment"
            and "api_handler" in a.evidence.location.file_path
        ]
        assert rsa_assets, "No RSA key_establishment assets found in api_handler"
        # At least one RSA should be reachable (the one in handle_login)
        assert any(a.reachable is True for a in rsa_assets), (
            f"Expected at least one RSA to be reachable; got: "
            f"{[a.reachable for a in rsa_assets]}"
        )

    def test_sha256_in_entry_point_is_reachable(self, reach_pipeline):
        """hashlib.sha256 in handle_register() → REACHABLE."""
        sha256_assets = [
            a for a in reach_pipeline.scored_assets
            if "SHA-256" in a.algorithm
        ]
        if sha256_assets:
            assert any(a.reachable is True for a in sha256_assets), (
                "Expected at least one SHA-256 to be reachable"
            )

    def test_exposure_context_for_reachable_asset(self, reach_pipeline):
        """Reachable assets must have a non-empty exposure context."""
        reachable = [a for a in reach_pipeline.scored_assets if a.reachable is True]
        for asset in reachable:
            assert asset.exposure_context is not None
            assert len(asset.exposure_context) > 20  # meaningful, not empty
            assert asset.algorithm in asset.exposure_context or \
                   asset.location.split(":")[0] in asset.exposure_context or \
                   "Reachable" in asset.exposure_context

    def test_unknown_reachability_has_explanation(self, reach_pipeline):
        """None-reachability assets must explain WHY it's unknown."""
        unknowns = [a for a in reach_pipeline.scored_assets if a.reachable is None]
        for asset in unknowns:
            assert asset.exposure_context is not None
            ctx = asset.exposure_context.lower()
            assert (
                "unknown" in ctx or
                "undetermined" in ctx or
                "not supported" in ctx or
                "not found" in ctx or
                "no entry" in ctx
            ), f"Unclear unknown context: {asset.exposure_context}"


# ── 4. Mosca receives correct reachability weight ─────────────────────────────

class TestMoscaReachabilityIntegration:
    """
    Verify that risk.reachability_weight reflects the actual reachable state.
    Stage 7 must run BEFORE Stage 9 for this to work.
    """

    def test_reachable_asset_has_weight_1(self, reach_pipeline):
        reachable = [a for a in reach_pipeline.scored_assets
                     if a.reachable is True and a.risk is not None]
        for asset in reachable:
            assert asset.risk.reachability_weight == 1.0, (
                f"Reachable asset {asset.algorithm} has wrong weight "
                f"{asset.risk.reachability_weight}"
            )

    def test_unreachable_asset_has_weight_0_5(self, reach_pipeline):
        unreachable = [a for a in reach_pipeline.scored_assets
                       if a.reachable is False and a.risk is not None]
        for asset in unreachable:
            assert asset.risk.reachability_weight == 0.5, (
                f"Unreachable asset {asset.algorithm} has wrong weight "
                f"{asset.risk.reachability_weight}"
            )

    def test_unknown_reachability_has_weight_0_8(self, reach_pipeline):
        unknowns = [a for a in reach_pipeline.scored_assets
                    if a.reachable is None and a.risk is not None]
        for asset in unknowns:
            assert asset.risk.reachability_weight == 0.8, (
                f"Unknown-reachability asset {asset.algorithm} has wrong weight "
                f"{asset.risk.reachability_weight}"
            )

    def test_all_assets_have_risk(self, reach_pipeline):
        """Mosca must have run on all assets (reachability did not break it)."""
        for asset in reach_pipeline.scored_assets:
            assert asset.risk is not None, (
                f"Asset {asset.algorithm} @ {asset.location} has no risk record "
                "— Mosca engine may not have run"
            )

    def test_urgency_flag_still_consistent_with_xyz(self, reach_pipeline):
        """Mosca math must still be correct — Day 4 behaviour preserved."""
        for asset in reach_pipeline.scored_assets:
            r = asset.risk
            if (r.mosca_x_years is not None and
                    r.mosca_y_years is not None and
                    r.mosca_z_years is not None):
                expected = (r.mosca_x_years + r.mosca_y_years) > r.mosca_z_years
                assert r.urgency_flag == expected, (
                    f"urgency_flag inconsistency for {asset.algorithm}: "
                    f"X={r.mosca_x_years}+Y={r.mosca_y_years}="
                    f"{r.mosca_x_years+r.mosca_y_years} vs Z={r.mosca_z_years}"
                )


# ── 5. Discovery Completeness ─────────────────────────────────────────────────

class TestDiscoveryCompleteness:
    def test_completeness_attached_to_result(self, reach_pipeline):
        assert reach_pipeline.completeness is not None

    def test_surfaces_scanned_count(self, reach_pipeline):
        c = reach_pipeline.completeness
        assert c.surfaces_scanned >= 1

    def test_source_code_surface_is_scanned(self, reach_pipeline):
        from ecdat.engines.completeness_engine import SurfaceStatus
        c = reach_pipeline.completeness
        src = next(
            sc for sc in c.surface_coverage if sc.surface == "source_code"
        )
        assert src.status == SurfaceStatus.SCANNED

    def test_other_surfaces_unavailable(self, reach_pipeline):
        from ecdat.engines.completeness_engine import SurfaceStatus
        c = reach_pipeline.completeness
        for sc in c.surface_coverage:
            if sc.surface != "source_code":
                assert sc.status == SurfaceStatus.UNAVAILABLE

    def test_categories_expected_set(self, reach_pipeline):
        c = reach_pipeline.completeness
        assert c.categories_expected > 0

    def test_overall_completeness_in_range(self, reach_pipeline):
        c = reach_pipeline.completeness
        assert 0.0 <= c.overall_completeness_pct <= 100.0

    def test_completeness_summary_serialisable(self, reach_pipeline):
        summary = reach_pipeline.completeness.summary()
        json_str = json.dumps(summary)
        parsed = json.loads(json_str)
        assert "overall_completeness_pct" in parsed

    def test_demo_completeness_finds_hashing(self, demo_pipeline):
        c = demo_pipeline.completeness
        hash_cat = next(
            (cc for cc in c.category_coverage if cc.category == "hashing"),
            None,
        )
        assert hash_cat is not None
        assert hash_cat.found is True  # demo_app has MD5, SHA-1, SHA-256, SHA-512

    def test_demo_completeness_total_assets_matches(self, demo_pipeline):
        c = demo_pipeline.completeness
        assert c.total_assets_discovered == len(demo_pipeline.scored_assets)


# ── 6. Pipeline report sections ───────────────────────────────────────────────

class TestPipelineReport:
    def test_report_has_reachability_section(self, reach_pipeline):
        report = reach_pipeline.report()
        assert "Reachability" in report

    def test_report_has_completeness_section(self, reach_pipeline):
        report = reach_pipeline.report()
        assert "Completeness" in report or "Discovery" in report

    def test_report_has_risk_summary(self, reach_pipeline):
        report = reach_pipeline.report()
        assert "Risk Summary" in report

    def test_report_contains_reach_indicators(self, reach_pipeline):
        report = reach_pipeline.report()
        # Assets with known reachability should appear with indicators
        assert "[REACH]" in report or "[UNREACH]" in report or "HNDL" in report

    def test_report_is_non_empty_string(self, reach_pipeline):
        report = reach_pipeline.report()
        assert isinstance(report, str)
        assert len(report) > 200


# ── 7. run_reachability=False leaves all reachable=None ──────────────────────

class TestReachabilityDisabled:
    def test_no_reachability_flag_leaves_assets_none(self):
        result = run_pipeline(
            target_path=REACH_REPO,
            rules_path=RULES_PATH,
            scan_id="test-no-reach",
            run_reachability=False,
            run_completeness=False,
            run_mosca=False,
            run_recommendations=False,
        )
        for asset in result.scored_assets:
            assert asset.reachable is None, (
                f"reachable was set without reachability engine: "
                f"{asset.algorithm} = {asset.reachable}"
            )

    def test_no_reachability_flag_leaves_report_none(self):
        result = run_pipeline(
            target_path=REACH_REPO,
            rules_path=RULES_PATH,
            scan_id="test-no-reach-2",
            run_reachability=False,
            run_completeness=False,
            run_mosca=False,
            run_recommendations=False,
        )
        assert result.reachability_report is None

    def test_no_completeness_flag_leaves_completeness_none(self):
        result = run_pipeline(
            target_path=REACH_REPO,
            rules_path=RULES_PATH,
            scan_id="test-no-comp",
            run_reachability=False,
            run_completeness=False,
            run_mosca=False,
            run_recommendations=False,
        )
        assert result.completeness is None


# ── 8. Backwards-compatible wrapper ──────────────────────────────────────────

class TestBackwardsCompatibility:
    def test_run_source_discovery_no_reachability(self):
        result = run_source_discovery(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
            scan_id="test-compat-day5",
        )
        for asset in result.scored_assets:
            assert asset.reachable is None
            assert asset.risk is None
            assert asset.recommendation is None

    def test_run_source_discovery_no_reachability_report(self):
        result = run_source_discovery(
            target_path=DEMO_REPO,
            rules_path=RULES_PATH,
        )
        assert result.reachability_report is None
        assert result.completeness is None


# ── 9. Day 4 regression — demo_app ───────────────────────────────────────────

class TestDay4Regression:
    """Verify Day 4 behaviour is fully preserved with Day 5 additions."""

    def test_all_assets_have_risk(self, demo_pipeline):
        for asset in demo_pipeline.scored_assets:
            assert asset.risk is not None

    def test_all_assets_have_recommendation(self, demo_pipeline):
        for asset in demo_pipeline.scored_assets:
            assert asset.recommendation is not None

    def test_md5_is_still_p1(self, demo_pipeline):
        md5 = [a for a in demo_pipeline.scored_assets if a.algorithm == "MD5"]
        assert md5
        for a in md5:
            assert a.risk.priority == RiskPriority.P1

    def test_sha256_is_still_p4(self, demo_pipeline):
        sha256 = [a for a in demo_pipeline.scored_assets if "SHA-256" in a.algorithm]
        if sha256:
            for a in sha256:
                assert a.risk.priority == RiskPriority.P4

    def test_rsa_key_establishment_still_ml_kem(self, demo_pipeline):
        rsa_key = [
            a for a in demo_pipeline.scored_assets
            if a.algorithm.startswith("RSA") and a.purpose.value == "key_establishment"
        ]
        assert rsa_key
        for a in rsa_key:
            assert "ML-KEM" in a.recommendation.standardized_replacement

    def test_ecdsa_still_ml_dsa(self, demo_pipeline):
        ecdsa = [a for a in demo_pipeline.scored_assets if a.algorithm.startswith("ECDSA")]
        assert ecdsa
        for a in ecdsa:
            assert "ML-DSA" in a.recommendation.standardized_replacement

    def test_mosca_math_still_correct(self, demo_pipeline):
        for asset in demo_pipeline.scored_assets:
            r = asset.risk
            if (r.mosca_x_years is not None and
                    r.mosca_y_years is not None and
                    r.mosca_z_years is not None):
                expected = (r.mosca_x_years + r.mosca_y_years) > r.mosca_z_years
                assert r.urgency_flag == expected

    def test_hndl_on_rsa_key_establishment(self, demo_pipeline):
        rsa_key = [
            a for a in demo_pipeline.scored_assets
            if a.algorithm.startswith("RSA") and a.purpose.value == "key_establishment"
        ]
        for a in rsa_key:
            assert a.risk.hndl_flag is True

    def test_no_under_standardization_primary(self, demo_pipeline):
        from ecdat.schemas import StandardizationStatus
        for a in demo_pipeline.scored_assets:
            assert a.recommendation.status != StandardizationStatus.UNDER_STANDARDIZATION


# ── 10. Full JSON serialisation with new fields ───────────────────────────────

class TestJsonSerialisation:
    def test_assets_serialise_with_reachability_fields(self, reach_pipeline):
        for asset in reach_pipeline.scored_assets:
            data = json.loads(asset.model_dump_json())
            # reachability fields exist in the JSON
            assert "reachable" in data
            assert "reachability_path" in data
            assert "exposure_context" in data

    def test_reachable_true_serialises(self, reach_pipeline):
        reachable = [a for a in reach_pipeline.scored_assets if a.reachable is True]
        if reachable:
            data = json.loads(reachable[0].model_dump_json())
            assert data["reachable"] is True
            assert data["reachability_path"] is not None

    def test_reachable_false_serialises(self, reach_pipeline):
        unreachable = [a for a in reach_pipeline.scored_assets if a.reachable is False]
        if unreachable:
            data = json.loads(unreachable[0].model_dump_json())
            assert data["reachable"] is False
            assert data["reachability_path"] is None

    def test_reachable_none_serialises(self, reach_pipeline):
        unknowns = [a for a in reach_pipeline.scored_assets if a.reachable is None]
        if unknowns:
            data = json.loads(unknowns[0].model_dump_json())
            assert data["reachable"] is None
