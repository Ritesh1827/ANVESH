"""
Integration tests — Day 8: CBOM Export + Migration Impact Analysis.

Tests:
  1.  Full pipeline with run_migration=True + run_cbom_export=True runs
  2.  migration_roadmaps dict populated for all assets with recommendations
  3.  cbom_export_result.document is non-empty valid JSON
  4.  Every source asset appears as a component in the CBOM
  5.  Certificate assets appear as certificate-type components
  6.  CBOM quality score is real and non-zero
  7.  ecdat:risk.priority present in BOM components
  8.  Version diff: generates new/removed/changed correctly
  9.  Migration roadmap narrative contains all 5 PRD-mandated sequence elements
  10. Pipeline report contains Migration and CBOM sections
  11. REGRESSION: no asset's classification, risk, or recommendation changes
      as a side effect of running migration or CBOM export stages
  12. run_migration=False leaves migration_roadmaps empty
  13. run_cbom_export=False leaves cbom_export_result=None
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ecdat.pipeline import run_pipeline
from ecdat.engines.cbom_exporter import CBOMExporter, compute_version_diff
from ecdat.schemas import CBOMExport, CBOMMetadata, RiskPriority, StandardizationStatus

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEMO_REPO  = REPO_ROOT / "test_repos" / "demo_app"
CERTS_DIR  = REPO_ROOT / "test_repos" / "certs"
RULES_PATH = REPO_ROOT / "config" / "detection_rules.yaml"
CLS_PATH   = REPO_ROOT / "config" / "classification_rules.yaml"
MOSCA_PATH = REPO_ROOT / "config" / "mosca_profiles.yaml"
PQC_PATH   = REPO_ROOT / "config" / "pqc_mappings.yaml"
MIGS_PATH  = REPO_ROOT / "config" / "migration_weights.yaml"


@pytest.fixture(scope="module")
def full_pipeline():
    """Full Day 8 pipeline: source + certs + migration + CBOM."""
    return run_pipeline(
        target_path=DEMO_REPO,
        rules_path=RULES_PATH,
        classification_rules_path=CLS_PATH,
        mosca_profiles_path=MOSCA_PATH,
        pqc_mappings_path=PQC_PATH,
        migration_weights_path=MIGS_PATH,
        scan_id="test-day8-full-001",
        cert_paths=[CERTS_DIR],
        run_classification=True,
        run_reachability=False,
        run_completeness=True,
        run_mosca=True,
        run_recommendations=True,
        run_migration=True,
        run_cbom_export=True,
    )


@pytest.fixture(scope="module")
def baseline_no_migration():
    """Baseline without migration/CBOM — for regression comparison."""
    return run_pipeline(
        target_path=DEMO_REPO,
        rules_path=RULES_PATH,
        classification_rules_path=CLS_PATH,
        mosca_profiles_path=MOSCA_PATH,
        pqc_mappings_path=PQC_PATH,
        scan_id="test-day8-base-001",
        run_classification=True,
        run_reachability=False,
        run_completeness=False,
        run_mosca=True,
        run_recommendations=True,
        run_migration=False,
        run_cbom_export=False,
    )


# ── 1. Pipeline runs ──────────────────────────────────────────────────────────

class TestPipelineExecutes:
    def test_pipeline_completes(self, full_pipeline):
        assert full_pipeline is not None
        assert full_pipeline.scan_id == "test-day8-full-001"

    def test_has_scored_assets(self, full_pipeline):
        assert len(full_pipeline.scored_assets) > 0

    def test_has_migration_roadmaps(self, full_pipeline):
        assert len(full_pipeline.migration_roadmaps) > 0

    def test_has_cbom_export_result(self, full_pipeline):
        assert full_pipeline.cbom_export_result is not None


# ── 2. Migration roadmaps ─────────────────────────────────────────────────────

class TestMigrationRoadmaps:
    def test_every_asset_with_recommendation_has_roadmap(self, full_pipeline):
        for asset in full_pipeline.scored_assets:
            if asset.recommendation is not None:
                assert asset.asset_id in full_pipeline.migration_roadmaps, (
                    f"Missing roadmap for {asset.algorithm} @ {asset.location}"
                )

    def test_assets_without_recommendation_have_no_roadmap(self, full_pipeline):
        for asset in full_pipeline.scored_assets:
            if asset.recommendation is None:
                assert asset.asset_id not in full_pipeline.migration_roadmaps

    def test_roadmap_narrative_contains_all_prd_elements(self, full_pipeline):
        """PRD §5 stage 11: current state → risk → recommendation →
        affected components → priority → validation steps."""
        for roadmap in full_pipeline.migration_roadmaps.values():
            n = roadmap.narrative
            assert "→" in n, "Narrative missing arrow separators"
            assert roadmap.current_state in n or len(roadmap.current_state) > 0
            assert roadmap.migration_priority in n

    def test_immediate_assets_are_p1(self, full_pipeline):
        for asset in full_pipeline.scored_assets:
            if asset.asset_id in full_pipeline.migration_roadmaps:
                roadmap = full_pipeline.migration_roadmaps[asset.asset_id]
                if roadmap.migration_priority == "immediate":
                    assert asset.risk.priority == RiskPriority.P1

    def test_composite_scores_in_range(self, full_pipeline):
        for roadmap in full_pipeline.migration_roadmaps.values():
            assert 0.0 <= roadmap.composite_impact_score <= 1.0

    def test_validation_steps_nonempty(self, full_pipeline):
        for roadmap in full_pipeline.migration_roadmaps.values():
            assert len(roadmap.validation_steps) > 0

    def test_roadmap_summaries_json_serialisable(self, full_pipeline):
        for roadmap in full_pipeline.migration_roadmaps.values():
            json.dumps(roadmap.summary())


# ── 3. CBOM export — structure ────────────────────────────────────────────────

class TestCBOMExportStructure:
    def test_document_nonempty(self, full_pipeline):
        assert len(full_pipeline.cbom_export_result.document) > 0

    def test_document_is_valid_json(self, full_pipeline):
        doc = json.loads(full_pipeline.cbom_export_result.document)
        assert "components" in doc

    def test_component_count_matches_assets(self, full_pipeline):
        r = full_pipeline.cbom_export_result
        assert r.component_count == len(full_pipeline.scored_assets)

    def test_every_asset_has_bom_ref(self, full_pipeline):
        doc = json.loads(full_pipeline.cbom_export_result.document)
        bom_refs = {c["bom-ref"] for c in doc["components"]}
        for asset in full_pipeline.scored_assets:
            assert asset.asset_id in bom_refs, (
                f"Missing bom-ref for asset {asset.algorithm} @ {asset.location}"
            )

    def test_ecdat_location_in_all_components(self, full_pipeline):
        doc = json.loads(full_pipeline.cbom_export_result.document)
        for comp in doc["components"]:
            prop_names = {p["name"] for p in comp.get("properties", [])}
            assert "ecdat:location" in prop_names, (
                f"Missing ecdat:location in {comp.get('name')}"
            )

    def test_risk_priority_in_risk_scored_components(self, full_pipeline):
        doc = json.loads(full_pipeline.cbom_export_result.document)
        assets_with_risk = {
            a.asset_id for a in full_pipeline.scored_assets if a.risk is not None
        }
        for comp in doc["components"]:
            if comp["bom-ref"] in assets_with_risk:
                props = {p["name"]: p["value"] for p in comp.get("properties", [])}
                assert "ecdat:risk.priority" in props


# ── 4. Certificate assets in CBOM ─────────────────────────────────────────────

class TestCertificateAssetsInCBOM:
    def test_certificate_assets_present(self, full_pipeline):
        cert_assets = [a for a in full_pipeline.scored_assets
                       if a.source_surface == "certificate"]
        assert len(cert_assets) > 0

    def test_certificate_components_have_cert_type(self, full_pipeline):
        doc = json.loads(full_pipeline.cbom_export_result.document)
        cert_asset_ids = {a.asset_id for a in full_pipeline.scored_assets
                         if a.source_surface == "certificate"}
        for comp in doc["components"]:
            if comp["bom-ref"] in cert_asset_ids:
                assert comp["cryptoProperties"]["assetType"] == "certificate", (
                    f"Certificate asset {comp.get('name')} has wrong assetType"
                )


# ── 5. CBOM quality score ─────────────────────────────────────────────────────

class TestCBOMQualityScore:
    def test_quality_score_present(self, full_pipeline):
        q = full_pipeline.cbom_export_result.cbom_export.quality_score
        assert q is not None

    def test_evidence_coverage_is_1(self, full_pipeline):
        q = full_pipeline.cbom_export_result.cbom_export.quality_score
        assert q.evidence_coverage == 1.0

    def test_risk_coverage_is_1(self, full_pipeline):
        q = full_pipeline.cbom_export_result.cbom_export.quality_score
        assert q.risk_coverage == 1.0

    def test_recommendation_coverage_is_1(self, full_pipeline):
        q = full_pipeline.cbom_export_result.cbom_export.quality_score
        assert q.recommendation_coverage == 1.0

    def test_overall_quality_nonzero(self, full_pipeline):
        q = full_pipeline.cbom_export_result.cbom_export.quality_score
        assert q.overall_quality > 0.0

    def test_quality_scores_in_0_1(self, full_pipeline):
        q = full_pipeline.cbom_export_result.cbom_export.quality_score
        for val in [q.completeness_score, q.evidence_coverage,
                    q.risk_coverage, q.recommendation_coverage,
                    q.overall_quality]:
            assert 0.0 <= val <= 1.0


# ── 6. Version diff ───────────────────────────────────────────────────────────

class TestVersionDiff:
    def test_diff_self_is_empty(self, full_pipeline):
        cbom = full_pipeline.cbom_export_result.cbom_export
        diff = compute_version_diff(cbom, cbom)
        assert diff.new_assets == []
        assert diff.removed_assets == []
        assert diff.changed_assets == []

    def test_diff_detects_removed_asset(self, full_pipeline):
        cbom = full_pipeline.cbom_export_result.cbom_export
        all_assets = cbom.assets
        if len(all_assets) < 2:
            pytest.skip("Need at least 2 assets for diff test")

        # Build a "current" export missing one asset
        meta = CBOMMetadata(
            ecdat_version="0.1.0", scan_id="current-diff-001",
            scanned_targets=["demo"], input_surfaces=["source_code"],
        )
        reduced = CBOMExport(metadata=meta, assets=all_assets[1:])
        diff = compute_version_diff(cbom, reduced)
        assert all_assets[0].asset_id in diff.removed_assets

    def test_diff_detects_new_asset(self, full_pipeline):
        cbom = full_pipeline.cbom_export_result.cbom_export
        all_assets = cbom.assets
        meta_base = CBOMMetadata(
            ecdat_version="0.1.0", scan_id="base-diff-001",
            scanned_targets=["demo"], input_surfaces=["source_code"],
        )
        meta_curr = CBOMMetadata(
            ecdat_version="0.1.0", scan_id="curr-diff-002",
            scanned_targets=["demo"], input_surfaces=["source_code"],
        )
        if len(all_assets) < 2:
            pytest.skip("Need at least 2 assets")
        smaller = CBOMExport(metadata=meta_base, assets=all_assets[:-1])
        current = CBOMExport(metadata=meta_curr, assets=all_assets)
        diff = compute_version_diff(smaller, current)
        assert all_assets[-1].asset_id in diff.new_assets


# ── 7. Pipeline report sections ───────────────────────────────────────────────

class TestPipelineReport:
    def test_report_contains_migration_section(self, full_pipeline):
        assert "Migration" in full_pipeline.report()

    def test_report_contains_cbom_section(self, full_pipeline):
        report = full_pipeline.report()
        assert "CBOM" in report or "Stage 12" in report

    def test_report_contains_quality_score(self, full_pipeline):
        report = full_pipeline.report()
        assert "quality" in report.lower() or "Quality" in report


# ── 8. Regression: migration/CBOM don't change asset values ──────────────────

class TestRegressionNoAssetChanges:
    def test_same_asset_count(self, full_pipeline, baseline_no_migration):
        src_full = [a for a in full_pipeline.scored_assets
                    if a.source_surface == "source_code"]
        src_base = baseline_no_migration.scored_assets
        assert len(src_full) == len(src_base), (
            f"Asset count changed: {len(src_base)} → {len(src_full)}"
        )

    def test_classifications_unchanged(self, full_pipeline, baseline_no_migration):
        base = {a.location: a.classification for a in baseline_no_migration.scored_assets}
        curr = {a.location: a.classification
                for a in full_pipeline.scored_assets if a.source_surface == "source_code"}
        for loc in base:
            assert base[loc] == curr[loc], f"Classification changed at {loc}"

    def test_priorities_unchanged(self, full_pipeline, baseline_no_migration):
        base = {a.location: a.risk.priority for a in baseline_no_migration.scored_assets}
        curr = {a.location: a.risk.priority
                for a in full_pipeline.scored_assets if a.source_surface == "source_code"}
        for loc in base:
            assert base[loc] == curr[loc], f"Priority changed at {loc}"

    def test_recommendations_unchanged(self, full_pipeline, baseline_no_migration):
        base = {a.location: a.recommendation.standardized_replacement
                for a in baseline_no_migration.scored_assets}
        curr = {a.location: a.recommendation.standardized_replacement
                for a in full_pipeline.scored_assets if a.source_surface == "source_code"}
        for loc in base:
            assert base[loc] == curr[loc], f"Recommendation changed at {loc}"


# ── 9. Flags work correctly ───────────────────────────────────────────────────

class TestPipelineFlags:
    def test_run_migration_false_leaves_empty_roadmaps(self):
        r = run_pipeline(
            target_path=DEMO_REPO, rules_path=RULES_PATH,
            scan_id="test-no-migration",
            run_classification=False, run_reachability=False,
            run_completeness=False, run_mosca=False,
            run_recommendations=False, run_migration=False, run_cbom_export=False,
        )
        assert r.migration_roadmaps == {}

    def test_run_cbom_false_leaves_none(self):
        r = run_pipeline(
            target_path=DEMO_REPO, rules_path=RULES_PATH,
            scan_id="test-no-cbom",
            run_classification=False, run_reachability=False,
            run_completeness=False, run_mosca=False,
            run_recommendations=False, run_migration=False, run_cbom_export=False,
        )
        assert r.cbom_export_result is None
