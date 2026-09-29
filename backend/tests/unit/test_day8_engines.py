"""Unit tests — Day 8: Migration Impact Analysis + CBOM Export engines."""
from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from ecdat.engines.migration_impact import (
    FACTOR_NAMES, MigrationImpactEngine, compute_migration_roadmap,
    load_migration_weights, _find_impact_entry, _impact_level,
)
from ecdat.engines.cbom_exporter import (
    CBOMExporter, compute_version_diff, _compute_quality, _purpose_to_primitive,
)
from ecdat.schemas import (
    AssetClassification, BusinessCriticality, CBOMExport, CBOMFormat,
    CBOMMetadata, CryptoAsset, CryptoPurpose, DetectionMethod, Evidence,
    FindingType, LifecycleStage, MigrationPathType, Recommendation, Risk,
    RiskPriority, SensitivityLevel, SourceLocation, StandardizationStatus,
)

REPO_ROOT = Path(__file__).parent.parent.parent.parent
WEIGHTS_PATH = REPO_ROOT / "config" / "migration_weights.yaml"


def _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                with_risk=True, with_recommendation=True, priority="P1",
                source_surface="source_code") -> CryptoAsset:
    ev = Evidence(
        detection_method=DetectionMethod.AST_RULE,
        finding_type=FindingType.DETERMINISTIC, rule_id="R-001",
        location=SourceLocation(file_path="auth_service.py", line_number=29,
                                snippet=f"{algorithm}.call()"),
        source_surface=source_surface, confidence=0.97,
    )
    risk = Risk(mosca_x_years=15.0, mosca_y_years=2.0, mosca_z_years=10.0,
                urgency_flag=True, hndl_flag=True,
                priority=RiskPriority(priority)) if with_risk else None
    rec = Recommendation(
        standardized_replacement="ML-KEM (FIPS 203)",
        migration_path="hybrid: X25519 + ML-KEM",
        migration_path_type=MigrationPathType.HYBRID,
        status=StandardizationStatus.STANDARDIZED,
    ) if with_recommendation else None
    return CryptoAsset(
        algorithm=algorithm, purpose=purpose,
        location="auth_service.py:29", source_surface=source_surface,
        classification=AssetClassification.APPLICATION,
        sensitivity=SensitivityLevel.HIGH,
        business_criticality=BusinessCriticality.CRITICAL,
        lifecycle_stage=LifecycleStage.ACTIVE,
        evidence=ev, risk=risk, recommendation=rec,
    )


# ── Config loader ─────────────────────────────────────────────────────────────

class TestMigrationWeightsConfig:
    def test_loads(self):
        assert load_migration_weights(WEIGHTS_PATH) is not None

    def test_all_8_factors_present(self):
        config = load_migration_weights(WEIGHTS_PATH)
        names = {f.name for f in config.factors}
        for n in FACTOR_NAMES:
            assert n in names

    def test_weights_sum_to_1(self):
        config = load_migration_weights(WEIGHTS_PATH)
        assert abs(sum(f.weight for f in config.factors) - 1.0) < 0.001

    def test_wildcard_entry_present(self):
        config = load_migration_weights(WEIGHTS_PATH)
        assert any(e.algorithm_prefix == "*" for e in config.algorithm_impacts)

    def test_validation_steps_hybrid_present(self):
        config = load_migration_weights(WEIGHTS_PATH)
        assert "hybrid" in config.validation_steps
        assert len(config.validation_steps["hybrid"]) > 0

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_migration_weights(tmp_path / "nope.yaml")


# ── Algorithm lookup ──────────────────────────────────────────────────────────

class TestAlgorithmImpactLookup:
    def setup_method(self):
        self.config = load_migration_weights(WEIGHTS_PATH)

    def _scores(self, alg, purp):
        return _find_impact_entry(self.config, alg, purp).scores

    def test_rsa_key_estab_found(self):
        e = _find_impact_entry(self.config, "RSA-2048", "key_establishment")
        assert "RSA" in e.algorithm_prefix.upper()

    def test_rsa_key_estab_differs_from_sig(self):
        ke = _find_impact_entry(self.config, "RSA-2048", "key_establishment")
        sg = _find_impact_entry(self.config, "RSA-2048", "digital_signature")
        assert ke.scores != sg.scores or ke.purpose != sg.purpose

    def test_hmac_all_zero(self):
        assert all(v == 0.0 for v in self._scores("HMAC", "mac").values())

    def test_sha256_all_zero(self):
        assert all(v == 0.0 for v in self._scores("SHA-256", "hashing").values())

    def test_unknown_alg_uses_wildcard(self):
        e = _find_impact_entry(self.config, "MYSTERY-999", "hashing")
        assert e.algorithm_prefix == "*"

    def test_all_scores_0_to_1(self):
        for entry in self.config.algorithm_impacts:
            for f, s in entry.scores.items():
                assert 0.0 <= s <= 1.0, f"{entry.algorithm_prefix}/{f}={s}"


# ── Roadmap computation ───────────────────────────────────────────────────────

class TestMigrationRoadmap:
    def setup_method(self):
        self.config = load_migration_weights(WEIGHTS_PATH)
        self.asset = _make_asset("RSA-2048", "key_establishment")

    def test_current_state_contains_algorithm(self):
        r = compute_migration_roadmap(self.asset, self.config)
        assert "RSA-2048" in r.current_state

    def test_risk_context_nonempty(self):
        r = compute_migration_roadmap(self.asset, self.config)
        assert len(r.risk_context) > 0

    def test_recommendation_action_contains_ml_kem(self):
        r = compute_migration_roadmap(self.asset, self.config)
        assert "ML-KEM" in r.recommendation_action or "Migrate" in r.recommendation_action

    def test_affected_components_nonempty(self):
        r = compute_migration_roadmap(self.asset, self.config)
        assert len(r.affected_components) > 0

    def test_validation_steps_nonempty(self):
        r = compute_migration_roadmap(self.asset, self.config)
        assert len(r.validation_steps) > 0

    def test_narrative_has_arrows(self):
        r = compute_migration_roadmap(self.asset, self.config)
        assert r.narrative.count("→") >= 4

    def test_composite_score_in_range(self):
        r = compute_migration_roadmap(self.asset, self.config)
        assert 0.0 <= r.composite_impact_score <= 1.0

    def test_8_factor_scores(self):
        r = compute_migration_roadmap(self.asset, self.config)
        assert len(r.factor_scores) == 8

    def test_impact_level_low(self):      assert _impact_level(0.1) == "low"
    def test_impact_level_moderate(self): assert _impact_level(0.3) == "moderate"
    def test_impact_level_high(self):     assert _impact_level(0.6) == "high"
    def test_impact_level_critical(self): assert _impact_level(0.9) == "critical"

    def test_p1_priority_is_immediate(self):
        r = compute_migration_roadmap(_make_asset("RSA-2048", "key_establishment", priority="P1"), self.config)
        assert r.migration_priority == "immediate"

    def test_p4_priority_is_monitor(self):
        r = compute_migration_roadmap(_make_asset("SHA-256", "hashing", priority="P4"), self.config)
        assert r.migration_priority == "monitor"

    def test_hmac_zero_composite(self):
        r = compute_migration_roadmap(_make_asset("HMAC", "mac"), self.config)
        assert r.composite_impact_score == pytest.approx(0.0)

    def test_summary_is_serialisable(self):
        r = compute_migration_roadmap(self.asset, self.config)
        json.dumps(r.summary())


# ── Migration engine batch ────────────────────────────────────────────────────

class TestMigrationImpactEngine:
    def test_returns_same_assets_list(self):
        engine = MigrationImpactEngine(weights_path=WEIGHTS_PATH)
        assets = [_make_asset()]
        returned, _ = engine.process(assets)
        assert returned is assets

    def test_asset_without_recommendation_excluded_from_roadmaps(self):
        engine = MigrationImpactEngine(weights_path=WEIGHTS_PATH)
        _, roadmaps = engine.process([
            _make_asset(with_recommendation=True),
            _make_asset("MD5", "hashing", with_recommendation=False),
        ])
        assert len(roadmaps) == 1

    def test_stats_immediate_counted(self):
        engine = MigrationImpactEngine(weights_path=WEIGHTS_PATH)
        engine.process([_make_asset("RSA-2048", "key_establishment", priority="P1")])
        assert engine.stats.immediate == 1

    def test_assets_not_mutated(self):
        engine = MigrationImpactEngine(weights_path=WEIGHTS_PATH)
        asset = _make_asset()
        orig_id = asset.asset_id
        engine.process([asset])
        assert asset.asset_id == orig_id


# ── CBOM Exporter ─────────────────────────────────────────────────────────────

class TestCBOMExporter:
    def setup_method(self):
        self.exporter = CBOMExporter()
        self.asset = _make_asset("RSA-2048", "key_establishment")

    def test_produces_nonempty_json(self):
        r = self.exporter.export_json([self.asset], "scan-001", "demo_repo")
        assert len(r.document) > 0

    def test_json_is_valid(self):
        r = self.exporter.export_json([self.asset], "scan-001", "demo_repo")
        doc = json.loads(r.document)
        assert "components" in doc

    def test_asset_id_appears_as_bom_ref(self):
        r = self.exporter.export_json([self.asset], "scan-001", "demo_repo")
        doc = json.loads(r.document)
        refs = [c["bom-ref"] for c in doc["components"]]
        assert self.asset.asset_id in refs

    def test_ecdat_location_property_present(self):
        r = self.exporter.export_json([self.asset], "scan-001", "demo_repo")
        doc = json.loads(r.document)
        comp = doc["components"][0]
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert "ecdat:location" in props
        assert "auth_service.py" in props["ecdat:location"]

    def test_risk_priority_property_present_when_risk_set(self):
        r = self.exporter.export_json([self.asset], "scan-001", "demo_repo")
        doc = json.loads(r.document)
        comp = doc["components"][0]
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert "ecdat:risk.priority" in props
        assert props["ecdat:risk.priority"] == "P1"

    def test_algorithm_asset_type_is_algorithm(self):
        r = self.exporter.export_json([self.asset], "scan-001", "demo_repo")
        doc = json.loads(r.document)
        comp = doc["components"][0]
        assert comp["cryptoProperties"]["assetType"] == "algorithm"

    def test_certificate_asset_type_is_certificate(self):
        cert_asset = _make_asset(
            "RSA-2048", "key_establishment", source_surface="certificate"
        )
        r = self.exporter.export_json([cert_asset], "scan-001", "demo_repo")
        doc = json.loads(r.document)
        comp = doc["components"][0]
        assert comp["cryptoProperties"]["assetType"] == "certificate"

    def test_component_count_matches_assets(self):
        assets = [_make_asset("RSA-2048", "key_establishment"),
                  _make_asset("MD5", "hashing")]
        r = self.exporter.export_json(assets, "scan-001", "demo_repo")
        assert r.component_count == 2

    def test_xml_export_nonempty(self):
        r = self.exporter.export_xml([self.asset], "scan-001", "demo_repo")
        assert len(r.document) > 0
        assert "<?xml" in r.document or "<bom" in r.document

    def test_cbom_export_pydantic_model_populated(self):
        r = self.exporter.export_json([self.asset], "scan-001", "demo_repo")
        assert r.cbom_export is not None
        assert r.cbom_export.metadata.scan_id == "scan-001"
        assert len(r.cbom_export.assets) == 1


# ── Quality score ─────────────────────────────────────────────────────────────

class TestCBOMQualityScore:
    def test_full_inventory_evidence_coverage_1(self):
        assets = [_make_asset()]
        q = _compute_quality(assets, total_raw_findings=1, total_unique_assets=1)
        assert q.evidence_coverage == 1.0

    def test_risk_coverage_1_when_all_have_risk(self):
        assets = [_make_asset(with_risk=True)]
        q = _compute_quality(assets, total_raw_findings=1, total_unique_assets=1)
        assert q.risk_coverage == 1.0

    def test_risk_coverage_0_when_no_risk(self):
        assets = [_make_asset(with_risk=False, with_recommendation=False)]
        q = _compute_quality(assets, total_raw_findings=1, total_unique_assets=1)
        assert q.risk_coverage == 0.0

    def test_rec_coverage_0_when_no_recommendation(self):
        assets = [_make_asset(with_risk=True, with_recommendation=False)]
        q = _compute_quality(assets, total_raw_findings=1, total_unique_assets=1)
        assert q.recommendation_coverage == 0.0

    def test_duplicate_rate_computed(self):
        # 4 raw findings → 2 unique = 2 duplicates → 50% rate
        assets = [_make_asset(), _make_asset("MD5", "hashing")]
        q = _compute_quality(assets, total_raw_findings=4, total_unique_assets=2)
        assert q.duplicate_rate == pytest.approx(0.5)

    def test_overall_quality_in_0_1(self):
        assets = [_make_asset()]
        q = _compute_quality(assets, total_raw_findings=1, total_unique_assets=1)
        assert 0.0 <= q.overall_quality <= 1.0

    def test_empty_inventory_all_zeros(self):
        q = _compute_quality([], total_raw_findings=0, total_unique_assets=0)
        assert q.overall_quality == 0.0


# ── Purpose to primitive mapping ──────────────────────────────────────────────

class TestPurposeToPrimitive:
    def test_key_establishment_is_kem(self):
        from cyclonedx.model.crypto import CryptoPrimitive
        assert _purpose_to_primitive("key_establishment") == CryptoPrimitive.KEM

    def test_digital_signature_is_signature(self):
        from cyclonedx.model.crypto import CryptoPrimitive
        assert _purpose_to_primitive("digital_signature") == CryptoPrimitive.SIGNATURE

    def test_hashing_is_hash(self):
        from cyclonedx.model.crypto import CryptoPrimitive
        assert _purpose_to_primitive("hashing") == CryptoPrimitive.HASH

    def test_unknown_is_unknown(self):
        from cyclonedx.model.crypto import CryptoPrimitive
        assert _purpose_to_primitive("unknown") == CryptoPrimitive.UNKNOWN


# ── Version diff ──────────────────────────────────────────────────────────────

class TestVersionDiff:
    def _make_cbom(self, assets, scan_id="scan-001"):
        meta = CBOMMetadata(ecdat_version="0.1.0", scan_id=scan_id,
                             scanned_targets=["demo"], input_surfaces=["source_code"])
        return CBOMExport(metadata=meta, assets=assets)

    def test_identical_exports_produce_empty_diff(self):
        asset = _make_asset()
        cbom = self._make_cbom([asset])
        diff = compute_version_diff(cbom, cbom)
        assert diff.new_assets == []
        assert diff.removed_assets == []
        assert diff.changed_assets == []

    def test_new_asset_detected(self):
        a1 = _make_asset("RSA-2048", "key_establishment")
        a2 = _make_asset("MD5", "hashing")
        baseline = self._make_cbom([a1], "scan-001")
        current = self._make_cbom([a1, a2], "scan-002")
        diff = compute_version_diff(baseline, current)
        assert a2.asset_id in diff.new_assets
        assert diff.removed_assets == []

    def test_removed_asset_detected(self):
        a1 = _make_asset("RSA-2048", "key_establishment")
        a2 = _make_asset("MD5", "hashing")
        baseline = self._make_cbom([a1, a2], "scan-001")
        current = self._make_cbom([a1], "scan-002")
        diff = compute_version_diff(baseline, current)
        assert a2.asset_id in diff.removed_assets
        assert diff.new_assets == []

    def test_changed_asset_detected(self):
        original = _make_asset("RSA-2048", "key_establishment", priority="P2")
        changed = original.model_copy(
            update={"risk": Risk(
                mosca_x_years=15.0, mosca_y_years=2.0, mosca_z_years=10.0,
                urgency_flag=True, hndl_flag=True, priority=RiskPriority.P1,
            )}
        )
        baseline = self._make_cbom([original], "scan-001")
        current = self._make_cbom([changed], "scan-002")
        diff = compute_version_diff(baseline, current)
        assert original.asset_id in diff.changed_assets

    def test_diff_scan_ids_correct(self):
        a = _make_asset()
        b1 = self._make_cbom([a], "baseline-001")
        b2 = self._make_cbom([a], "current-002")
        diff = compute_version_diff(b1, b2)
        assert diff.baseline_scan_id == "baseline-001"
        assert diff.current_scan_id == "current-002"
