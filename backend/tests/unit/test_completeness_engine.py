"""
Unit tests — completeness_engine.py (Day 5)

Validates:
  1.  Surface coverage: scanned / skipped / unavailable states
  2.  Category coverage: found vs expected
  3.  Completeness percentages (surface, category, overall)
  4.  Weighted average formula: 30% surface + 70% category
  5.  Missing expected categories reported
  6.  Unscanned surfaces reported
  7.  Notes generated for gaps
  8.  summary() dict is serialisable and complete
  9.  Edge cases: no assets, all categories found, no expected categories
  10. Correct total_assets and total_raw_findings counts
"""

from __future__ import annotations

import pytest
from pathlib import Path
from dataclasses import dataclass, field

from ecdat.engines.completeness_engine import (
    ALL_SURFACES,
    ALGORITHM_CATEGORIES,
    DEFAULT_EXPECTED_CATEGORIES,
    DiscoveryCompletenessEngine,
    DiscoveryCompletenessResult,
    SurfaceStatus,
)
from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    LifecycleStage,
    SensitivityLevel,
    SourceLocation,
)

# ── Minimal scan result mock ───────────────────────────────────────────────────

@dataclass
class MockScanResult:
    """Minimal mock of DirectoryScanResult for completeness tests."""
    files_scanned: int = 5
    files_skipped: int = 1
    total_lines: int = 220
    total_matches: int = 16
    root_path: Path = Path("test_repos/demo_app")
    file_results: list = field(default_factory=list)


# ── Asset factory ─────────────────────────────────────────────────────────────

def _make_asset(
    algorithm: str = "RSA-2048",
    purpose: str = "key_establishment",
    source_surface: str = "source_code",
) -> CryptoAsset:
    evidence = Evidence(
        detection_method=DetectionMethod.AST_RULE,
        finding_type=FindingType.DETERMINISTIC,
        rule_id="R-001",
        location=SourceLocation(file_path="auth_service.py", line_number=10),
        source_surface=source_surface,
        confidence=0.97,
    )
    return CryptoAsset(
        algorithm=algorithm,
        purpose=purpose,
        location="auth_service.py:10",
        source_surface=source_surface,
        classification=AssetClassification.APPLICATION,
        sensitivity=SensitivityLevel.HIGH,
        business_criticality=BusinessCriticality.CRITICAL,
        lifecycle_stage=LifecycleStage.ACTIVE,
        evidence=evidence,
    )


def _make_full_asset_set() -> list[CryptoAsset]:
    """A diverse set covering all DEFAULT_EXPECTED_CATEGORIES."""
    return [
        _make_asset("RSA-2048", "key_establishment"),
        _make_asset("MD5", "hashing"),
        _make_asset("SHA-256", "hashing"),
        _make_asset("AES-256", "encryption"),
        _make_asset("ECDSA-P256", "digital_signature"),
        _make_asset("HMAC", "mac"),
    ]


# ── 1. Surface coverage ───────────────────────────────────────────────────────

class TestSurfaceCoverage:
    def test_scanned_surfaces_marked_scanned(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        sc_map = {sc.surface: sc.status for sc in result.surface_coverage}
        assert sc_map["source_code"] == SurfaceStatus.SCANNED

    def test_unscanned_surfaces_marked_unavailable(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        sc_map = {sc.surface: sc.status for sc in result.surface_coverage}
        for surface in ["binary", "container", "certificate", "infrastructure"]:
            assert sc_map[surface] == SurfaceStatus.UNAVAILABLE

    def test_all_surfaces_present_in_coverage(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[],
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        covered = {sc.surface for sc in result.surface_coverage}
        assert covered == set(ALL_SURFACES)

    def test_surfaces_scanned_count(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        assert result.surfaces_scanned == 1

    def test_unscanned_surfaces_list_populated(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        assert len(result.unscanned_surfaces) == 4
        assert "binary" in result.unscanned_surfaces

    def test_source_code_surface_has_file_counts(self):
        scan = MockScanResult(files_scanned=10, files_skipped=2)
        engine = DiscoveryCompletenessEngine(
            scan_result=scan,
            assets=[_make_asset()],
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        src = next(sc for sc in result.surface_coverage if sc.surface == "source_code")
        assert src.files_scanned == 10
        assert src.files_skipped == 2

    def test_assets_found_per_surface(self):
        assets = [
            _make_asset(source_surface="source_code"),
            _make_asset(algorithm="MD5", source_surface="source_code"),
        ]
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=assets,
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        src = next(sc for sc in result.surface_coverage if sc.surface == "source_code")
        assert src.assets_found == 2


# ── 2. Category coverage ──────────────────────────────────────────────────────

class TestCategoryCoverage:
    def test_found_category_marked_found(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset("RSA-2048", "key_establishment")],
            expected_categories={"key_establishment"},
        )
        result = engine.compute()
        key_cat = next(
            cc for cc in result.category_coverage
            if cc.category == "key_establishment"
        )
        assert key_cat.found is True

    def test_missing_category_not_found(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset("RSA-2048", "key_establishment")],
            expected_categories={"key_establishment", "hashing"},
        )
        result = engine.compute()
        hash_cat = next(cc for cc in result.category_coverage if cc.category == "hashing")
        assert hash_cat.found is False

    def test_expected_flag_set_correctly(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
            expected_categories={"key_establishment"},
        )
        result = engine.compute()
        key_cat = next(
            cc for cc in result.category_coverage
            if cc.category == "key_establishment"
        )
        hash_cat = next(cc for cc in result.category_coverage if cc.category == "hashing")
        assert key_cat.expected is True
        assert hash_cat.expected is False   # not in expected set

    def test_categories_found_count(self):
        assets = _make_full_asset_set()
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=assets,
            expected_categories=DEFAULT_EXPECTED_CATEGORIES,
        )
        result = engine.compute()
        assert result.categories_found == len(DEFAULT_EXPECTED_CATEGORIES)

    def test_missing_expected_categories_list(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[],
            expected_categories={"hashing", "key_establishment"},
        )
        result = engine.compute()
        assert "hashing" in result.missing_expected_categories
        assert "key_establishment" in result.missing_expected_categories

    def test_algorithms_found_per_category(self):
        assets = [
            _make_asset("MD5", "hashing"),
            _make_asset("SHA-256", "hashing"),
        ]
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=assets,
            expected_categories={"hashing"},
        )
        result = engine.compute()
        hash_cat = next(cc for cc in result.category_coverage if cc.category == "hashing")
        assert "MD5" in hash_cat.algorithms_found
        assert "SHA-256" in hash_cat.algorithms_found


# ── 3. Completeness percentages ──────────────────────────────────────────────

class TestCompletenessPercentages:
    def test_surface_completeness_1_of_5(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        assert result.surface_completeness_pct == pytest.approx(20.0)  # 1/5 × 100

    def test_category_completeness_100_percent(self):
        assets = _make_full_asset_set()
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=assets,
            expected_categories=DEFAULT_EXPECTED_CATEGORIES,
        )
        result = engine.compute()
        assert result.category_completeness_pct == pytest.approx(100.0)

    def test_category_completeness_zero_when_nothing_found(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[],
            expected_categories={"hashing", "key_establishment"},
        )
        result = engine.compute()
        assert result.category_completeness_pct == pytest.approx(0.0)

    def test_overall_completeness_weighted_average(self):
        """overall = 0.3 × surface + 0.7 × category"""
        assets = _make_full_asset_set()
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=assets,
            scanned_surfaces=["source_code"],
            expected_categories=DEFAULT_EXPECTED_CATEGORIES,
        )
        result = engine.compute()
        expected = 0.3 * result.surface_completeness_pct + 0.7 * result.category_completeness_pct
        assert result.overall_completeness_pct == pytest.approx(expected, abs=0.1)

    def test_overall_completeness_bounded_0_to_100(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=_make_full_asset_set(),
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        assert 0.0 <= result.overall_completeness_pct <= 100.0

    def test_no_expected_categories_gives_100_percent(self):
        """If nothing is expected, 100% of expectations are met."""
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[],
            expected_categories=set(),
        )
        result = engine.compute()
        assert result.category_completeness_pct == pytest.approx(100.0)


# ── 4. Notes and counts ───────────────────────────────────────────────────────

class TestNotesAndCounts:
    def test_notes_mention_skipped_files(self):
        scan = MockScanResult(files_skipped=3)
        engine = DiscoveryCompletenessEngine(
            scan_result=scan,
            assets=[_make_asset()],
        )
        result = engine.compute()
        notes_text = " ".join(result.notes)
        assert "3 files" in notes_text or "skipped" in notes_text.lower()

    def test_notes_mention_unscanned_surfaces(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
            scanned_surfaces=["source_code"],
        )
        result = engine.compute()
        notes_text = " ".join(result.notes)
        assert "unscanned" in notes_text.lower() or "surfaces" in notes_text.lower()

    def test_notes_mention_missing_categories(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[],
            expected_categories={"hashing"},
        )
        result = engine.compute()
        notes_text = " ".join(result.notes)
        assert "hashing" in notes_text.lower() or "not found" in notes_text.lower()

    def test_no_assets_note_generated(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[],
        )
        result = engine.compute()
        notes_text = " ".join(result.notes)
        assert "no cryptographic assets" in notes_text.lower()

    def test_total_assets_count(self):
        assets = _make_full_asset_set()
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(total_matches=20),
            assets=assets,
        )
        result = engine.compute()
        assert result.total_assets_discovered == len(assets)
        assert result.total_raw_findings == 20


# ── 5. Summary dict ───────────────────────────────────────────────────────────

class TestSummaryDict:
    def test_summary_is_dict(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
        )
        result = engine.compute()
        summary = result.summary()
        assert isinstance(summary, dict)

    def test_summary_has_required_keys(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[_make_asset()],
        )
        result = engine.compute()
        summary = result.summary()
        required = [
            "overall_completeness_pct", "surface_completeness_pct",
            "category_completeness_pct", "surfaces_scanned", "surfaces_total",
            "categories_found", "categories_expected",
            "total_assets_discovered", "total_raw_findings",
            "missing_expected_categories", "unscanned_surfaces",
            "surface_detail", "category_detail", "notes",
        ]
        for key in required:
            assert key in summary, f"Missing key: {key}"

    def test_summary_is_json_serialisable(self):
        import json
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=_make_full_asset_set(),
        )
        result = engine.compute()
        # Should not raise
        json.dumps(result.summary())

    def test_surface_detail_has_all_surfaces(self):
        engine = DiscoveryCompletenessEngine(
            scan_result=MockScanResult(),
            assets=[],
        )
        result = engine.compute()
        surfaces_in_detail = {d["surface"] for d in result.summary()["surface_detail"]}
        assert surfaces_in_detail == set(ALL_SURFACES)
