"""
Unit tests — inventory.py

Tests deduplication, merging, and query operations on CryptoAssetInventory.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ecdat.engines.inventory import CryptoAssetInventory, _dedup_key
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


def _make_asset(
    algorithm="MD5",
    purpose="hashing",
    file_path="auth_service.py",
    line_number=38,
    confidence=0.97,
    rule_id="R-007",
) -> CryptoAsset:
    evidence = Evidence(
        detection_method=DetectionMethod.AST_RULE,
        finding_type=FindingType.DETERMINISTIC,
        rule_id=rule_id,
        location=SourceLocation(file_path=file_path, line_number=line_number),
        source_surface="source_code",
        confidence=confidence,
    )
    return CryptoAsset(
        algorithm=algorithm,
        purpose=purpose,
        location=f"{file_path}:{line_number}",
        source_surface="source_code",
        classification=AssetClassification.APPLICATION,
        sensitivity=SensitivityLevel.HIGH,
        business_criticality=BusinessCriticality.HIGH,
        lifecycle_stage=LifecycleStage.ACTIVE,
        evidence=evidence,
    )


class TestDedupKey:
    def test_same_asset_same_key(self):
        a1 = _make_asset()
        a2 = _make_asset()
        assert _dedup_key(a1) == _dedup_key(a2)

    def test_different_algorithm_different_key(self):
        a1 = _make_asset(algorithm="MD5")
        a2 = _make_asset(algorithm="SHA-1")
        assert _dedup_key(a1) != _dedup_key(a2)

    def test_different_line_different_key(self):
        a1 = _make_asset(line_number=10)
        a2 = _make_asset(line_number=20)
        assert _dedup_key(a1) != _dedup_key(a2)

    def test_different_file_different_key(self):
        a1 = _make_asset(file_path="file_a.py")
        a2 = _make_asset(file_path="file_b.py")
        assert _dedup_key(a1) != _dedup_key(a2)

    def test_different_purpose_different_key(self):
        a1 = _make_asset(algorithm="RSA", purpose="key_establishment")
        a2 = _make_asset(algorithm="RSA", purpose="digital_signature")
        assert _dedup_key(a1) != _dedup_key(a2)


class TestInventoryAddAsset:
    def test_first_asset_added(self):
        inv = CryptoAssetInventory()
        a = _make_asset()
        added = inv.add_asset(a)
        assert added is True
        assert inv.stats.unique_assets == 1

    def test_duplicate_not_added_twice(self):
        inv = CryptoAssetInventory()
        a1 = _make_asset()
        a2 = _make_asset()   # identical dedup key
        inv.add_asset(a1)
        added = inv.add_asset(a2)
        assert added is False
        assert inv.stats.unique_assets == 1
        assert inv.stats.duplicates_removed == 1

    def test_total_findings_counts_duplicates(self):
        inv = CryptoAssetInventory()
        a1 = _make_asset()
        a2 = _make_asset()
        inv.add_asset(a1)
        inv.add_asset(a2)
        assert inv.stats.total_findings == 2

    def test_higher_confidence_replaces_lower(self):
        inv = CryptoAssetInventory()
        low = _make_asset(confidence=0.70)
        high = _make_asset(confidence=0.95)
        inv.add_asset(low)
        inv.add_asset(high)
        # The stored asset should have the higher confidence
        assert inv.assets[0].evidence.confidence == pytest.approx(0.95)

    def test_lower_confidence_does_not_replace_higher(self):
        inv = CryptoAssetInventory()
        high = _make_asset(confidence=0.95)
        low = _make_asset(confidence=0.70)
        inv.add_asset(high)
        inv.add_asset(low)
        assert inv.assets[0].evidence.confidence == pytest.approx(0.95)

    def test_two_different_files_are_separate_assets(self):
        inv = CryptoAssetInventory()
        a1 = _make_asset(file_path="file_a.py")
        a2 = _make_asset(file_path="file_b.py")
        inv.add_asset(a1)
        inv.add_asset(a2)
        assert inv.stats.unique_assets == 2

    def test_two_different_algorithms_are_separate(self):
        inv = CryptoAssetInventory()
        inv.add_asset(_make_asset(algorithm="MD5"))
        inv.add_asset(_make_asset(algorithm="SHA-1", line_number=50))
        assert inv.stats.unique_assets == 2

    def test_algorithm_counter_populated(self):
        inv = CryptoAssetInventory()
        inv.add_asset(_make_asset(algorithm="MD5", line_number=10))
        inv.add_asset(_make_asset(algorithm="MD5", line_number=50))  # different line = unique
        assert "MD5" in inv.stats.algorithms_found
        # Both are unique assets (different lines), so counter = 2
        assert inv.stats.algorithms_found["MD5"] == 2


class TestInventoryQuery:
    def setup_method(self):
        self.inv = CryptoAssetInventory()
        self.inv.add_asset(_make_asset(algorithm="MD5", purpose="hashing", line_number=10))
        self.inv.add_asset(_make_asset(algorithm="RSA-2048", purpose="key_establishment", line_number=20))
        self.inv.add_asset(_make_asset(algorithm="SHA-1", purpose="hashing", line_number=30,
                                        file_path="crypto_utils.py"))

    def test_get_by_algorithm(self):
        results = self.inv.get_by_algorithm("MD5")
        assert len(results) == 1
        assert results[0].algorithm == "MD5"

    def test_get_by_algorithm_prefix(self):
        results = self.inv.get_by_algorithm("RSA")
        assert len(results) == 1

    def test_get_by_purpose_hashing(self):
        results = self.inv.get_by_purpose("hashing")
        assert len(results) == 2

    def test_get_by_purpose_key_establishment(self):
        results = self.inv.get_by_purpose("key_establishment")
        assert len(results) == 1

    def test_get_by_file(self):
        results = self.inv.get_by_file("crypto_utils.py")
        assert len(results) == 1
        assert results[0].algorithm == "SHA-1"

    def test_assets_sorted_by_location(self):
        assets = self.inv.assets
        lines = [a.evidence.location.line_number for a in assets]
        assert lines == sorted(lines)

    def test_summary_structure(self):
        summary = self.inv.summary()
        assert "unique_assets" in summary
        assert "total_findings" in summary
        assert "duplicate_rate" in summary
        assert summary["unique_assets"] == 3


class TestInventoryStats:
    def test_duplicate_rate_zero_with_no_duplicates(self):
        inv = CryptoAssetInventory()
        inv.add_asset(_make_asset(line_number=1))
        inv.add_asset(_make_asset(line_number=2))
        assert inv.stats.duplicate_rate == 0.0

    def test_duplicate_rate_fifty_percent(self):
        inv = CryptoAssetInventory()
        inv.add_asset(_make_asset())        # unique
        inv.add_asset(_make_asset())        # duplicate of first
        assert inv.stats.total_findings == 2
        assert inv.stats.duplicates_removed == 1
        assert inv.stats.duplicate_rate == pytest.approx(0.5)

    def test_empty_inventory_duplicate_rate_zero(self):
        inv = CryptoAssetInventory()
        assert inv.stats.duplicate_rate == 0.0
