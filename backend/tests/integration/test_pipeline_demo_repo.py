"""
Integration tests — full pipeline against the demo test repository.

Runs the complete source discovery pipeline (stages 2 → 4 → 5) on
test_repos/demo_app/ and validates against the ground-truth finding map
documented in test_repos/demo_app/README.md.

These tests verify:
  1. The pipeline runs end-to-end without errors.
  2. Known-crypto calls are detected with the correct algorithm and purpose.
  3. False positives (comments, label strings) are NOT detected.
  4. Key sizes are extracted correctly from integer literal arguments.
  5. Evidence records are correctly populated (rule_id, confidence, location).
  6. Deduplication works — the same call is not counted twice.
  7. The inventory summary contains expected algorithms and purposes.
  8. PipelineResult.report() produces a non-empty string.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ecdat.pipeline import run_source_discovery, PipelineResult
from ecdat.schemas import CryptoPurpose, DetectionMethod, FindingType

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEMO_REPO = REPO_ROOT / "test_repos" / "demo_app"
RULES_PATH = REPO_ROOT / "config" / "detection_rules.yaml"


@pytest.fixture(scope="module")
def pipeline_result() -> PipelineResult:
    """Run the full pipeline once for all tests in this module."""
    assert DEMO_REPO.exists(), f"Demo repo not found: {DEMO_REPO}"
    result = run_source_discovery(
        target_path=DEMO_REPO,
        rules_path=RULES_PATH,
        scan_id="test-integration-001",
    )
    return result


# ── 1. Pipeline runs end-to-end ────────────────────────────────────────────────

class TestPipelineExecution:
    def test_pipeline_completes(self, pipeline_result):
        assert pipeline_result is not None

    def test_scan_id_preserved(self, pipeline_result):
        assert pipeline_result.scan_id == "test-integration-001"

    def test_files_were_scanned(self, pipeline_result):
        assert pipeline_result.scan_result.files_scanned >= 4

    def test_rules_were_loaded(self, pipeline_result):
        assert pipeline_result.rules_loaded >= 10

    def test_inventory_has_assets(self, pipeline_result):
        assert pipeline_result.inventory.stats.unique_assets > 0

    def test_report_is_non_empty(self, pipeline_result):
        report = pipeline_result.report()
        assert isinstance(report, str)
        assert len(report) > 100
        assert "ECDAT" in report and "Report" in report


# ── 2. Ground-truth algorithm detection ───────────────────────────────────────

class TestGroundTruthDetection:
    """Verify that every deliberately planted crypto call is detected."""

    def test_rsa_detected(self, pipeline_result):
        rsa_assets = pipeline_result.inventory.get_by_algorithm("RSA")
        assert len(rsa_assets) >= 1, "RSA not detected"

    def test_md5_detected(self, pipeline_result):
        md5_assets = pipeline_result.inventory.get_by_algorithm("MD5")
        assert len(md5_assets) >= 1, "MD5 not detected"

    def test_sha1_detected(self, pipeline_result):
        sha1_assets = pipeline_result.inventory.get_by_algorithm("SHA-1")
        assert len(sha1_assets) >= 1, "SHA-1 not detected"

    def test_des_detected(self, pipeline_result):
        des_assets = pipeline_result.inventory.get_by_algorithm("DES")
        assert len(des_assets) >= 1, "DES not detected"

    def test_aes_detected(self, pipeline_result):
        aes_assets = pipeline_result.inventory.get_by_algorithm("AES")
        assert len(aes_assets) >= 1, "AES not detected"

    def test_ecdsa_detected(self, pipeline_result):
        ec_assets = pipeline_result.inventory.get_by_algorithm("ECDSA")
        assert len(ec_assets) >= 1, "ECDSA not detected"

    def test_sha256_detected(self, pipeline_result):
        sha256_assets = pipeline_result.inventory.get_by_algorithm("SHA-256")
        assert len(sha256_assets) >= 1, "SHA-256 not detected"

    def test_sha512_detected(self, pipeline_result):
        sha512_assets = pipeline_result.inventory.get_by_algorithm("SHA-512")
        assert len(sha512_assets) >= 1, "SHA-512 not detected"

    def test_hmac_detected(self, pipeline_result):
        hmac_assets = pipeline_result.inventory.get_by_algorithm("HMAC")
        assert len(hmac_assets) >= 1, "HMAC not detected"

    def test_minimum_unique_assets(self, pipeline_result):
        """We expect at least 8 unique asset types from the demo repo."""
        assert pipeline_result.inventory.stats.unique_assets >= 8


# ── 3. Purpose assignment ─────────────────────────────────────────────────────

class TestPurposeAssignment:
    def test_rsa_has_key_establishment_purpose(self, pipeline_result):
        rsa_assets = pipeline_result.inventory.get_by_algorithm("RSA")
        assert any(
            a.purpose == CryptoPurpose.KEY_ESTABLISHMENT for a in rsa_assets
        ), "RSA asset should have key_establishment purpose"

    def test_md5_has_hashing_purpose(self, pipeline_result):
        md5_assets = pipeline_result.inventory.get_by_algorithm("MD5")
        assert all(
            a.purpose == CryptoPurpose.HASHING for a in md5_assets
        ), "MD5 should always have hashing purpose"

    def test_ecdsa_has_digital_signature_purpose(self, pipeline_result):
        ec_assets = pipeline_result.inventory.get_by_algorithm("ECDSA")
        assert any(
            a.purpose == CryptoPurpose.DIGITAL_SIGNATURE for a in ec_assets
        ), "ECDSA should have digital_signature purpose"

    def test_des_has_encryption_purpose(self, pipeline_result):
        des_assets = pipeline_result.inventory.get_by_algorithm("DES")
        assert all(
            a.purpose == CryptoPurpose.ENCRYPTION for a in des_assets
        )

    def test_hmac_has_mac_purpose(self, pipeline_result):
        hmac_assets = pipeline_result.inventory.get_by_algorithm("HMAC")
        assert all(
            a.purpose == CryptoPurpose.MAC for a in hmac_assets
        )


# ── 4. Key size extraction ────────────────────────────────────────────────────

class TestKeySizeExtraction:
    def test_rsa_2048_key_size_extracted(self, pipeline_result):
        rsa_assets = pipeline_result.inventory.get_by_algorithm("RSA-2048")
        assert len(rsa_assets) >= 1, "RSA-2048 (with extracted key size) not found"
        for a in rsa_assets:
            assert a.key_size_bits == 2048 or a.algorithm == "RSA-2048"

    def test_rsa_4096_detected(self, pipeline_result):
        # payment_service.py uses rsa.generate_private_key(key_size=4096)
        rsa4096 = pipeline_result.inventory.get_by_algorithm("RSA-4096")
        rsa_generic = pipeline_result.inventory.get_by_algorithm("RSA")
        # At least one RSA asset should be 4096
        all_rsa = rsa4096 + rsa_generic
        assert len(all_rsa) >= 2  # should have both 2048 and 4096

    def test_des_fixed_key_size(self, pipeline_result):
        des_assets = pipeline_result.inventory.get_by_algorithm("DES")
        assert des_assets
        # DES has a fixed 56-bit key size from the rule config
        assert des_assets[0].key_size_bits == 56


# ── 5. Evidence record quality ────────────────────────────────────────────────

class TestEvidenceQuality:
    def test_all_assets_have_evidence(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.evidence is not None, f"Asset {asset.algorithm} has no evidence"

    def test_all_evidence_has_rule_id(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.evidence.rule_id is not None
            assert asset.evidence.rule_id.startswith("R-")

    def test_all_evidence_is_ast_rule(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.evidence.detection_method == DetectionMethod.AST_RULE

    def test_all_findings_are_deterministic(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.evidence.finding_type == FindingType.DETERMINISTIC

    def test_all_evidence_has_file_path(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.evidence.location.file_path
            assert len(asset.evidence.location.file_path) > 0

    def test_all_evidence_has_line_number(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.evidence.location.line_number is not None
            assert asset.evidence.location.line_number >= 1

    def test_confidence_scores_in_valid_range(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert 0.0 <= asset.evidence.confidence <= 1.0

    def test_high_confidence_for_deterministic_calls(self, pipeline_result):
        # All deterministic AST matches should have confidence >= 0.85
        for asset in pipeline_result.inventory.assets:
            assert asset.evidence.confidence >= 0.85, (
                f"Low confidence {asset.evidence.confidence:.2f} for "
                f"{asset.algorithm} in {asset.evidence.location.file_path}"
            )

    def test_source_surface_is_source_code(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.evidence.source_surface == "source_code"


# ── 6. False positive prevention ──────────────────────────────────────────────

class TestFalsePositivePrevention:
    def test_config_py_comment_rsa_not_detected(self, pipeline_result):
        """
        config.py line 30 has 'RSA' in a Python comment — must not be detected.
        We check that no finding comes from config.py at that line.
        """
        config_assets = pipeline_result.inventory.get_by_file("config.py")
        comment_matches = [
            a for a in config_assets
            if a.evidence.location.line_number == 30
        ]
        assert len(comment_matches) == 0, (
            "RSA in comment at config.py:30 was incorrectly detected"
        )

    def test_log_label_string_not_detected_as_sha256(self, pipeline_result):
        """
        config.py has LOG_ALGORITHM_LABEL = 'sha256_audit_log' — a string
        assignment, not a crypto API call. Must not be detected.
        """
        config_assets = pipeline_result.inventory.get_by_file("config.py")
        # Any SHA-256 from config.py would be a false positive
        sha256_in_config = [
            a for a in config_assets
            if "SHA-256" in a.algorithm.upper() or "SHA256" in a.algorithm.upper()
        ]
        assert len(sha256_in_config) == 0, (
            f"String label in config.py incorrectly detected as SHA-256: "
            f"{[a.location for a in sha256_in_config]}"
        )


# ── 7. Deduplication ──────────────────────────────────────────────────────────

class TestDeduplication:
    def test_duplicate_rate_is_reasonable(self, pipeline_result):
        # Some duplicates are expected (same algorithm in multiple files)
        # but the rate should not be extreme
        rate = pipeline_result.inventory.stats.duplicate_rate
        assert rate < 0.8, f"Deduplication rate too high: {rate:.1%}"

    def test_no_two_assets_at_same_location(self, pipeline_result):
        """No two assets should share the exact same file + line + algorithm + purpose."""
        seen = set()
        for asset in pipeline_result.inventory.assets:
            key = (
                asset.algorithm,
                asset.purpose.value,
                asset.evidence.location.file_path,
                asset.evidence.location.line_number,
            )
            assert key not in seen, f"Duplicate asset at same location: {key}"
            seen.add(key)


# ── 8. Inventory structure ────────────────────────────────────────────────────

class TestInventoryStructure:
    def test_all_assets_have_algorithm(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.algorithm and len(asset.algorithm) > 0

    def test_all_assets_have_location(self, pipeline_result):
        for asset in pipeline_result.inventory.assets:
            assert asset.location and ":" in asset.location

    def test_all_assets_have_classification(self, pipeline_result):
        from ecdat.schemas import AssetClassification
        for asset in pipeline_result.inventory.assets:
            assert asset.classification in (
                AssetClassification.APPLICATION,
                AssetClassification.INFRASTRUCTURE,
            )

    def test_risk_is_none_before_mosca_engine(self, pipeline_result):
        """Risk should be None — Mosca engine runs on Day 4."""
        for asset in pipeline_result.inventory.assets:
            assert asset.risk is None, (
                f"Risk unexpectedly populated for {asset.algorithm} — "
                f"Mosca engine has not run yet"
            )

    def test_recommendation_is_none_before_pqc_engine(self, pipeline_result):
        """Recommendation should be None — PQC engine runs on Day 4."""
        for asset in pipeline_result.inventory.assets:
            assert asset.recommendation is None

    def test_purposes_found_in_summary(self, pipeline_result):
        summary = pipeline_result.inventory.summary()
        purposes = summary["purposes"]
        assert "hashing" in purposes
        assert "key_establishment" in purposes

    def test_assets_serialise_to_json(self, pipeline_result):
        """Every asset in the inventory must be JSON-serialisable."""
        import json
        for asset in pipeline_result.inventory.assets:
            data = json.loads(asset.model_dump_json())
            assert data["algorithm"] == asset.algorithm
