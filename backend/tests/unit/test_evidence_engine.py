"""
Unit tests — evidence_engine.py

Tests that RawMatch objects are correctly converted into Evidence +
CryptoAsset records, with correct algorithm names, purposes, confidence,
and location fields.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ecdat.discovery.rule_loader import load_rules
from ecdat.discovery.ast_matchers import RawMatch
from ecdat.engines.evidence_engine import (
    raw_match_to_asset,
    _normalise_algorithm,
    _compute_confidence,
    _STAGING_CLASSIFICATION,
    _STAGING_SENSITIVITY,
    _STAGING_CRITICALITY,
)
from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CryptoPurpose,
    DetectionMethod,
    FindingType,
    LifecycleStage,
    SensitivityLevel,
)

RULES_PATH = Path(__file__).parent.parent.parent.parent / "config" / "detection_rules.yaml"


def _get_rule(rule_id: str):
    rules = load_rules(RULES_PATH)
    r = next((r for r in rules if r.rule_id == rule_id), None)
    assert r is not None
    return r


def _make_raw_match(rule_id: str, start_row=5, key_size=None, curve=None):
    rule = _get_rule(rule_id)
    return RawMatch(
        rule=rule,
        start_row=start_row,
        start_col=4,
        end_row=start_row,
        end_col=20,
        snippet=f"mock_snippet_{rule_id}",
        extracted_key_size=key_size,
        extracted_curve=curve,
    )


class TestAlgorithmNormalisation:
    def test_rsa_with_key_size(self):
        assert _normalise_algorithm("RSA", 2048, None) == "RSA-2048"

    def test_rsa_with_4096(self):
        assert _normalise_algorithm("RSA", 4096, None) == "RSA-4096"

    def test_rsa_no_key_size(self):
        assert _normalise_algorithm("RSA", None, None) == "RSA"

    def test_ecdsa_with_curve(self):
        assert _normalise_algorithm("ECDSA", None, "SECP256R1") == "ECDSA-P256"

    def test_ecdsa_p384(self):
        assert _normalise_algorithm("ECDSA", None, "SECP384R1") == "ECDSA-P384"

    def test_curve_takes_precedence_over_key_size(self):
        # If both provided, curve wins
        result = _normalise_algorithm("ECDSA", 256, "SECP256R1")
        assert result == "ECDSA-P256"

    def test_md5_no_suffix(self):
        assert _normalise_algorithm("MD5", None, None) == "MD5"

    def test_aes_with_size(self):
        assert _normalise_algorithm("AES", 128, None) == "AES-128"


class TestConfidenceScoring:
    def test_base_confidence_preserved(self):
        raw = _make_raw_match("R-007")
        conf = _compute_confidence(0.97, raw)
        assert conf == pytest.approx(0.97, abs=0.02)

    def test_key_size_extraction_adds_bonus(self):
        raw = _make_raw_match("R-001", key_size=2048)
        conf = _compute_confidence(0.97, raw)
        assert conf > 0.97

    def test_confidence_capped_at_1(self):
        raw = _make_raw_match("R-001", key_size=2048)
        conf = _compute_confidence(1.0, raw)
        assert conf == 1.0

    def test_confidence_floor_at_0(self):
        raw = _make_raw_match("R-007")
        conf = _compute_confidence(0.0, raw)
        assert conf == 0.0


class TestStagingDefaults:
    """
    Evidence Engine emits staging defaults for classification fields.
    ClassificationEngine (stage 6) overwrites these — these tests verify
    the staging values are what the ClassificationEngine expects to receive
    and overwrite (not any heuristic-computed values).
    """

    def test_classification_is_staging_default(self):
        raw = _make_raw_match("R-007")
        result = raw_match_to_asset(raw, file_path=Path("auth_service.py"))
        assert result.asset.classification == _STAGING_CLASSIFICATION
        assert result.asset.classification == AssetClassification.APPLICATION

    def test_sensitivity_is_staging_default(self):
        raw = _make_raw_match("R-007")
        result = raw_match_to_asset(raw, file_path=Path("auth_service.py"))
        assert result.asset.sensitivity == _STAGING_SENSITIVITY
        assert result.asset.sensitivity == SensitivityLevel.INTERNAL

    def test_criticality_is_staging_default(self):
        raw = _make_raw_match("R-007")
        result = raw_match_to_asset(raw, file_path=Path("auth_service.py"))
        assert result.asset.business_criticality == _STAGING_CRITICALITY
        assert result.asset.business_criticality == BusinessCriticality.LOW

    def test_lifecycle_is_active_by_default(self):
        raw = _make_raw_match("R-007")
        result = raw_match_to_asset(raw, file_path=Path("auth_service.py"))
        assert result.asset.lifecycle_stage == LifecycleStage.ACTIVE

    def test_staging_defaults_same_for_tls_file(self):
        # tls_client.py previously got INFRASTRUCTURE from the old heuristic;
        # now it gets the staging default APPLICATION. The ClassificationEngine
        # will correctly assign INFRASTRUCTURE at stage 6.
        raw = _make_raw_match("R-016")
        result = raw_match_to_asset(raw, file_path=Path("tls_client.py"))
        assert result.asset.classification == AssetClassification.APPLICATION  # staging

    def test_staging_defaults_same_for_rsa_key_establishment(self):
        # RSA key_establishment previously got sensitivity=HIGH from the heuristic;
        # staging default is INTERNAL. ClassificationEngine assigns HIGH at stage 6.
        raw = _make_raw_match("R-001", key_size=2048)
        result = raw_match_to_asset(raw, file_path=Path("auth_service.py"))
        assert result.asset.sensitivity == SensitivityLevel.INTERNAL   # staging


class TestRawMatchToAsset:
    def test_basic_asset_from_md5_match(self):
        raw = _make_raw_match("R-007", start_row=9)  # line 10 (1-based)
        result = raw_match_to_asset(
            raw,
            file_path=Path("e:/ECDAT/test_repos/demo_app/auth_service.py"),
            relative_to=Path("e:/ECDAT/test_repos/demo_app"),
        )
        asset = result.asset
        evidence = result.evidence

        # Algorithm
        assert asset.algorithm == "MD5"
        assert asset.purpose == CryptoPurpose.HASHING

        # Evidence fields
        assert evidence.detection_method == DetectionMethod.AST_RULE
        assert evidence.finding_type == FindingType.DETERMINISTIC
        assert evidence.rule_id == "R-007"
        assert evidence.confidence > 0.0

        # Location (tree-sitter row 9 → line 10)
        assert evidence.location.line_number == 10
        assert "auth_service.py" in evidence.location.file_path

    def test_rsa_asset_has_key_size(self):
        raw = _make_raw_match("R-001", start_row=16, key_size=2048)
        result = raw_match_to_asset(
            raw,
            file_path=Path("e:/ECDAT/test_repos/demo_app/crypto_utils.py"),
        )
        assert result.asset.algorithm == "RSA-2048"
        assert result.asset.key_size_bits == 2048

    def test_partial_asset_has_no_risk_or_recommendation(self):
        raw = _make_raw_match("R-007")
        result = raw_match_to_asset(
            raw,
            file_path=Path("auth_service.py"),
        )
        assert result.asset.risk is None
        assert result.asset.recommendation is None

    def test_source_surface_is_source_code(self):
        raw = _make_raw_match("R-007")
        result = raw_match_to_asset(raw, file_path=Path("auth_service.py"))
        assert result.asset.source_surface == "source_code"
        assert result.evidence.source_surface == "source_code"

    def test_location_string_format(self):
        raw = _make_raw_match("R-007", start_row=37)  # → line 38
        result = raw_match_to_asset(
            raw,
            file_path=Path("e:/ECDAT/test_repos/demo_app/auth_service.py"),
            relative_to=Path("e:/ECDAT/test_repos/demo_app"),
        )
        # location string should be "file:line"
        assert ":" in result.asset.location
        assert "38" in result.asset.location

    def test_parse_error_lowers_confidence(self):
        raw = _make_raw_match("R-007")
        result_clean = raw_match_to_asset(
            raw, file_path=Path("a.py"), has_parse_error=False
        )
        result_error = raw_match_to_asset(
            raw, file_path=Path("a.py"), has_parse_error=True
        )
        assert result_error.evidence.confidence < result_clean.evidence.confidence

    def test_relative_path_used_in_location(self):
        raw = _make_raw_match("R-007", start_row=2)
        result = raw_match_to_asset(
            raw,
            file_path=Path("e:/ECDAT/test_repos/demo_app/auth_service.py"),
            relative_to=Path("e:/ECDAT/test_repos/demo_app"),
        )
        # Should use relative path, not absolute
        loc_file = result.evidence.location.file_path
        assert "auth_service.py" in loc_file
        # Should not start with drive letter when relative_to is provided
        assert not loc_file.startswith("e:")
