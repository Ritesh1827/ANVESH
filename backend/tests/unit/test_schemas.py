"""
Day 1 schema tests — ECDAT Pydantic data model validation.

Test coverage:
  1.  PRD §9 sample JSON validates successfully against all models.
  2.  Serialise a constructed model to JSON and back (round-trip).
  3.  Nested Evidence, Risk, and Recommendation objects validate correctly.
  4.  Invalid / missing required fields are rejected with ValidationError.
  5.  Enum constraints are enforced.
  6.  Risk.urgency_flag consistency validator (X + Y > Z).
  7.  Evidence.llm_prompt_version required when finding_type=LLM_ENRICHED.
  8.  SourceLocation end_line >= start_line constraint.
  9.  CryptoAsset rejects empty algorithm / location / source_surface.
  10. CBOMExport rejects assets without evidence.
  11. CBOMQualityScore score bounds (0.0–1.0).
  12. Recommendation.status must be StandardizationStatus enum value.
  13. CryptoAsset with no risk/recommendation is valid (pipeline stages optional).
  14. CBOM with empty asset list is valid.
  15. Full CryptoAsset round-trip preserves every PRD §9 field.
"""

import json
import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CBOMExport,
    CBOMMetadata,
    CBOMQualityScore,
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    LifecycleStage,
    MigrationPathType,
    Recommendation,
    Risk,
    RiskPriority,
    SensitivityLevel,
    SourceLocation,
    StandardizationStatus,
)


# ── Shared fixtures ────────────────────────────────────────────────────────────

def make_source_location(**overrides) -> dict:
    base = {
        "file_path": "auth_service.py",
        "line_number": 143,
    }
    base.update(overrides)
    return base


def make_evidence(**overrides) -> dict:
    """Minimal valid Evidence matching PRD §9 sample."""
    base = {
        "detection_method": "ast_rule",
        "finding_type": "deterministic",
        "rule_id": "R-014",
        "location": make_source_location(),
        "source_surface": "source_code",
        "confidence": 0.98,
    }
    base.update(overrides)
    return base


def make_risk(**overrides) -> dict:
    """PRD §9 sample risk values: X=15, Y=2, Z=12 → urgency_flag=True."""
    base = {
        "mosca_x_years": 15,
        "mosca_y_years": 2,
        "mosca_z_years": 12,
        "urgency_flag": True,
        "hndl_flag": True,
        "priority": "P1",
    }
    base.update(overrides)
    return base


def make_recommendation(**overrides) -> dict:
    """PRD §9 sample recommendation."""
    base = {
        "standardized_replacement": "ML-KEM (FIPS 203)",
        "migration_path": "hybrid: X25519 + ML-KEM",
        "status": "standardized",
    }
    base.update(overrides)
    return base


def make_crypto_asset(**overrides) -> dict:
    """Full PRD §9 sample asset as a plain dict."""
    base = {
        "algorithm": "RSA-2048",
        "purpose": "key_establishment",
        "location": "auth_service.py:143",
        "library": "OpenSSL 1.1.1",
        "protocol": "TLS 1.2",
        "classification": "application",
        "sensitivity": "high",
        "business_criticality": "critical",
        "owner": "Citizen Services Team",
        "reachable": True,
        "source_surface": "source_code",
        "evidence": make_evidence(),
        "risk": make_risk(),
        "recommendation": make_recommendation(),
    }
    base.update(overrides)
    return base


# ── 1. PRD §9 sample validates ────────────────────────────────────────────────

class TestPRDSampleValidation:
    """The PRD §9 sample JSON must validate successfully — non-negotiable."""

    def test_prd_sample_evidence_validates(self):
        e = Evidence(**make_evidence())
        assert e.confidence == 0.98
        assert e.detection_method == DetectionMethod.AST_RULE
        assert e.finding_type == FindingType.DETERMINISTIC
        assert e.rule_id == "R-014"
        assert e.location.file_path == "auth_service.py"
        assert e.location.line_number == 143

    def test_prd_sample_risk_validates(self):
        r = Risk(**make_risk())
        assert r.mosca_x_years == 15
        assert r.mosca_y_years == 2
        assert r.mosca_z_years == 12
        assert r.urgency_flag is True
        assert r.hndl_flag is True
        assert r.priority == RiskPriority.P1

    def test_prd_sample_recommendation_validates(self):
        rec = Recommendation(**make_recommendation())
        assert rec.standardized_replacement == "ML-KEM (FIPS 203)"
        assert rec.migration_path == "hybrid: X25519 + ML-KEM"
        assert rec.status == StandardizationStatus.STANDARDIZED

    def test_prd_sample_full_asset_validates(self):
        asset = CryptoAsset(**make_crypto_asset())
        # Top-level PRD §9 fields
        assert asset.algorithm == "RSA-2048"
        assert asset.purpose == CryptoPurpose.KEY_ESTABLISHMENT
        assert asset.location == "auth_service.py:143"
        assert asset.library == "OpenSSL 1.1.1"
        assert asset.protocol == "TLS 1.2"
        assert asset.classification == AssetClassification.APPLICATION
        assert asset.sensitivity == SensitivityLevel.HIGH
        assert asset.business_criticality == BusinessCriticality.CRITICAL
        assert asset.owner == "Citizen Services Team"
        assert asset.reachable is True
        # Nested objects
        assert asset.evidence.confidence == 0.98
        assert asset.evidence.rule_id == "R-014"
        assert asset.risk.urgency_flag is True
        assert asset.risk.hndl_flag is True
        assert asset.risk.priority == RiskPriority.P1
        assert asset.recommendation.standardized_replacement == "ML-KEM (FIPS 203)"
        assert asset.recommendation.status == StandardizationStatus.STANDARDIZED


# ── 2. JSON round-trip ────────────────────────────────────────────────────────

class TestJSONRoundTrip:
    """Serialise to JSON, deserialise back, assert equality."""

    def test_evidence_round_trip(self):
        original = Evidence(**make_evidence())
        json_str = original.model_dump_json()
        restored = Evidence.model_validate_json(json_str)
        assert restored == original

    def test_risk_round_trip(self):
        original = Risk(**make_risk())
        json_str = original.model_dump_json()
        restored = Risk.model_validate_json(json_str)
        assert restored == original

    def test_recommendation_round_trip(self):
        original = Recommendation(**make_recommendation())
        json_str = original.model_dump_json()
        restored = Recommendation.model_validate_json(json_str)
        assert restored == original

    def test_crypto_asset_round_trip(self):
        original = CryptoAsset(**make_crypto_asset())
        json_str = original.model_dump_json()
        restored = CryptoAsset.model_validate_json(json_str)
        # Core fields preserved
        assert restored.algorithm == original.algorithm
        assert restored.purpose == original.purpose
        assert restored.location == original.location
        assert restored.evidence.confidence == original.evidence.confidence
        assert restored.evidence.rule_id == original.evidence.rule_id
        assert restored.risk.priority == original.risk.priority
        assert restored.risk.urgency_flag == original.risk.urgency_flag
        assert restored.recommendation.standardized_replacement == (
            original.recommendation.standardized_replacement
        )

    def test_dict_round_trip(self):
        """model_dump() → model_validate() must preserve all PRD §9 fields."""
        original = CryptoAsset(**make_crypto_asset())
        as_dict = original.model_dump()
        restored = CryptoAsset.model_validate(as_dict)
        assert restored.algorithm == "RSA-2048"
        assert restored.risk.mosca_x_years == 15
        assert restored.recommendation.migration_path == "hybrid: X25519 + ML-KEM"

    def test_json_is_valid_json(self):
        asset = CryptoAsset(**make_crypto_asset())
        raw = asset.model_dump_json()
        parsed = json.loads(raw)
        assert parsed["algorithm"] == "RSA-2048"
        assert parsed["evidence"]["confidence"] == 0.98
        assert parsed["risk"]["priority"] == "P1"
        assert parsed["recommendation"]["status"] == "standardized"


# ── 3. Nested object validation ────────────────────────────────────────────────

class TestNestedObjects:
    """Nested Evidence, Risk, and Recommendation validate their own constraints."""

    def test_evidence_nested_in_asset(self):
        asset = CryptoAsset(**make_crypto_asset())
        assert isinstance(asset.evidence, Evidence)
        assert isinstance(asset.evidence.location, SourceLocation)

    def test_risk_nested_in_asset(self):
        asset = CryptoAsset(**make_crypto_asset())
        assert isinstance(asset.risk, Risk)
        assert asset.risk.mosca_x_years == 15

    def test_recommendation_nested_in_asset(self):
        asset = CryptoAsset(**make_crypto_asset())
        assert isinstance(asset.recommendation, Recommendation)
        assert asset.recommendation.migration_path_type == MigrationPathType.HYBRID

    def test_source_location_validates_inside_evidence(self):
        loc = SourceLocation(file_path="main.py", line_number=10, end_line_number=15)
        assert loc.end_line_number == 15

    def test_evidence_with_full_location(self):
        e = Evidence(**make_evidence(
            location={
                "file_path": "crypto_util.py",
                "line_number": 55,
                "column_number": 4,
                "end_line_number": 60,
                "snippet": "rsa_key = RSA.generate(2048)",
            }
        ))
        assert e.location.column_number == 4
        assert e.location.snippet == "rsa_key = RSA.generate(2048)"


# ── 4. Invalid data is rejected ────────────────────────────────────────────────

class TestInvalidDataRejected:
    """Required fields absent or with wrong types must raise ValidationError."""

    def test_crypto_asset_missing_algorithm_rejected(self):
        data = make_crypto_asset()
        del data["algorithm"]
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "algorithm" in str(exc_info.value)

    def test_crypto_asset_missing_evidence_rejected(self):
        data = make_crypto_asset()
        del data["evidence"]
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "evidence" in str(exc_info.value)

    def test_crypto_asset_missing_purpose_rejected(self):
        data = make_crypto_asset()
        del data["purpose"]
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "purpose" in str(exc_info.value)

    def test_crypto_asset_missing_classification_rejected(self):
        data = make_crypto_asset()
        del data["classification"]
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "classification" in str(exc_info.value)

    def test_evidence_missing_location_rejected(self):
        data = make_evidence()
        del data["location"]
        with pytest.raises(ValidationError) as exc_info:
            Evidence(**data)
        assert "location" in str(exc_info.value)

    def test_evidence_missing_confidence_rejected(self):
        data = make_evidence()
        del data["confidence"]
        with pytest.raises(ValidationError) as exc_info:
            Evidence(**data)
        assert "confidence" in str(exc_info.value)

    def test_risk_missing_urgency_flag_rejected(self):
        data = make_risk()
        del data["urgency_flag"]
        with pytest.raises(ValidationError) as exc_info:
            Risk(**data)
        assert "urgency_flag" in str(exc_info.value)

    def test_risk_missing_priority_rejected(self):
        data = make_risk()
        del data["priority"]
        with pytest.raises(ValidationError) as exc_info:
            Risk(**data)
        assert "priority" in str(exc_info.value)

    def test_recommendation_missing_replacement_rejected(self):
        data = make_recommendation()
        del data["standardized_replacement"]
        with pytest.raises(ValidationError) as exc_info:
            Recommendation(**data)
        assert "standardized_replacement" in str(exc_info.value)

    def test_recommendation_missing_status_rejected(self):
        data = make_recommendation()
        del data["status"]
        with pytest.raises(ValidationError) as exc_info:
            Recommendation(**data)
        assert "status" in str(exc_info.value)

    def test_source_location_missing_file_path_rejected(self):
        with pytest.raises(ValidationError):
            SourceLocation(line_number=10)


# ── 5. Enum constraints ────────────────────────────────────────────────────────

class TestEnumConstraints:
    """Invalid enum values must be rejected; valid values must round-trip."""

    def test_invalid_purpose_rejected(self):
        data = make_crypto_asset(purpose="encrypt_everything")
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "purpose" in str(exc_info.value)

    def test_invalid_classification_rejected(self):
        data = make_crypto_asset(classification="cloud")
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "classification" in str(exc_info.value)

    def test_invalid_detection_method_rejected(self):
        data = make_evidence(detection_method="magic_scanner")
        with pytest.raises(ValidationError) as exc_info:
            Evidence(**data)
        assert "detection_method" in str(exc_info.value)

    def test_invalid_priority_rejected(self):
        data = make_risk(priority="URGENT")
        with pytest.raises(ValidationError) as exc_info:
            Risk(**data)
        assert "priority" in str(exc_info.value)

    def test_invalid_standardization_status_rejected(self):
        data = make_recommendation(status="maybe")
        with pytest.raises(ValidationError) as exc_info:
            Recommendation(**data)
        assert "status" in str(exc_info.value)

    def test_all_valid_purposes_accepted(self):
        valid_purposes = [
            "key_establishment", "digital_signature", "encryption",
            "hashing", "mac", "key_derivation", "random_generation",
            "certificate", "unknown",
        ]
        for purpose in valid_purposes:
            asset = CryptoAsset(**make_crypto_asset(purpose=purpose))
            assert asset.purpose.value == purpose

    def test_all_valid_priorities_accepted(self):
        for p in ["P1", "P2", "P3", "P4", "UNKNOWN"]:
            r = Risk(**make_risk(priority=p, urgency_flag=True))
            assert r.priority.value == p


# ── 6. Mosca urgency_flag consistency validator ────────────────────────────────

class TestMoscaUrgencyFlagConsistency:
    """X + Y > Z must match urgency_flag when all three values are present."""

    def test_correct_urgency_true(self):
        # 15 + 2 = 17 > 12 → True
        r = Risk(**make_risk(mosca_x_years=15, mosca_y_years=2, mosca_z_years=12, urgency_flag=True))
        assert r.urgency_flag is True

    def test_correct_urgency_false(self):
        # 1 + 1 = 2 <= 20 → False
        r = Risk(
            mosca_x_years=1, mosca_y_years=1, mosca_z_years=20,
            urgency_flag=False, hndl_flag=False, priority=RiskPriority.P4
        )
        assert r.urgency_flag is False

    def test_inconsistent_urgency_flag_rejected(self):
        # 15 + 2 = 17 > 12 → should be True, but we supply False
        with pytest.raises(ValidationError) as exc_info:
            Risk(
                mosca_x_years=15, mosca_y_years=2, mosca_z_years=12,
                urgency_flag=False,  # WRONG
                hndl_flag=False,
                priority=RiskPriority.P1,
            )
        assert "urgency_flag" in str(exc_info.value).lower() or "inconsistent" in str(exc_info.value).lower()

    def test_inconsistent_urgency_flag_true_when_should_be_false(self):
        # 1 + 1 = 2 <= 20 → should be False, but we supply True
        with pytest.raises(ValidationError):
            Risk(
                mosca_x_years=1, mosca_y_years=1, mosca_z_years=20,
                urgency_flag=True,  # WRONG
                hndl_flag=False,
                priority=RiskPriority.P4,
            )

    def test_missing_mosca_params_allows_any_urgency_flag(self):
        # When parameters are not available, the engine sets urgency_flag directly
        r = Risk(urgency_flag=True, hndl_flag=True, priority=RiskPriority.P1)
        assert r.urgency_flag is True
        assert r.mosca_x_years is None

    def test_exact_boundary_x_plus_y_equals_z_not_urgent(self):
        # X + Y == Z means NOT urgent (requires strictly greater)
        r = Risk(
            mosca_x_years=10, mosca_y_years=2, mosca_z_years=12,
            urgency_flag=False, hndl_flag=False, priority=RiskPriority.P3
        )
        assert r.urgency_flag is False

    def test_exact_boundary_x_plus_y_equals_z_urgent_is_rejected(self):
        # Same values but urgency_flag=True should be rejected
        with pytest.raises(ValidationError):
            Risk(
                mosca_x_years=10, mosca_y_years=2, mosca_z_years=12,
                urgency_flag=True,  # WRONG — 12 is not > 12
                hndl_flag=False,
                priority=RiskPriority.P1,
            )


# ── 7. LLM enrichment Evidence constraints ────────────────────────────────────

class TestLLMEnrichmentEvidence:
    """LLM-enriched findings require llm_prompt_version."""

    def test_llm_enriched_without_prompt_version_rejected(self):
        data = make_evidence(
            finding_type="llm_enriched",
            detection_method="llm_enrichment",
            confidence=0.72,
            llm_prompt_version=None,
        )
        with pytest.raises(ValidationError) as exc_info:
            Evidence(**data)
        assert "llm_prompt_version" in str(exc_info.value)

    def test_llm_enriched_with_prompt_version_accepted(self):
        e = Evidence(**make_evidence(
            finding_type="llm_enriched",
            detection_method="llm_enrichment",
            confidence=0.72,
            llm_prompt_version="v1",
            llm_model="claude-3-5-sonnet-20241022",
        ))
        assert e.finding_type == FindingType.LLM_ENRICHED
        assert e.llm_prompt_version == "v1"

    def test_deterministic_finding_does_not_require_prompt_version(self):
        e = Evidence(**make_evidence(finding_type="deterministic"))
        assert e.llm_prompt_version is None


# ── 8. SourceLocation end_line constraint ────────────────────────────────────

class TestSourceLocationConstraints:
    """end_line_number must be >= line_number."""

    def test_valid_end_line_equal_to_start(self):
        loc = SourceLocation(file_path="a.py", line_number=10, end_line_number=10)
        assert loc.end_line_number == 10

    def test_valid_end_line_after_start(self):
        loc = SourceLocation(file_path="a.py", line_number=5, end_line_number=15)
        assert loc.end_line_number == 15

    def test_end_line_before_start_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            SourceLocation(file_path="a.py", line_number=20, end_line_number=10)
        assert "end_line" in str(exc_info.value).lower()

    def test_no_line_numbers_is_valid(self):
        # e.g. a binary symbol — no line number
        loc = SourceLocation(file_path="libssl.so")
        assert loc.line_number is None
        assert loc.end_line_number is None

    def test_confidence_out_of_range_rejected(self):
        data = make_evidence(confidence=1.5)
        with pytest.raises(ValidationError):
            Evidence(**data)

    def test_confidence_below_zero_rejected(self):
        data = make_evidence(confidence=-0.1)
        with pytest.raises(ValidationError):
            Evidence(**data)

    def test_confidence_boundary_zero_accepted(self):
        e = Evidence(**make_evidence(confidence=0.0))
        assert e.confidence == 0.0

    def test_confidence_boundary_one_accepted(self):
        e = Evidence(**make_evidence(confidence=1.0))
        assert e.confidence == 1.0


# ── 9. CryptoAsset field validation ───────────────────────────────────────────

class TestCryptoAssetFieldValidation:
    """CryptoAsset field-level validators."""

    def test_empty_algorithm_rejected(self):
        data = make_crypto_asset(algorithm="   ")
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "algorithm" in str(exc_info.value)

    def test_empty_location_rejected(self):
        data = make_crypto_asset(location="")
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "location" in str(exc_info.value)

    def test_empty_source_surface_rejected(self):
        data = make_crypto_asset(source_surface="  ")
        with pytest.raises(ValidationError) as exc_info:
            CryptoAsset(**data)
        assert "source_surface" in str(exc_info.value)

    def test_asset_id_auto_generated(self):
        a = CryptoAsset(**make_crypto_asset())
        assert a.asset_id is not None
        assert len(a.asset_id) > 0

    def test_two_assets_have_different_ids(self):
        a1 = CryptoAsset(**make_crypto_asset())
        a2 = CryptoAsset(**make_crypto_asset())
        assert a1.asset_id != a2.asset_id

    def test_asset_with_explicit_id(self):
        data = make_crypto_asset()
        data["asset_id"] = "fixed-id-001"
        a = CryptoAsset(**data)
        assert a.asset_id == "fixed-id-001"

    def test_negative_key_size_rejected(self):
        data = make_crypto_asset()
        data["key_size_bits"] = -1
        with pytest.raises(ValidationError):
            CryptoAsset(**data)


# ── 10. CBOM export constraints ────────────────────────────────────────────────

class TestCBOMExport:
    """CBOMExport validates inventory quality and asset evidence requirements."""

    def _make_metadata(self) -> CBOMMetadata:
        return CBOMMetadata(
            ecdat_version="0.1.0",
            scanned_targets=["test_repos/demo"],
            input_surfaces=["source_code"],
        )

    def test_empty_cbom_is_valid(self):
        cbom = CBOMExport(metadata=self._make_metadata())
        assert cbom.assets == []

    def test_cbom_with_valid_asset(self):
        asset = CryptoAsset(**make_crypto_asset())
        cbom = CBOMExport(metadata=self._make_metadata(), assets=[asset])
        assert len(cbom.assets) == 1

    def test_cbom_quality_score_bounds(self):
        qs = CBOMQualityScore(
            completeness_score=1.0,
            evidence_coverage=1.0,
            risk_coverage=0.8,
            recommendation_coverage=0.75,
            duplicate_rate=0.05,
            overall_quality=0.9,
        )
        assert qs.overall_quality == 0.9

    def test_cbom_quality_score_above_one_rejected(self):
        with pytest.raises(ValidationError):
            CBOMQualityScore(
                completeness_score=1.1,  # > 1.0
                evidence_coverage=1.0,
                risk_coverage=1.0,
                recommendation_coverage=1.0,
                duplicate_rate=0.0,
                overall_quality=1.0,
            )

    def test_cbom_quality_score_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            CBOMQualityScore(
                completeness_score=0.0,
                evidence_coverage=-0.1,  # < 0.0
                risk_coverage=1.0,
                recommendation_coverage=1.0,
                duplicate_rate=0.0,
                overall_quality=0.0,
            )

    def test_cbom_export_id_auto_generated(self):
        cbom = CBOMExport(metadata=self._make_metadata())
        assert cbom.export_id is not None

    def test_cbom_metadata_scan_id_auto_generated(self):
        meta = self._make_metadata()
        assert meta.scan_id is not None and len(meta.scan_id) > 0


# ── 11. Asset with no risk/recommendation is valid ────────────────────────────

class TestPartialAsset:
    """Assets before Mosca/Recommendation engines have run are still valid."""

    def test_asset_without_risk_is_valid(self):
        data = make_crypto_asset()
        del data["risk"]
        asset = CryptoAsset(**data)
        assert asset.risk is None

    def test_asset_without_recommendation_is_valid(self):
        data = make_crypto_asset()
        del data["recommendation"]
        asset = CryptoAsset(**data)
        assert asset.recommendation is None

    def test_asset_without_risk_and_recommendation_is_valid(self):
        data = make_crypto_asset()
        del data["risk"]
        del data["recommendation"]
        asset = CryptoAsset(**data)
        assert asset.risk is None
        assert asset.recommendation is None

    def test_asset_reachable_none_before_reachability_engine(self):
        data = make_crypto_asset()
        del data["reachable"]
        asset = CryptoAsset(**data)
        assert asset.reachable is None


# ── 12. Recommendation standardization status constraints ─────────────────────

class TestRecommendationStatus:
    """Status field must use StandardizationStatus enum values."""

    def test_standardized_status_accepted(self):
        rec = Recommendation(**make_recommendation(status="standardized"))
        assert rec.status == StandardizationStatus.STANDARDIZED

    def test_under_standardization_status_accepted(self):
        rec = Recommendation(**make_recommendation(status="under_standardization"))
        assert rec.status == StandardizationStatus.UNDER_STANDARDIZATION

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            Recommendation(**make_recommendation(status="approved_soon"))

    def test_migration_path_type_defaults_to_hybrid(self):
        rec = Recommendation(**make_recommendation())
        assert rec.migration_path_type == MigrationPathType.HYBRID

    def test_pure_pqc_migration_path_type_accepted(self):
        rec = Recommendation(**make_recommendation(migration_path_type="pure_pqc"))
        assert rec.migration_path_type == MigrationPathType.PURE_PQC


# ── 13. Full PRD §9 field preservation after round-trip ──────────────────────

class TestFullPRDFieldPreservation:
    """Every field named in PRD §9 sample JSON must survive a full round-trip."""

    def test_all_prd_fields_preserved(self):
        original_data = make_crypto_asset()
        asset = CryptoAsset(**original_data)
        json_str = asset.model_dump_json()
        restored = CryptoAsset.model_validate_json(json_str)

        # PRD §9 top-level fields
        assert restored.algorithm == "RSA-2048"
        assert restored.purpose == CryptoPurpose.KEY_ESTABLISHMENT
        assert restored.location == "auth_service.py:143"
        assert restored.library == "OpenSSL 1.1.1"
        assert restored.protocol == "TLS 1.2"
        assert restored.classification == AssetClassification.APPLICATION
        assert restored.sensitivity == SensitivityLevel.HIGH
        assert restored.business_criticality == BusinessCriticality.CRITICAL
        assert restored.owner == "Citizen Services Team"
        assert restored.reachable is True

        # PRD §9 evidence sub-object
        assert restored.evidence.detection_method == DetectionMethod.AST_RULE
        assert restored.evidence.confidence == 0.98

        # PRD §9 risk sub-object
        assert restored.risk.mosca_x_years == 15
        assert restored.risk.mosca_y_years == 2
        assert restored.risk.mosca_z_years == 12
        assert restored.risk.urgency_flag is True
        assert restored.risk.hndl_flag is True
        assert restored.risk.priority == RiskPriority.P1

        # PRD §9 recommendation sub-object
        assert restored.recommendation.standardized_replacement == "ML-KEM (FIPS 203)"
        assert restored.recommendation.migration_path == "hybrid: X25519 + ML-KEM"
        assert restored.recommendation.status == StandardizationStatus.STANDARDIZED
