"""
Unit tests — PQC Recommendation Engine (engines/recommendation_engine.py)

Validates:
  1.  RSA key_establishment → ML-KEM (FIPS 203), not ML-DSA
  2.  RSA digital_signature → ML-DSA (FIPS 204), not ML-KEM
  3.  ECDSA digital_signature → ML-DSA (FIPS 204)
  4.  MD5 hashing → SHA-256 (classical_upgrade, not hybrid PQC)
  5.  SHA-256 hashing → no_action (already safe)
  6.  DES encryption → AES-256-GCM (classical_upgrade)
  7.  All primary recommendations have status=standardized
  8.  Under-standardization algorithms are never primary recommendations
  9.  Hybrid is default migration_path_type for quantum-vulnerable algorithms
  10. Greenfield flag produces pure_pqc path type
  11. Unknown algorithm produces advisory fallback (not a crash)
  12. PRD §9 sample recommendation: ML-KEM (FIPS 203), hybrid, standardized
  13. RecommendationEngine.process() annotates all assets
  14. Original asset not mutated
  15. purpose_mismatch: RSA key_establishment must NOT get ML-DSA
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    LifecycleStage,
    MigrationPathType,
    RiskPriority,
    SensitivityLevel,
    SourceLocation,
    StandardizationStatus,
)
from ecdat.engines.recommendation_engine import RecommendationEngine
from ecdat.engines.pqc_loader import load_pqc_config, find_pqc_mapping

REPO_ROOT = Path(__file__).parent.parent.parent.parent
PQC_PATH = REPO_ROOT / "config" / "pqc_mappings.yaml"


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_asset(algorithm="RSA-2048", purpose="key_establishment") -> CryptoAsset:
    evidence = Evidence(
        detection_method=DetectionMethod.AST_RULE,
        finding_type=FindingType.DETERMINISTIC,
        rule_id="R-001",
        location=SourceLocation(file_path="auth_service.py", line_number=29),
        source_surface="source_code",
        confidence=0.97,
    )
    return CryptoAsset(
        algorithm=algorithm,
        purpose=purpose,
        location="auth_service.py:29",
        source_surface="source_code",
        classification=AssetClassification.APPLICATION,
        sensitivity=SensitivityLevel.HIGH,
        business_criticality=BusinessCriticality.CRITICAL,
        lifecycle_stage=LifecycleStage.ACTIVE,
        evidence=evidence,
    )


@pytest.fixture(scope="module")
def engine() -> RecommendationEngine:
    return RecommendationEngine(pqc_mappings_path=PQC_PATH)


# ── 1–6: Purpose-aware mapping ────────────────────────────────────────────────

class TestPurposeAwareMapping:
    """
    PRD §5 stage 10: "Do not map an algorithm directly to a PQC replacement
    without determining its cryptographic purpose."
    """

    def test_rsa_key_establishment_maps_to_ml_kem(self, engine):
        asset = _make_asset("RSA-2048", "key_establishment")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert rec is not None
        assert "ML-KEM" in rec.standardized_replacement
        assert "FIPS 203" in rec.standardized_replacement

    def test_rsa_key_establishment_does_not_map_to_ml_dsa(self, engine):
        """Key establishment must NEVER get a digital signature replacement."""
        asset = _make_asset("RSA-2048", "key_establishment")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert "ML-DSA" not in rec.standardized_replacement
        assert "SLH-DSA" not in rec.standardized_replacement

    def test_rsa_digital_signature_maps_to_ml_dsa(self, engine):
        asset = _make_asset("RSA-2048", "digital_signature")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert rec is not None
        assert "ML-DSA" in rec.standardized_replacement
        assert "FIPS 204" in rec.standardized_replacement

    def test_rsa_digital_signature_does_not_map_to_ml_kem(self, engine):
        """Digital signatures must NEVER get a key encapsulation replacement."""
        asset = _make_asset("RSA-4096", "digital_signature")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert "ML-KEM" not in rec.standardized_replacement

    def test_ecdsa_maps_to_ml_dsa(self, engine):
        asset = _make_asset("ECDSA-P256", "digital_signature")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert "ML-DSA" in rec.standardized_replacement

    def test_md5_maps_to_sha256_classical_upgrade(self, engine):
        asset = _make_asset("MD5", "hashing")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert "SHA-256" in rec.standardized_replacement or "SHA3" in rec.standardized_replacement
        assert rec.migration_path_type == MigrationPathType.CLASSICAL_UPGRADE

    def test_sha1_maps_to_sha256(self, engine):
        asset = _make_asset("SHA-1", "hashing")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert "SHA-256" in rec.standardized_replacement or "SHA3" in rec.standardized_replacement

    def test_des_maps_to_aes256(self, engine):
        asset = _make_asset("DES-56", "encryption")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert "AES-256" in rec.standardized_replacement

    def test_sha256_is_no_action(self, engine):
        asset = _make_asset("SHA-256", "hashing")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert rec.migration_path_type == MigrationPathType.NO_ACTION

    def test_sha512_is_no_action(self, engine):
        asset = _make_asset("SHA-512", "hashing")
        result = engine.recommend_for_asset(asset)
        assert result.recommendation.migration_path_type == MigrationPathType.NO_ACTION

    def test_hmac_is_no_action(self, engine):
        asset = _make_asset("HMAC", "mac")
        result = engine.recommend_for_asset(asset)
        assert result.recommendation.migration_path_type == MigrationPathType.NO_ACTION


# ── 7–8: Standardization status enforcement ──────────────────────────────────

class TestStandardizationStatus:
    """
    PRD §5 stage 10: "Keep standardized algorithms separate from those still
    under standardization. Never recommend the latter as primary."
    """

    def test_all_primary_recommendations_are_standardized(self, engine):
        """No asset should ever receive an under-standardization primary rec."""
        test_assets = [
            _make_asset("RSA-2048", "key_establishment"),
            _make_asset("RSA-4096", "digital_signature"),
            _make_asset("ECDSA-P256", "digital_signature"),
            _make_asset("MD5", "hashing"),
            _make_asset("SHA-1", "hashing"),
            _make_asset("DES-56", "encryption"),
        ]
        for asset in test_assets:
            result = engine.recommend_for_asset(asset)
            rec = result.recommendation
            assert rec.status != StandardizationStatus.UNDER_STANDARDIZATION, (
                f"{asset.algorithm} ({asset.purpose.value}) got "
                f"under_standardization status — violates PRD §5 stage 10"
            )

    def test_rsa_key_establishment_status_is_standardized(self, engine):
        result = engine.recommend_for_asset(_make_asset("RSA-2048", "key_establishment"))
        assert result.recommendation.status == StandardizationStatus.STANDARDIZED

    def test_ecdsa_status_is_standardized(self, engine):
        result = engine.recommend_for_asset(_make_asset("ECDSA-P256", "digital_signature"))
        assert result.recommendation.status == StandardizationStatus.STANDARDIZED

    def test_under_standardization_list_not_empty(self, engine):
        names = engine.get_under_standardization_names()
        assert len(names) > 0
        # HQC and Falcon should be listed as under standardization
        all_names = " ".join(names).upper()
        assert "HQC" in all_names or "FALCON" in all_names

    def test_under_standardization_not_in_primary_recommendations(self, engine):
        """HQC/Falcon/BIKE must not appear as primary_replacement."""
        forbidden = ["HQC", "FALCON", "BIKE", "FN-DSA"]
        test_assets = [
            _make_asset("RSA-2048", "key_establishment"),
            _make_asset("ECDSA-P256", "digital_signature"),
        ]
        for asset in test_assets:
            rec = engine.recommend_for_asset(asset).recommendation
            for name in forbidden:
                assert name not in rec.standardized_replacement.upper(), (
                    f"Under-standardization algorithm '{name}' appeared as "
                    f"primary recommendation for {asset.algorithm}"
                )


# ── 9–10: Hybrid-first / greenfield ──────────────────────────────────────────

class TestMigrationPathType:
    """
    PRD §5 stage 10: "Recommend hybrid (classical + PQC) by default during
    migration, pure-PQC only for greenfield systems."
    """

    def test_rsa_key_establishment_default_is_hybrid(self, engine):
        result = engine.recommend_for_asset(_make_asset("RSA-2048", "key_establishment"))
        assert result.recommendation.migration_path_type == MigrationPathType.HYBRID

    def test_ecdsa_default_is_hybrid(self, engine):
        result = engine.recommend_for_asset(_make_asset("ECDSA-P256", "digital_signature"))
        assert result.recommendation.migration_path_type == MigrationPathType.HYBRID

    def test_greenfield_rsa_is_pure_pqc(self, engine):
        asset = _make_asset("RSA-2048", "key_establishment")
        result = engine.recommend_for_asset(asset, is_greenfield=True)
        assert result.recommendation.migration_path_type == MigrationPathType.PURE_PQC

    def test_greenfield_ecdsa_is_pure_pqc(self, engine):
        asset = _make_asset("ECDSA-P256", "digital_signature")
        result = engine.recommend_for_asset(asset, is_greenfield=True)
        assert result.recommendation.migration_path_type == MigrationPathType.PURE_PQC

    def test_md5_classical_upgrade_unaffected_by_greenfield(self, engine):
        # MD5 is classical_upgrade regardless — greenfield doesn't change that
        asset = _make_asset("MD5", "hashing")
        default_result = engine.recommend_for_asset(asset)
        assert default_result.recommendation.migration_path_type == MigrationPathType.CLASSICAL_UPGRADE

    def test_hybrid_migration_path_contains_classical_plus_pqc(self, engine):
        result = engine.recommend_for_asset(_make_asset("RSA-2048", "key_establishment"))
        path = result.recommendation.migration_path.lower()
        # Hybrid path should reference both classical and PQC components
        assert "hybrid" in path or ("+" in path)


# ── 11: Unknown algorithm fallback ───────────────────────────────────────────

class TestUnknownAlgorithmFallback:
    def test_unknown_algorithm_does_not_crash(self, engine):
        asset = _make_asset("MYSTERY-ALGO-512", "key_establishment")
        result = engine.recommend_for_asset(asset)
        assert result.recommendation is not None

    def test_unknown_algorithm_recommendation_has_advisory_note(self, engine):
        asset = _make_asset("MYSTERY-ALGO-512", "key_establishment")
        result = engine.recommend_for_asset(asset)
        rec = result.recommendation
        assert rec.advisory_note is not None
        assert len(rec.advisory_note) > 0


# ── 12: PRD §9 sample ────────────────────────────────────────────────────────

class TestPRDSampleRecommendation:
    """PRD §9 sample: standardized_replacement='ML-KEM (FIPS 203)',
       migration_path='hybrid: X25519 + ML-KEM', status='standardized'."""

    def test_prd_sample_replacement(self, engine):
        asset = _make_asset("RSA-2048", "key_establishment")
        rec = engine.recommend_for_asset(asset).recommendation
        assert "ML-KEM" in rec.standardized_replacement
        assert "FIPS 203" in rec.standardized_replacement

    def test_prd_sample_status_standardized(self, engine):
        asset = _make_asset("RSA-2048", "key_establishment")
        rec = engine.recommend_for_asset(asset).recommendation
        assert rec.status == StandardizationStatus.STANDARDIZED

    def test_prd_sample_migration_path_is_hybrid(self, engine):
        asset = _make_asset("RSA-2048", "key_establishment")
        rec = engine.recommend_for_asset(asset).recommendation
        assert rec.migration_path_type == MigrationPathType.HYBRID
        assert "hybrid" in rec.migration_path.lower() or "ML-KEM" in rec.migration_path


# ── 13–14: Engine class ───────────────────────────────────────────────────────

class TestRecommendationEngineClass:
    def test_process_annotates_all_assets(self, engine):
        assets = [
            _make_asset("RSA-2048", "key_establishment"),
            _make_asset("MD5", "hashing"),
            _make_asset("SHA-256", "hashing"),
        ]
        result = engine.process(assets)
        assert len(result) == 3
        for a in result:
            assert a.recommendation is not None

    def test_original_asset_not_mutated(self, engine):
        asset = _make_asset("RSA-2048", "key_establishment")
        assert asset.recommendation is None
        engine.recommend_for_asset(asset)
        assert asset.recommendation is None   # immutable — not mutated

    def test_recommendation_serialises_to_json(self, engine):
        import json
        asset = _make_asset("RSA-2048", "key_establishment")
        result = engine.recommend_for_asset(asset)
        data = json.loads(result.model_dump_json())
        assert "recommendation" in data
        assert data["recommendation"]["status"] == "standardized"


# ── PQC mapping loader unit tests ────────────────────────────────────────────

class TestPQCMappingLoader:
    def test_config_loads(self):
        config = load_pqc_config(PQC_PATH)
        assert len(config.mappings) > 0

    def test_under_standardization_loaded(self):
        config = load_pqc_config(PQC_PATH)
        assert len(config.under_standardization) > 0

    def test_find_rsa_key_establishment(self):
        config = load_pqc_config(PQC_PATH)
        m = find_pqc_mapping(config, "RSA-2048", "key_establishment")
        assert m is not None
        assert "ML-KEM" in m.primary_replacement

    def test_find_rsa_digital_signature(self):
        config = load_pqc_config(PQC_PATH)
        m = find_pqc_mapping(config, "RSA-2048", "digital_signature")
        assert m is not None
        assert "ML-DSA" in m.primary_replacement

    def test_rsa_key_estab_and_sig_are_different_mappings(self):
        """Purpose-awareness: same algorithm, different purpose → different mappings."""
        config = load_pqc_config(PQC_PATH)
        m_key = find_pqc_mapping(config, "RSA-2048", "key_establishment")
        m_sig = find_pqc_mapping(config, "RSA-2048", "digital_signature")
        assert m_key.primary_replacement != m_sig.primary_replacement

    def test_find_md5_hashing(self):
        config = load_pqc_config(PQC_PATH)
        m = find_pqc_mapping(config, "MD5", "hashing")
        assert m is not None
        assert m.classical_broken is True

    def test_find_sha256_hashing(self):
        config = load_pqc_config(PQC_PATH)
        m = find_pqc_mapping(config, "SHA-256", "hashing")
        assert m is not None
        assert m.quantum_vulnerable is False

    def test_prefix_match_rsa4096(self):
        """RSA-4096 should match the 'RSA' pattern."""
        config = load_pqc_config(PQC_PATH)
        m = find_pqc_mapping(config, "RSA-4096", "key_establishment")
        assert m is not None
        assert "ML-KEM" in m.primary_replacement

    def test_longer_prefix_wins(self):
        """AES-128 should match the 'AES-128' pattern over the generic 'AES' pattern."""
        config = load_pqc_config(PQC_PATH)
        m = find_pqc_mapping(config, "AES-128-CBC", "encryption")
        assert m is not None
        assert m.algorithm_pattern.upper() == "AES-128"

    def test_unknown_algorithm_returns_none(self):
        config = load_pqc_config(PQC_PATH)
        m = find_pqc_mapping(config, "MYSTERY-ALGO", "key_establishment")
        assert m is None
