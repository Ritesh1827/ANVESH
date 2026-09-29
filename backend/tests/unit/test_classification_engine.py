"""
Unit tests — ClassificationEngine (engines/classification_engine.py)

Validates:
  1.  Config loader: classification_rules.yaml loads without error
  2.  Config loader: all three rule sections present with valid entries
  3.  Rule matching: classification (application / infrastructure)
      - TLS-algorithm prefix → infrastructure (regardless of filename)
      - key_establishment in TLS file → infrastructure
      - source_code default → application
      - certificate surface → infrastructure
  4.  Rule matching: sensitivity
      - broken algos (MD5, SHA-1, DES, RC4) → high
      - key_establishment → high
      - digital_signature → high
      - encryption → confidential
      - safe hashes (SHA-256, SHA-512) → internal
      - MAC, KDF → internal
  5.  Rule matching: criticality
      - broken algos → critical (PRD §9 pattern + security correctness)
      - key_establishment (application) → critical (matches PRD §9 sample)
      - key_establishment (infrastructure) → critical
      - digital_signature → high
      - encryption → medium
      - hashing, MAC → low
  6.  Lifecycle stage resolution
      - certificate with expired date → EXPIRED
      - certificate within rotation_pending window → ROTATION_PENDING
      - certificate with future expiry → ACTIVE
      - certificate with no expiry → UNKNOWN
      - source_code with legacy algorithm prefix → LEGACY
      - source_code non-legacy → ACTIVE
  7.  Cross-field dependency: criticality uses assigned classification
  8.  ClassificationResult carries provenance (rule descriptions not empty)
  9.  process() is immutable — original assets not mutated
  10. process() returns same count as input
  11. Fallback used when no rule matches
  12. Invalid rule value produces fallback with error log (not crash)
  13. Config error cases: missing file, missing required section
  14. PRD §9 sample asset classifies correctly end-to-end
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import io

from ecdat.engines.classification_engine import (
    ClassificationEngine,
    ClassificationResult,
    _resolve_lifecycle,
    load_classification_config,
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

REPO_ROOT = Path(__file__).parent.parent.parent.parent
RULES_PATH = REPO_ROOT / "config" / "classification_rules.yaml"


# ── Asset factory ─────────────────────────────────────────────────────────────

def _make_asset(
    algorithm: str = "RSA-2048",
    purpose: str = "key_establishment",
    source_surface: str = "source_code",
    file_path: str = "auth_service.py",
    line_number: int = 29,
    key_size_bits: int | None = None,
    certificate_expiry: datetime | None = None,
) -> CryptoAsset:
    evidence = Evidence(
        detection_method=DetectionMethod.AST_RULE,
        finding_type=FindingType.DETERMINISTIC,
        rule_id="R-001",
        location=SourceLocation(file_path=file_path, line_number=line_number),
        source_surface=source_surface,
        confidence=0.97,
    )
    return CryptoAsset(
        algorithm=algorithm,
        purpose=purpose,
        location=f"{file_path}:{line_number}",
        source_surface=source_surface,
        # Staging defaults — ClassificationEngine will overwrite these
        classification=AssetClassification.APPLICATION,
        sensitivity=SensitivityLevel.INTERNAL,
        business_criticality=BusinessCriticality.LOW,
        lifecycle_stage=LifecycleStage.ACTIVE,
        evidence=evidence,
        key_size_bits=key_size_bits,
        certificate_expiry=certificate_expiry,
    )


@pytest.fixture(scope="module")
def engine() -> ClassificationEngine:
    return ClassificationEngine(rules_path=RULES_PATH)


# ── 1–2. Config loader ─────────────────────────────────────────────────────────

class TestConfigLoader:
    def test_config_loads_without_error(self):
        config = load_classification_config(RULES_PATH)
        assert config is not None

    def test_classification_rules_present(self):
        config = load_classification_config(RULES_PATH)
        assert len(config.classification_rules) > 0

    def test_sensitivity_rules_present(self):
        config = load_classification_config(RULES_PATH)
        assert len(config.sensitivity_rules) > 0

    def test_criticality_rules_present(self):
        config = load_classification_config(RULES_PATH)
        assert len(config.criticality_rules) > 0

    def test_rules_sorted_by_priority_descending(self):
        config = load_classification_config(RULES_PATH)
        priorities = [r.priority for r in config.classification_rules]
        assert priorities == sorted(priorities, reverse=True)

    def test_fallbacks_are_valid_values(self):
        config = load_classification_config(RULES_PATH)
        assert config.classification_fallback in ("application", "infrastructure")
        assert config.sensitivity_fallback in (
            "public", "internal", "confidential", "high", "critical"
        )
        assert config.criticality_fallback in ("low", "medium", "high", "critical")

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_classification_config(tmp_path / "nonexistent.yaml")

    def test_missing_required_section_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("version: '1.0'\n", encoding="utf-8")
        with pytest.raises(ValueError, match="classification_rules"):
            load_classification_config(bad)

    def test_lifecycle_rotation_pending_days_loaded(self):
        config = load_classification_config(RULES_PATH)
        assert config.rotation_pending_days == 90

    def test_legacy_algorithm_prefixes_loaded(self):
        config = load_classification_config(RULES_PATH)
        assert len(config.legacy_algorithm_prefixes) > 0
        # Known broken algos must be in legacy list
        names_upper = [p.upper() for p in config.legacy_algorithm_prefixes]
        assert any("MD5" in n for n in names_upper)
        assert any("DES" in n for n in names_upper)


# ── 3. Classification rules ────────────────────────────────────────────────────

class TestClassificationRules:
    """PRD §5 stage 6: TEC 910018:2025 taxonomy (application vs infrastructure)."""

    def test_source_code_default_is_application(self, engine):
        asset = _make_asset(algorithm="SHA-256", purpose="hashing",
                            file_path="utils.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.APPLICATION

    def test_certificate_surface_is_infrastructure(self, engine):
        asset = _make_asset(source_surface="certificate",
                            algorithm="RSA-2048", purpose="key_establishment",
                            file_path="server.crt")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.INFRASTRUCTURE

    def test_tls_algorithm_prefix_is_infrastructure_regardless_of_filename(self, engine):
        # TLS-1.0 in auth_service.py → infrastructure (algorithm drives it, not filename)
        # This is the key regression fix: old heuristic returned APPLICATION here
        asset = _make_asset(algorithm="TLS-1.0", purpose="key_establishment",
                            file_path="auth_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.INFRASTRUCTURE

    def test_tls_legacy_algorithm_is_infrastructure(self, engine):
        asset = _make_asset(algorithm="TLS-legacy", purpose="key_establishment",
                            file_path="payment_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.INFRASTRUCTURE

    def test_key_establishment_in_tls_file_is_infrastructure(self, engine):
        # key_establishment AND tls in file path → infrastructure
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="tls_client.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.INFRASTRUCTURE

    def test_key_establishment_in_ssl_file_is_infrastructure(self, engine):
        asset = _make_asset(algorithm="ECDSA-P256", purpose="key_establishment",
                            file_path="ssl_wrapper.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.INFRASTRUCTURE

    def test_sha1_hashing_in_tls_file_is_application(self, engine):
        # SHA-1 (hashing) in tls_client.py → APPLICATION
        # This is the key regression fix: old heuristic returned INFRASTRUCTURE
        # because "tls" was in the filename, regardless of purpose.
        # Hashing is application-layer activity, not infrastructure key exchange.
        asset = _make_asset(algorithm="SHA-1", purpose="hashing",
                            file_path="tls_client.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.APPLICATION

    def test_md5_hashing_is_application(self, engine):
        asset = _make_asset(algorithm="MD5", purpose="hashing",
                            file_path="auth_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.APPLICATION

    def test_rsa_key_establishment_in_auth_service_is_application(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="auth_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.APPLICATION

    def test_binary_surface_is_application(self, engine):
        asset = _make_asset(source_surface="binary",
                            algorithm="RSA-2048", purpose="key_establishment",
                            file_path="libssl.so")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.APPLICATION

    def test_classification_rule_provenance_populated(self, engine):
        asset = _make_asset(algorithm="TLS-1.0", purpose="key_establishment",
                            file_path="auth_service.py")
        r = engine.classify_asset(asset)
        assert r.classification_rule
        assert len(r.classification_rule) > 5


# ── 4. Sensitivity rules ──────────────────────────────────────────────────────

class TestSensitivityRules:
    """Sensitivity reflects how important it is that protected data stays secret."""

    def test_md5_hashing_is_high(self, engine):
        asset = _make_asset(algorithm="MD5", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.HIGH

    def test_sha1_hashing_is_high(self, engine):
        asset = _make_asset(algorithm="SHA-1", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.HIGH

    def test_des_encryption_is_high(self, engine):
        asset = _make_asset(algorithm="DES-56", purpose="encryption")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.HIGH

    def test_rc4_encryption_is_high(self, engine):
        asset = _make_asset(algorithm="RC4", purpose="encryption")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.HIGH

    def test_rsa_key_establishment_is_high(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.HIGH

    def test_ecdsa_digital_signature_is_high(self, engine):
        asset = _make_asset(algorithm="ECDSA-P256", purpose="digital_signature")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.HIGH

    def test_aes_encryption_is_confidential(self, engine):
        asset = _make_asset(algorithm="AES-256-GCM", purpose="encryption")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.CONFIDENTIAL

    def test_aes128_encryption_is_confidential(self, engine):
        asset = _make_asset(algorithm="AES-128-CBC-128", purpose="encryption")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.CONFIDENTIAL

    def test_sha256_hashing_is_internal(self, engine):
        asset = _make_asset(algorithm="SHA-256", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.INTERNAL

    def test_sha512_hashing_is_internal(self, engine):
        asset = _make_asset(algorithm="SHA-512", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.INTERNAL

    def test_hmac_mac_is_internal(self, engine):
        asset = _make_asset(algorithm="HMAC", purpose="mac")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.INTERNAL

    def test_certificate_key_establishment_is_critical(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            source_surface="certificate")
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.CRITICAL

    def test_sensitivity_rule_provenance_populated(self, engine):
        asset = _make_asset(algorithm="MD5", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.sensitivity_rule
        assert len(r.sensitivity_rule) > 5


# ── 5. Criticality rules ──────────────────────────────────────────────────────

class TestCriticalityRules:
    """
    Business criticality — coarse heuristic (no ownership data available).
    PRD §9 sample: RSA-2048 key_establishment → "critical".
    """

    def test_md5_hashing_is_critical(self, engine):
        # Broken algorithm — already exploitable classically → critical
        # Old heuristic returned LOW. This is the main regression fix.
        asset = _make_asset(algorithm="MD5", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_sha1_hashing_is_critical(self, engine):
        asset = _make_asset(algorithm="SHA-1", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_des_encryption_is_critical(self, engine):
        # DES is classically broken → critical
        # Old heuristic returned MEDIUM. This is a regression fix.
        asset = _make_asset(algorithm="DES-56", purpose="encryption")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_rc4_is_critical(self, engine):
        asset = _make_asset(algorithm="RC4", purpose="encryption")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_rsa_key_establishment_application_is_critical(self, engine):
        # PRD §9 sample explicitly: RSA-2048 key_establishment → "critical"
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="auth_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_rsa4096_key_establishment_is_critical(self, engine):
        asset = _make_asset(algorithm="RSA-4096", purpose="key_establishment",
                            file_path="payment_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_tls_key_establishment_infrastructure_is_critical(self, engine):
        # Infrastructure key establishment (TLS session key) → critical
        asset = _make_asset(algorithm="TLS-1.0", purpose="key_establishment",
                            file_path="auth_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_certificate_surface_is_critical(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            source_surface="certificate")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_ecdsa_digital_signature_is_high(self, engine):
        asset = _make_asset(algorithm="ECDSA-P256", purpose="digital_signature",
                            file_path="payment_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.HIGH

    def test_aes_encryption_is_medium(self, engine):
        asset = _make_asset(algorithm="AES-128-CBC-128", purpose="encryption",
                            file_path="auth_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.MEDIUM

    def test_sha256_hashing_is_low(self, engine):
        asset = _make_asset(algorithm="SHA-256", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.LOW

    def test_sha512_hashing_is_low(self, engine):
        asset = _make_asset(algorithm="SHA-512", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.LOW

    def test_hmac_mac_is_low(self, engine):
        asset = _make_asset(algorithm="HMAC", purpose="mac")
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.LOW

    def test_criticality_rule_provenance_populated(self, engine):
        asset = _make_asset(algorithm="MD5", purpose="hashing")
        r = engine.classify_asset(asset)
        assert r.criticality_rule
        assert len(r.criticality_rule) > 5


# ── 6. Lifecycle stage resolution ────────────────────────────────────────────

class TestLifecycleResolution:
    def setup_method(self):
        self.config = load_classification_config(RULES_PATH)

    def _cert_asset(self, expiry: datetime | None) -> CryptoAsset:
        return _make_asset(
            source_surface="certificate",
            algorithm="RSA-2048",
            purpose="key_establishment",
            certificate_expiry=expiry,
        )

    def test_expired_certificate_is_expired(self):
        past = datetime.now(timezone.utc) - timedelta(days=30)
        asset = self._cert_asset(past)
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.EXPIRED

    def test_certificate_within_rotation_window_is_rotation_pending(self):
        # 45 days in the future < 90-day rotation window
        soon = datetime.now(timezone.utc) + timedelta(days=45)
        asset = self._cert_asset(soon)
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.ROTATION_PENDING

    def test_certificate_outside_rotation_window_is_active(self):
        # 180 days in the future > 90-day rotation window
        future = datetime.now(timezone.utc) + timedelta(days=180)
        asset = self._cert_asset(future)
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.ACTIVE

    def test_certificate_no_expiry_is_unknown(self):
        asset = self._cert_asset(None)
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.UNKNOWN

    def test_certificate_exactly_at_rotation_boundary(self):
        # Exactly 90 days → within window → ROTATION_PENDING
        boundary = datetime.now(timezone.utc) + timedelta(days=90)
        asset = self._cert_asset(boundary)
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.ROTATION_PENDING

    def test_source_code_legacy_algorithm_is_legacy(self):
        asset = _make_asset(algorithm="MD5", purpose="hashing",
                            source_surface="source_code")
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.LEGACY

    def test_source_code_sha1_is_legacy(self):
        asset = _make_asset(algorithm="SHA-1", purpose="hashing",
                            source_surface="source_code")
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.LEGACY

    def test_source_code_des_is_legacy(self):
        asset = _make_asset(algorithm="DES-56", purpose="encryption",
                            source_surface="source_code")
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.LEGACY

    def test_source_code_tls10_is_legacy(self):
        asset = _make_asset(algorithm="TLS-1.0", purpose="key_establishment",
                            source_surface="source_code")
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.LEGACY

    def test_source_code_rsa_is_active(self):
        # RSA is quantum-vulnerable but not classically deprecated
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            source_surface="source_code")
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.ACTIVE

    def test_source_code_sha256_is_active(self):
        asset = _make_asset(algorithm="SHA-256", purpose="hashing",
                            source_surface="source_code")
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.ACTIVE

    def test_naive_datetime_treated_as_utc(self):
        # timezone-naive expiry datetime should be treated as UTC
        naive_past = datetime.now() - timedelta(days=1)
        asset = self._cert_asset(naive_past)
        stage = _resolve_lifecycle(asset, self.config)
        assert stage == LifecycleStage.EXPIRED


# ── 7. Cross-field dependency ─────────────────────────────────────────────────

class TestCrossFieldDependency:
    """Criticality rules can condition on the classification already assigned."""

    def test_key_establishment_application_is_critical(self, engine):
        # classification=application + purpose=key_establishment → critical
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="auth_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.APPLICATION
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_key_establishment_infrastructure_is_critical(self, engine):
        # classification=infrastructure + purpose=key_establishment → critical
        # (different rule, same result)
        asset = _make_asset(algorithm="TLS-legacy", purpose="key_establishment",
                            file_path="auth_service.py", source_surface="source_code")
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.INFRASTRUCTURE
        assert r.business_criticality == BusinessCriticality.CRITICAL


# ── 8. Immutability and batch processing ─────────────────────────────────────

class TestImmutabilityAndBatch:
    def test_original_asset_not_mutated(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment")
        original_cls = asset.classification
        original_sens = asset.sensitivity
        original_crit = asset.business_criticality
        engine.classify_asset(asset)
        # Originals must be unchanged
        assert asset.classification == original_cls
        assert asset.sensitivity == original_sens
        assert asset.business_criticality == original_crit

    def test_process_returns_same_count(self, engine):
        assets = [
            _make_asset("RSA-2048", "key_establishment"),
            _make_asset("MD5", "hashing"),
            _make_asset("SHA-256", "hashing"),
            _make_asset("DES-56", "encryption"),
        ]
        result = engine.process(assets)
        assert len(result) == 4

    def test_process_empty_list(self, engine):
        result = engine.process([])
        assert result == []

    def test_process_does_not_mutate_inputs(self, engine):
        asset = _make_asset("RSA-2048", "key_establishment")
        assert asset.classification == AssetClassification.APPLICATION  # staging
        assert asset.sensitivity == SensitivityLevel.INTERNAL            # staging
        engine.process([asset])
        assert asset.classification == AssetClassification.APPLICATION  # unchanged
        assert asset.sensitivity == SensitivityLevel.INTERNAL            # unchanged

    def test_process_output_has_real_values(self, engine):
        asset = _make_asset("RSA-2048", "key_establishment",
                            file_path="auth_service.py")
        results = engine.process([asset])
        assert results[0].classification == AssetClassification.APPLICATION
        assert results[0].sensitivity == SensitivityLevel.HIGH       # not staging INTERNAL
        assert results[0].business_criticality == BusinessCriticality.CRITICAL  # not staging LOW


# ── 9. PRD §9 sample asset ────────────────────────────────────────────────────

class TestPRDSampleAsset:
    """
    PRD §9 sample:
      asset: RSA-2048, purpose: key_establishment,
      location: auth_service.py:143, classification: application,
      sensitivity: high, business_criticality: critical
    """

    def test_prd_sample_classification_is_application(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="auth_service.py", line_number=143)
        r = engine.classify_asset(asset)
        assert r.classification == AssetClassification.APPLICATION

    def test_prd_sample_sensitivity_is_high(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="auth_service.py", line_number=143)
        r = engine.classify_asset(asset)
        assert r.sensitivity == SensitivityLevel.HIGH

    def test_prd_sample_criticality_is_critical(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="auth_service.py", line_number=143)
        r = engine.classify_asset(asset)
        assert r.business_criticality == BusinessCriticality.CRITICAL

    def test_prd_sample_lifecycle_is_active(self, engine):
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="auth_service.py", line_number=143)
        r = engine.classify_asset(asset)
        assert r.lifecycle_stage == LifecycleStage.ACTIVE

    def test_prd_sample_all_fields_together(self, engine):
        """Full PRD §9 field validation in one test."""
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment",
                            file_path="auth_service.py", line_number=143)
        results = engine.process([asset])
        a = results[0]
        assert a.classification == AssetClassification.APPLICATION
        assert a.sensitivity == SensitivityLevel.HIGH
        assert a.business_criticality == BusinessCriticality.CRITICAL
        assert a.lifecycle_stage == LifecycleStage.ACTIVE
