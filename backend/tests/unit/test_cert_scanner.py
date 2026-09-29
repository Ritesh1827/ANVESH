"""
Unit tests — cert_scanner.py (Day 6)

Validates:
  1.  RSA-2048 certificate produces correct algorithm, key_size, purpose
  2.  RSA-4096 certificate produces correct key_size
  3.  ECDSA P-256 certificate produces correct algorithm and purpose
  4.  RSA-1024 (weak) certificate produces correct key_size
  5.  Expired certificate: asset has correct expiry date (parsed)
  6.  Near-expiry certificate: correct expiry date parsed
  7.  Signature hash asset: second asset with hashing purpose and SHA-256 algorithm
  8.  source_surface is "certificate" on all assets
  9.  DetectionMethod is CERTIFICATE_PARSER on all assets
  10. finding_type is DETERMINISTIC on all assets
  11. confidence is 0.99 on all assets
  12. reachable is None on all assets (no call graph for certs)
  13. certificate_subject, certificate_issuer, certificate_serial populated
  14. certificate_expiry populated and timezone-aware
  15. Staging defaults used (APPLICATION/INTERNAL/LOW) — ClassificationEngine overwrites
  16. Unsupported file extension returns None
  17. Non-certificate file returns error result
  18. Directory scanner finds all .pem files
  19. Directory scanner skips non-cert extensions
  20. SHA-1 signed cert detection via mock (cryptography>=42 blocks live generation)
  21. rule_id C-001 for public key asset, C-002 for signature hash asset
  22. CertScanResult.asset_count property
  23. CertDirectoryScanResult.all_assets flat list
  24. relative_to affects display path in file_path field
"""

from __future__ import annotations

import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ecdat.discovery.cert_scanner import (
    CERT_EXTENSIONS,
    CertDirectoryScanResult,
    CertScanResult,
    scan_certificate_directory,
    scan_certificate_file,
    _extract_public_key_info,
    _cert_expiry_utc,
    PublicKeyInfo,
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

REPO_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = REPO_ROOT / "test_repos" / "certs"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cert_path(name: str) -> Path:
    return CERTS_DIR / name


def _get_fixture_result(name: str) -> CertScanResult:
    r = scan_certificate_file(_cert_path(name), relative_to=CERTS_DIR)
    assert r is not None, f"scan_certificate_file returned None for {name}"
    assert not r.parse_error, f"Parse error for {name}: {r.error_message}"
    return r


# ── 1. Fixture files exist ─────────────────────────────────────────────────────

class TestFixturesExist:
    def test_rsa2048_valid_exists(self):
        assert _cert_path("rsa2048_valid.pem").exists()

    def test_rsa4096_valid_exists(self):
        assert _cert_path("rsa4096_valid.pem").exists()

    def test_ecdsa_p256_valid_exists(self):
        assert _cert_path("ecdsa_p256_valid.pem").exists()

    def test_rsa1024_weak_exists(self):
        assert _cert_path("rsa1024_weak.pem").exists()

    def test_rsa2048_expired_exists(self):
        assert _cert_path("rsa2048_expired.pem").exists()

    def test_rsa2048_near_expiry_exists(self):
        assert _cert_path("rsa2048_near_expiry.pem").exists()

    def test_sha256_signed_exists(self):
        assert _cert_path("sha256_signed.pem").exists()

    def test_self_signed_ca_exists(self):
        assert _cert_path("self_signed_ca.pem").exists()


# ── 2–4. Public key extraction ─────────────────────────────────────────────────

class TestRSA2048Certificate:
    def setup_method(self):
        self.result = _get_fixture_result("rsa2048_valid.pem")
        # Asset 0 = public key, asset 1 = signature hash
        self.pk_asset = self.result.assets[0]

    def test_algorithm_is_rsa2048(self):
        assert self.pk_asset.algorithm == "RSA-2048"

    def test_key_size_is_2048(self):
        assert self.pk_asset.key_size_bits == 2048

    def test_purpose_is_key_establishment(self):
        assert self.pk_asset.purpose == CryptoPurpose.KEY_ESTABLISHMENT

    def test_source_surface_is_certificate(self):
        assert self.pk_asset.source_surface == "certificate"

    def test_rule_id_is_c001(self):
        assert self.pk_asset.evidence.rule_id == "C-001"

    def test_detection_method_is_certificate_parser(self):
        assert self.pk_asset.evidence.detection_method == DetectionMethod.CERTIFICATE_PARSER

    def test_finding_type_is_deterministic(self):
        assert self.pk_asset.evidence.finding_type == FindingType.DETERMINISTIC

    def test_confidence_is_0_99(self):
        assert self.pk_asset.evidence.confidence == 0.99

    def test_reachable_is_none(self):
        assert self.pk_asset.reachable is None

    def test_certificate_subject_populated(self):
        assert self.pk_asset.certificate_subject is not None
        assert len(self.pk_asset.certificate_subject) > 0

    def test_certificate_issuer_populated(self):
        assert self.pk_asset.certificate_issuer is not None

    def test_certificate_serial_populated(self):
        assert self.pk_asset.certificate_serial is not None
        assert self.pk_asset.certificate_serial.startswith("0x")

    def test_certificate_expiry_populated_and_aware(self):
        expiry = self.pk_asset.certificate_expiry
        assert expiry is not None
        assert expiry.tzinfo is not None  # must be timezone-aware

    def test_certificate_expiry_in_future(self):
        expiry = self.pk_asset.certificate_expiry
        assert expiry > datetime.datetime.now(datetime.timezone.utc)

    def test_staging_classification_application(self):
        # Staging default — ClassificationEngine overwrites this
        assert self.pk_asset.classification == AssetClassification.APPLICATION

    def test_staging_sensitivity_internal(self):
        assert self.pk_asset.sensitivity == SensitivityLevel.INTERNAL

    def test_staging_criticality_low(self):
        assert self.pk_asset.business_criticality == BusinessCriticality.LOW

    def test_risk_is_none(self):
        assert self.pk_asset.risk is None

    def test_recommendation_is_none(self):
        assert self.pk_asset.recommendation is None


class TestRSA4096Certificate:
    def test_algorithm_is_rsa4096(self):
        r = _get_fixture_result("rsa4096_valid.pem")
        assert r.assets[0].algorithm == "RSA-4096"

    def test_key_size_is_4096(self):
        r = _get_fixture_result("rsa4096_valid.pem")
        assert r.assets[0].key_size_bits == 4096


class TestECDSAP256Certificate:
    def setup_method(self):
        self.result = _get_fixture_result("ecdsa_p256_valid.pem")
        self.pk_asset = self.result.assets[0]

    def test_algorithm_is_ecdsa_p256(self):
        assert self.pk_asset.algorithm == "ECDSA-P256"

    def test_key_size_is_256(self):
        assert self.pk_asset.key_size_bits == 256

    def test_purpose_is_digital_signature(self):
        assert self.pk_asset.purpose == CryptoPurpose.DIGITAL_SIGNATURE

    def test_source_surface_is_certificate(self):
        assert self.pk_asset.source_surface == "certificate"


class TestRSA1024WeakCertificate:
    def test_algorithm_is_rsa1024(self):
        r = _get_fixture_result("rsa1024_weak.pem")
        assert r.assets[0].algorithm == "RSA-1024"

    def test_key_size_is_1024(self):
        r = _get_fixture_result("rsa1024_weak.pem")
        assert r.assets[0].key_size_bits == 1024

    def test_purpose_is_key_establishment(self):
        r = _get_fixture_result("rsa1024_weak.pem")
        assert r.assets[0].purpose == CryptoPurpose.KEY_ESTABLISHMENT


# ── 5–6. Expiry dates ─────────────────────────────────────────────────────────

class TestCertificateExpiry:
    def test_expired_cert_expiry_in_past(self):
        r = _get_fixture_result("rsa2048_expired.pem")
        expiry = r.assets[0].certificate_expiry
        assert expiry is not None
        assert expiry < datetime.datetime.now(datetime.timezone.utc)

    def test_near_expiry_cert_expiry_in_future(self):
        r = _get_fixture_result("rsa2048_near_expiry.pem")
        expiry = r.assets[0].certificate_expiry
        assert expiry is not None
        assert expiry > datetime.datetime.now(datetime.timezone.utc)

    def test_near_expiry_within_90_days(self):
        r = _get_fixture_result("rsa2048_near_expiry.pem")
        expiry = r.assets[0].certificate_expiry
        days_remaining = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
        assert days_remaining <= 90

    def test_expiry_is_timezone_aware(self):
        for name in ("rsa2048_valid.pem", "rsa2048_expired.pem", "rsa2048_near_expiry.pem"):
            r = _get_fixture_result(name)
            assert r.assets[0].certificate_expiry.tzinfo is not None, (
                f"Expiry on {name} is timezone-naive"
            )


# ── 7. Signature hash asset ────────────────────────────────────────────────────

class TestSignatureHashAsset:
    def setup_method(self):
        self.result = _get_fixture_result("sha256_signed.pem")

    def test_produces_two_assets(self):
        assert len(self.result.assets) == 2

    def test_first_asset_is_public_key(self):
        assert self.result.assets[0].evidence.rule_id == "C-001"
        assert self.result.assets[0].purpose != CryptoPurpose.HASHING

    def test_second_asset_is_signature_hash(self):
        assert self.result.assets[1].evidence.rule_id == "C-002"
        assert self.result.assets[1].purpose == CryptoPurpose.HASHING

    def test_signature_hash_algorithm_is_sha256(self):
        hash_asset = self.result.assets[1]
        assert hash_asset.algorithm == "SHA-256"

    def test_hash_asset_source_surface_is_certificate(self):
        assert self.result.assets[1].source_surface == "certificate"

    def test_hash_asset_reachable_is_none(self):
        assert self.result.assets[1].reachable is None

    def test_hash_asset_shares_subject_with_pk_asset(self):
        # Both assets from same cert share the same certificate_subject
        assert self.result.assets[0].certificate_subject == \
               self.result.assets[1].certificate_subject


# ── 8. SHA-1 signature hash detection via mock ────────────────────────────────

class TestSHA1SignatureHashViaMock:
    """
    SHA-1 certificate signing is blocked by cryptography>=42.
    Test SHA-1 sig hash detection path by mocking the cert object.
    """

    def test_sha1_sig_hash_produces_sha1_asset(self, tmp_path):
        """Mock a cert with SHA-1 signature_hash_algorithm."""
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography import x509 as _x509
        import cryptography.hazmat.primitives.asymmetric.rsa as _rsa

        # Create a real RSA-2048 cert to get the public key / metadata
        real_result = _get_fixture_result("rsa2048_valid.pem")
        real_cert_path = _cert_path("rsa2048_valid.pem")
        real_bytes = real_cert_path.read_bytes()
        real_cert = _x509.load_pem_x509_certificate(real_bytes)

        # Patch signature_hash_algorithm to return SHA1
        mock_cert = MagicMock(spec=_x509.Certificate)
        mock_cert.public_key.return_value = real_cert.public_key()
        mock_cert.subject = real_cert.subject
        mock_cert.issuer = real_cert.issuer
        mock_cert.serial_number = real_cert.serial_number
        mock_cert.not_valid_after_utc = real_cert.not_valid_after_utc
        sha1_mock = MagicMock()
        sha1_mock.name = "sha1"
        mock_cert.signature_hash_algorithm = sha1_mock

        from ecdat.discovery.cert_scanner import (
            _extract_public_key_info,
            _make_cert_asset,
            _HASH_ALG_NAMES,
            CryptoPurpose,
        )

        # Simulate what scan_certificate_file does
        assets = []
        pk_info = _extract_public_key_info(mock_cert)
        assert pk_info is not None
        pk_asset = _make_cert_asset(
            file_path=real_cert_path,
            algorithm=pk_info.algorithm,
            key_size_bits=pk_info.key_size_bits,
            purpose=pk_info.purpose,
            cert=mock_cert,
            rule_id="C-001",
            scan_id=None,
            relative_to=CERTS_DIR,
        )
        assets.append(pk_asset)

        sig_hash = mock_cert.signature_hash_algorithm
        canonical = _HASH_ALG_NAMES.get(sig_hash.name.lower())
        if canonical:
            hash_asset = _make_cert_asset(
                file_path=real_cert_path,
                algorithm=canonical,
                key_size_bits=None,
                purpose=CryptoPurpose.HASHING,
                cert=mock_cert,
                rule_id="C-002",
                scan_id=None,
                relative_to=CERTS_DIR,
            )
            assets.append(hash_asset)

        # Verify SHA-1 hash asset was produced
        assert len(assets) == 2
        hash_a = assets[1]
        assert hash_a.algorithm == "SHA-1"
        assert hash_a.purpose == CryptoPurpose.HASHING
        assert hash_a.evidence.rule_id == "C-002"


# ── 9. File extension and error handling ──────────────────────────────────────

class TestFileHandling:
    def test_unsupported_extension_returns_none(self, tmp_path):
        f = tmp_path / "file.py"
        f.write_text("not a cert")
        result = scan_certificate_file(f)
        assert result is None

    def test_txt_extension_returns_none(self, tmp_path):
        f = tmp_path / "cert.txt"
        f.write_bytes(b"-----BEGIN CERTIFICATE-----")
        result = scan_certificate_file(f)
        assert result is None

    def test_invalid_pem_content_returns_parse_error(self, tmp_path):
        f = tmp_path / "bad.pem"
        f.write_bytes(b"this is not a valid certificate")
        result = scan_certificate_file(f)
        assert result is not None
        assert result.parse_error is True
        assert result.assets == []

    def test_empty_file_returns_parse_error(self, tmp_path):
        f = tmp_path / "empty.pem"
        f.write_bytes(b"")
        result = scan_certificate_file(f)
        assert result is not None
        assert result.parse_error is True

    def test_cert_extensions_set_contains_expected(self):
        assert ".pem" in CERT_EXTENSIONS
        assert ".crt" in CERT_EXTENSIONS
        assert ".cer" in CERT_EXTENSIONS
        assert ".der" in CERT_EXTENSIONS
        assert ".py" not in CERT_EXTENSIONS


# ── 10. CertScanResult properties ────────────────────────────────────────────

class TestCertScanResultProperties:
    def test_asset_count_property(self):
        r = _get_fixture_result("rsa2048_valid.pem")
        assert r.asset_count == len(r.assets)

    def test_asset_count_sha256_signed_is_2(self):
        r = _get_fixture_result("sha256_signed.pem")
        assert r.asset_count == 2

    def test_parse_error_false_for_valid_cert(self):
        r = _get_fixture_result("rsa2048_valid.pem")
        assert r.parse_error is False

    def test_error_message_none_for_valid_cert(self):
        r = _get_fixture_result("rsa2048_valid.pem")
        assert r.error_message is None


# ── 11. Directory scanner ─────────────────────────────────────────────────────

class TestDirectoryScanner:
    def test_scans_certs_dir_finds_pem_files(self):
        result = scan_certificate_directory(CERTS_DIR, relative_to=CERTS_DIR)
        assert result.files_scanned >= 7  # 8 .pem fixtures minus generate script

    def test_all_assets_from_directory(self):
        result = scan_certificate_directory(CERTS_DIR, relative_to=CERTS_DIR)
        assert result.total_assets > 0
        all_a = result.all_assets
        assert len(all_a) == result.total_assets

    def test_python_script_excluded(self):
        result = scan_certificate_directory(CERTS_DIR, relative_to=CERTS_DIR)
        for cr in result.cert_results:
            assert cr.file_path.suffix.lower() != ".py", (
                f"Python file incorrectly scanned: {cr.file_path}"
            )

    def test_directory_skips_non_cert_files(self, tmp_path):
        # Create a dir with one cert and one non-cert
        import shutil
        shutil.copy(_cert_path("rsa2048_valid.pem"), tmp_path / "valid.pem")
        (tmp_path / "readme.txt").write_text("not a cert")
        result = scan_certificate_directory(tmp_path, relative_to=tmp_path)
        assert result.files_scanned == 1
        assert result.files_skipped >= 1

    def test_all_cert_assets_have_certificate_surface(self):
        result = scan_certificate_directory(CERTS_DIR, relative_to=CERTS_DIR)
        for asset in result.all_assets:
            assert asset.source_surface == "certificate"

    def test_all_cert_assets_reachable_none(self):
        result = scan_certificate_directory(CERTS_DIR, relative_to=CERTS_DIR)
        for asset in result.all_assets:
            assert asset.reachable is None

    def test_nonexistent_directory_raises(self):
        with pytest.raises(FileNotFoundError):
            scan_certificate_directory(Path("/nonexistent/dir"))


# ── 12. Relative path handling ────────────────────────────────────────────────

class TestRelativePath:
    def test_relative_path_used_when_provided(self):
        r = scan_certificate_file(
            _cert_path("rsa2048_valid.pem"),
            relative_to=CERTS_DIR,
        )
        assert r is not None
        file_path_in_location = r.assets[0].evidence.location.file_path
        # Should be relative, not absolute
        assert not file_path_in_location.startswith("e:")
        assert "rsa2048_valid.pem" in file_path_in_location

    def test_location_contains_filename(self):
        r = scan_certificate_file(
            _cert_path("rsa2048_valid.pem"),
            relative_to=CERTS_DIR,
        )
        assert "rsa2048_valid.pem" in r.assets[0].location


# ── 13. Self-signed CA certificate ───────────────────────────────────────────

class TestSelfSignedCA:
    def test_ca_cert_parsed_successfully(self):
        r = _get_fixture_result("self_signed_ca.pem")
        assert not r.parse_error

    def test_ca_cert_has_rsa2048_public_key(self):
        r = _get_fixture_result("self_signed_ca.pem")
        assert r.assets[0].algorithm == "RSA-2048"

    def test_ca_cert_subject_equals_issuer(self):
        # Self-signed: subject == issuer
        r = _get_fixture_result("self_signed_ca.pem")
        pk = r.assets[0]
        assert pk.certificate_subject == pk.certificate_issuer
