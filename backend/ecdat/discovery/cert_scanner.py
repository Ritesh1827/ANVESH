"""
Certificate Scanner — PRD §5 stages 1 & 2 (certificate/keys surface).

PRD §5 stage 1: "Ingest ... certificates/keys"
PRD §5 stage 2: "Apply the detection mechanism appropriate to each input type:
                 ... dedicated parsers (certificates)"
PRD §8 Technology Stack: "Certificate parsing: cryptography (pyca) —
                          Direct X.509 parsing (issuer, subject, key algorithm,
                          size, expiry) in a few lines."

This module parses X.509 certificates in PEM or DER format and produces
CryptoAsset records in the same schema used by the source scanner.

Each certificate contributes up to TWO CryptoAsset records:
  1. The PUBLIC KEY asset — the cryptographic primitive in the certificate.
     algorithm, key_size_bits, purpose derived from the public key type.
     This is the primary asset: it carries the key establishment or signing key.

  2. The SIGNATURE HASH asset — the hash algorithm used to sign the certificate.
     Only produced when the signature hash algorithm is identifiable AND
     is distinct from the public key algorithm (i.e. not "self-describing").
     Purpose: hashing. This captures weak-hash cases (e.g. MD5/SHA-1 signed certs).

Both assets carry the certificate's metadata fields:
  certificate_subject, certificate_issuer, certificate_expiry, certificate_serial

Classification fields are LEFT AS STAGING DEFAULTS here.
The ClassificationEngine (stage 6) assigns definitive values via
classification_rules.yaml — no parallel ad-hoc heuristic lives in this module.
This was the entire reason the ClassificationEngine was built before Day 6.

Reachability:
  Certificate assets always receive reachable=None (unknown).
  Certificates have no call graph; reachability cannot be determined from
  static X.509 parsing. The ReachabilityEngine enforces this explicitly.

Read-only guarantee (PRD §6):
  This scanner reads certificate files only. It never modifies them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.x509.oid import NameOID

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
from ecdat.engines.evidence_engine import (
    _STAGING_CLASSIFICATION,
    _STAGING_CRITICALITY,
    _STAGING_SENSITIVITY,
)

logger = logging.getLogger(__name__)

# Supported certificate file extensions
CERT_EXTENSIONS: frozenset[str] = frozenset({
    ".pem", ".crt", ".cer", ".der",
})

# Curve name → canonical algorithm name (matching the existing naming convention)
_EC_CURVE_NAMES: dict[str, str] = {
    "secp256r1":   "ECDSA-P256",
    "secp384r1":   "ECDSA-P384",
    "secp521r1":   "ECDSA-P521",
    "secp256k1":   "ECDSA-K256",
    "brainpoolP256r1": "ECDSA-BRAINPOOL256",
    "brainpoolP384r1": "ECDSA-BRAINPOOL384",
}

# Hash algorithm name → canonical algorithm string
_HASH_ALG_NAMES: dict[str, str] = {
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha1":   "SHA-1",
    "sha224": "SHA-224",
    "md5":    "MD5",
}

# Public key purpose by type
# RSA in a certificate is used for key establishment (TLS key exchange)
# or digital signing depending on key usage extensions. Without parsing
# key usage extensions, we use the heuristic:
#   RSA → key_establishment (most common in TLS server certs)
#   EC  → digital_signature (ECDSA signing key, also used for ECDH)
#   DSA → digital_signature
#   Ed25519/Ed448 → digital_signature
# This is a deliberate, documented simplification for the prototype.
_PK_PURPOSE: dict[str, CryptoPurpose] = {
    "RSA":     CryptoPurpose.KEY_ESTABLISHMENT,
    "EC":      CryptoPurpose.DIGITAL_SIGNATURE,
    "DSA":     CryptoPurpose.DIGITAL_SIGNATURE,
    "Ed25519": CryptoPurpose.DIGITAL_SIGNATURE,
    "Ed448":   CryptoPurpose.DIGITAL_SIGNATURE,
    "X25519":  CryptoPurpose.KEY_ESTABLISHMENT,
    "X448":    CryptoPurpose.KEY_ESTABLISHMENT,
}


# ── Public key extraction ─────────────────────────────────────────────────────

@dataclass
class PublicKeyInfo:
    """Extracted public key information from an X.509 certificate."""
    pk_type: str               # "RSA", "EC", "DSA", "Ed25519", etc.
    algorithm: str             # canonical algorithm name e.g. "RSA-2048", "ECDSA-P256"
    key_size_bits: Optional[int]
    purpose: CryptoPurpose


def _extract_public_key_info(cert: x509.Certificate) -> Optional[PublicKeyInfo]:
    """
    Extract public key type, canonical algorithm name, and key size from a certificate.
    Returns None if the public key type is unrecognised.
    """
    pub = cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        ks = pub.key_size
        return PublicKeyInfo(
            pk_type="RSA",
            algorithm=f"RSA-{ks}",
            key_size_bits=ks,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
        )

    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve_name = pub.curve.name  # e.g. "secp256r1"
        alg = _EC_CURVE_NAMES.get(curve_name, f"ECDSA-{curve_name.upper()}")
        return PublicKeyInfo(
            pk_type="EC",
            algorithm=alg,
            key_size_bits=pub.key_size,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        )

    if isinstance(pub, dsa.DSAPublicKey):
        ks = pub.key_size
        return PublicKeyInfo(
            pk_type="DSA",
            algorithm=f"DSA-{ks}",
            key_size_bits=ks,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        )

    if isinstance(pub, ed25519.Ed25519PublicKey):
        return PublicKeyInfo(
            pk_type="Ed25519",
            algorithm="Ed25519",
            key_size_bits=256,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        )

    if isinstance(pub, ed448.Ed448PublicKey):
        return PublicKeyInfo(
            pk_type="Ed448",
            algorithm="Ed448",
            key_size_bits=448,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        )

    if isinstance(pub, X25519PublicKey):
        return PublicKeyInfo(
            pk_type="X25519",
            algorithm="X25519",
            key_size_bits=256,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
        )

    if isinstance(pub, X448PublicKey):
        return PublicKeyInfo(
            pk_type="X448",
            algorithm="X448",
            key_size_bits=448,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
        )

    logger.warning("Unrecognised public key type: %s", type(pub).__name__)
    return None


# ── Certificate metadata extraction ──────────────────────────────────────────

def _get_cn(name: x509.Name) -> Optional[str]:
    """Extract the Common Name from an X.509 Name, or None."""
    for attr in name:
        if attr.oid == NameOID.COMMON_NAME:
            return str(attr.value)
    return None


def _cert_expiry_utc(cert: x509.Certificate) -> Optional[datetime]:
    """
    Return the certificate's not_valid_after as a timezone-aware UTC datetime.
    cryptography>=42 provides not_valid_after_utc (already aware).
    """
    try:
        # cryptography>=42 API (timezone-aware)
        return cert.not_valid_after_utc
    except AttributeError:
        # Older API fallback (naive, assumed UTC)
        nva = cert.not_valid_after  # type: ignore[attr-defined]
        if nva.tzinfo is None:
            return nva.replace(tzinfo=timezone.utc)
        return nva


def _serial_hex(cert: x509.Certificate) -> str:
    return hex(cert.serial_number)


# ── CryptoAsset construction ──────────────────────────────────────────────────

def _make_cert_asset(
    file_path: Path,
    algorithm: str,
    key_size_bits: Optional[int],
    purpose: CryptoPurpose,
    cert: x509.Certificate,
    rule_id: str,
    scan_id: Optional[str],
    relative_to: Optional[Path],
) -> CryptoAsset:
    """
    Build a CryptoAsset for a certificate-surface finding.

    Classification fields are set to STAGING DEFAULTS — the ClassificationEngine
    will overwrite them with rule-driven values at stage 6. No ad-hoc
    certificate-specific heuristics live here.
    """
    # Display path
    display_path = (
        str(file_path.relative_to(relative_to))
        if relative_to and file_path.is_relative_to(relative_to)
        else str(file_path)
    )
    display_path = display_path.replace("\\", "/")

    # Metadata reads can also fail on exotic certificates (non-UTF8 names,
    # unusual validity encodings). Degrade to placeholders, never raise.
    try:
        subject_str = cert.subject.rfc4514_string()
    except Exception:
        subject_str = "<unreadable subject>"
    try:
        issuer_str = cert.issuer.rfc4514_string()
    except Exception:
        issuer_str = "<unreadable issuer>"
    try:
        expiry = _cert_expiry_utc(cert)
    except Exception:
        expiry = None
    try:
        serial = _serial_hex(cert)
    except Exception:
        serial = None
    try:
        cn = _get_cn(cert.subject)
    except Exception:
        cn = None

    source_location = SourceLocation(
        file_path=display_path,
        # Certificates have no line number — omit
        line_number=None,
        snippet=f"subject={cn or subject_str[:60]}",
    )

    evidence = Evidence(
        detection_method=DetectionMethod.CERTIFICATE_PARSER,
        finding_type=FindingType.DETERMINISTIC,
        rule_id=rule_id,
        location=source_location,
        source_surface="certificate",
        confidence=0.99,   # deterministic X.509 parser — highest confidence
    )

    return CryptoAsset(
        scan_id=scan_id,
        algorithm=algorithm,
        key_size_bits=key_size_bits,
        purpose=purpose,
        location=f"{display_path}",    # certificates have no line number
        source_surface="certificate",
        # ── Staging defaults — ClassificationEngine overwrites these ─────────
        classification=_STAGING_CLASSIFICATION,
        sensitivity=_STAGING_SENSITIVITY,
        business_criticality=_STAGING_CRITICALITY,
        lifecycle_stage=LifecycleStage.ACTIVE,   # overwritten by ClassificationEngine
        # ── Certificate-specific metadata ─────────────────────────────────────
        certificate_subject=subject_str,
        certificate_issuer=issuer_str,
        certificate_expiry=expiry,
        certificate_serial=serial,
        # ── Reachability — always None for certificates (PRD §11) ─────────────
        # Certificates have no call graph. ReachabilityEngine enforces this.
        reachable=None,
        evidence=evidence,
        risk=None,
        recommendation=None,
    )


# ── File-level scanner ────────────────────────────────────────────────────────

@dataclass
class CertScanResult:
    """Result of parsing a single certificate file."""
    file_path: Path
    assets: list[CryptoAsset]
    parse_error: bool = False
    error_message: Optional[str] = None

    @property
    def asset_count(self) -> int:
        return len(self.assets)


def scan_certificate_file(
    file_path: Path,
    scan_id: Optional[str] = None,
    relative_to: Optional[Path] = None,
) -> Optional[CertScanResult]:
    """
    Parse a single X.509 certificate file (PEM or DER) and return
    a list of CryptoAsset records.

    Returns None if the file extension is not a supported certificate format.
    Returns a CertScanResult with parse_error=True if the file cannot be parsed.

    One certificate file produces up to two assets:
      1. The public key asset (algorithm, key_size, purpose)
      2. The signature hash asset (only when the sig hash is identifiable)
    """
    file_path = Path(file_path)

    if file_path.suffix.lower() not in CERT_EXTENSIONS:
        return None

    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        return CertScanResult(
            file_path=file_path,
            assets=[],
            parse_error=True,
            error_message=f"Cannot read file: {exc}",
        )

    # Try PEM first, then DER
    cert: Optional[x509.Certificate] = None
    try:
        cert = x509.load_pem_x509_certificate(raw)
    except Exception:
        pass

    if cert is None:
        try:
            cert = x509.load_der_x509_certificate(raw)
        except Exception as exc:
            logger.warning("Cannot parse certificate %s: %s", file_path, exc)
            return CertScanResult(
                file_path=file_path,
                assets=[],
                parse_error=True,
                error_message=str(exc),
            )

    assets: list[CryptoAsset] = []

    # ── Asset 1: Public key ───────────────────────────────────────────────────
    # Real-world corpora contain keys the library cannot model (explicit
    # EC parameters, GOST, DH...). Those yield zero assets for this file,
    # never an exception — a scanner must degrade per file, not per scan.
    try:
        pk_info = _extract_public_key_info(cert)
    except Exception as exc:
        logger.warning("Unsupported public key in %s: %s", file_path, exc)
        pk_info = None
    if pk_info is not None:
        pk_asset = _make_cert_asset(
            file_path=file_path,
            algorithm=pk_info.algorithm,
            key_size_bits=pk_info.key_size_bits,
            purpose=pk_info.purpose,
            cert=cert,
            rule_id="C-001",   # Certificate public key
            scan_id=scan_id,
            relative_to=relative_to,
        )
        assets.append(pk_asset)
    else:
        logger.warning("Could not extract public key info from %s", file_path)

    # ── Asset 2: Signature hash algorithm ─────────────────────────────────────
    # Produces a hashing asset when the certificate's signature algorithm
    # uses an identifiable hash function. Captures weak-hash scenarios
    # (SHA-1 signed certs from older CAs, MD5 signed legacy certs).
    # Same per-file degradation: an exotic signature OID is skipped, not fatal.
    try:
        sig_hash = cert.signature_hash_algorithm
    except Exception as exc:
        logger.warning("Unreadable signature algorithm in %s: %s", file_path, exc)
        sig_hash = None
    if sig_hash is not None:
        hash_name_raw = sig_hash.name.lower()   # e.g. "sha256", "sha1", "md5"
        canonical = _HASH_ALG_NAMES.get(hash_name_raw)
        if canonical is not None:
            hash_asset = _make_cert_asset(
                file_path=file_path,
                algorithm=canonical,
                key_size_bits=None,
                purpose=CryptoPurpose.HASHING,
                cert=cert,
                rule_id="C-002",   # Certificate signature hash
                scan_id=scan_id,
                relative_to=relative_to,
            )
            assets.append(hash_asset)

    logger.debug(
        "Parsed %s: %d asset(s) — %s",
        file_path.name,
        len(assets),
        ", ".join(a.algorithm for a in assets),
    )

    return CertScanResult(file_path=file_path, assets=assets)


# ── Directory scanner ─────────────────────────────────────────────────────────

@dataclass
class CertDirectoryScanResult:
    """Aggregate result of scanning a directory for certificate files."""
    root_path: Path
    cert_results: list[CertScanResult]
    files_scanned: int
    files_skipped: int

    @property
    def all_assets(self) -> list[CryptoAsset]:
        """Flat list of all CryptoAsset records across all parsed certificates."""
        assets = []
        for cr in self.cert_results:
            assets.extend(cr.assets)
        return assets

    @property
    def total_assets(self) -> int:
        return sum(cr.asset_count for cr in self.cert_results)


def scan_certificate_directory(
    root_path: Path,
    scan_id: Optional[str] = None,
    relative_to: Optional[Path] = None,
    exclude_dirs: Optional[set[str]] = None,
) -> CertDirectoryScanResult:
    """
    Recursively scan a directory for X.509 certificate files.

    Args:
        root_path:    Root directory to scan.
        scan_id:      Optional scan run identifier.
        relative_to:  Base path for relative display paths.
        exclude_dirs: Directory names to skip.

    Returns:
        CertDirectoryScanResult with all parsed certificate assets.
    """
    root_path = Path(root_path)
    if not root_path.exists():
        raise FileNotFoundError(f"Certificate scan root not found: {root_path}")

    if exclude_dirs is None:
        exclude_dirs = {".git", ".venv", "venv", "env", "node_modules", "__pycache__"}

    cert_results: list[CertScanResult] = []
    files_skipped = 0

    for item in sorted(root_path.rglob("*")):
        if any(part in exclude_dirs for part in item.parts):
            continue
        if not item.is_file():
            continue

        if item.suffix.lower() not in CERT_EXTENSIONS:
            files_skipped += 1
            continue

        result = scan_certificate_file(
            item,
            scan_id=scan_id,
            relative_to=relative_to or root_path,
        )
        if result is not None:
            cert_results.append(result)
        else:
            files_skipped += 1

    total = len(cert_results)
    total_assets = sum(r.asset_count for r in cert_results)
    logger.info(
        "Certificate scan: %d files parsed, %d skipped, %d assets extracted",
        total, files_skipped, total_assets,
    )

    return CertDirectoryScanResult(
        root_path=root_path,
        cert_results=cert_results,
        files_scanned=total,
        files_skipped=files_skipped,
    )
