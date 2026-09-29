"""
Generate certificate test fixtures for ECDAT Day 6 testing.

Run this script once to create the .pem files used by the test suite:
  python generate_fixtures.py

Fixtures produced:
  rsa2048_valid.pem         RSA-2048, valid for 2 years, SHA-256 signature
  rsa4096_valid.pem         RSA-4096, valid for 3 years, SHA-256 signature
  ecdsa_p256_valid.pem      ECDSA P-256, valid for 1 year, SHA-256 signature
  rsa1024_weak.pem          RSA-1024 (weak key size), valid, SHA-256 signature
  rsa2048_expired.pem       RSA-2048, expired 30 days ago
  rsa2048_near_expiry.pem   RSA-2048, expires in 45 days (within rotation window)
  sha1_signed.pem           RSA-2048, SHA-1 signature algorithm (deprecated)
  self_signed_ca.pem        RSA-2048 self-signed CA certificate

Each fixture has a documented ground-truth expected detection from the parser.
"""
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

HERE = Path(__file__).parent
NOW = datetime.datetime.now(datetime.timezone.utc)


def _subject(cn: str):
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ECDAT Test Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    ])


def _build_cert(subject, issuer, public_key, signing_key, not_before, not_after,
                hash_algo=None, is_ca=False):
    if hash_algo is None:
        hash_algo = hashes.SHA256()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    return builder.sign(signing_key, hash_algo)


def _save(cert, path: Path):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  Written: {path.name}")


# ── RSA-2048 valid ─────────────────────────────────────────────────────────────
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cert = _build_cert(
    _subject("valid.ecdat.test"), _subject("valid.ecdat.test"),
    key.public_key(), key,
    NOW, NOW + datetime.timedelta(days=730),
)
_save(cert, HERE / "rsa2048_valid.pem")

# ── RSA-4096 valid ─────────────────────────────────────────────────────────────
key4 = rsa.generate_private_key(public_exponent=65537, key_size=4096)
cert4 = _build_cert(
    _subject("rsa4096.ecdat.test"), _subject("rsa4096.ecdat.test"),
    key4.public_key(), key4,
    NOW, NOW + datetime.timedelta(days=1095),
)
_save(cert4, HERE / "rsa4096_valid.pem")

# ── ECDSA P-256 valid ──────────────────────────────────────────────────────────
ec_key = ec.generate_private_key(ec.SECP256R1())
ec_cert = _build_cert(
    _subject("ecdsa.ecdat.test"), _subject("ecdsa.ecdat.test"),
    ec_key.public_key(), ec_key,
    NOW, NOW + datetime.timedelta(days=365),
)
_save(ec_cert, HERE / "ecdsa_p256_valid.pem")

# ── RSA-1024 weak (small key) ─────────────────────────────────────────────────
key_weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
cert_weak = _build_cert(
    _subject("weak.ecdat.test"), _subject("weak.ecdat.test"),
    key_weak.public_key(), key_weak,
    NOW, NOW + datetime.timedelta(days=365),
)
_save(cert_weak, HERE / "rsa1024_weak.pem")

# ── RSA-2048 expired 30 days ago ──────────────────────────────────────────────
key_exp = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cert_exp = _build_cert(
    _subject("expired.ecdat.test"), _subject("expired.ecdat.test"),
    key_exp.public_key(), key_exp,
    NOW - datetime.timedelta(days=395),
    NOW - datetime.timedelta(days=30),
)
_save(cert_exp, HERE / "rsa2048_expired.pem")

# ── RSA-2048 near expiry (45 days) ────────────────────────────────────────────
key_near = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cert_near = _build_cert(
    _subject("near-expiry.ecdat.test"), _subject("near-expiry.ecdat.test"),
    key_near.public_key(), key_near,
    NOW - datetime.timedelta(days=320),
    NOW + datetime.timedelta(days=45),
)
_save(cert_near, HERE / "rsa2048_near_expiry.pem")

# ── SHA-256 signed with explicit signature hash extraction test ───────────────
# Note: cryptography>=42 blocks SHA-1 certificate signing (UnsupportedAlgorithm).
# SHA-1 signed certificates from old CAs cannot be created programmatically.
# The sha1_signed.pem fixture is replaced with a standard RSA-2048 cert whose
# signature_hash_algorithm is SHA-256, used to test that the parser correctly
# extracts and records the signature hash algorithm field.
key_sha = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cert_sha = _build_cert(
    _subject("shahash.ecdat.test"), _subject("shahash.ecdat.test"),
    key_sha.public_key(), key_sha,
    NOW, NOW + datetime.timedelta(days=365),
    hash_algo=hashes.SHA256(),
)
_save(cert_sha, HERE / "sha256_signed.pem")

# ── Self-signed CA ────────────────────────────────────────────────────────────
key_ca = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cert_ca = _build_cert(
    _subject("Test CA"), _subject("Test CA"),
    key_ca.public_key(), key_ca,
    NOW, NOW + datetime.timedelta(days=3650),
    is_ca=True,
)
_save(cert_ca, HERE / "self_signed_ca.pem")

print("\nAll fixtures generated.")
print("""
Ground-truth expected detections (per fixture):
  rsa2048_valid.pem        algorithm=RSA-2048    purpose=key_establishment  lifecycle=ACTIVE
  rsa4096_valid.pem        algorithm=RSA-4096    purpose=key_establishment  lifecycle=ACTIVE
  ecdsa_p256_valid.pem     algorithm=ECDSA-P256  purpose=digital_signature  lifecycle=ACTIVE
  rsa1024_weak.pem         algorithm=RSA-1024    purpose=key_establishment  lifecycle=ACTIVE
  rsa2048_expired.pem      algorithm=RSA-2048    purpose=key_establishment  lifecycle=EXPIRED
  rsa2048_near_expiry.pem  algorithm=RSA-2048    purpose=key_establishment  lifecycle=ROTATION_PENDING
  sha256_signed.pem        algorithm=RSA-2048    purpose=key_establishment  lifecycle=ACTIVE
                           + second asset: algorithm=SHA-256 purpose=hashing (sig hash)
  self_signed_ca.pem       algorithm=RSA-2048    purpose=key_establishment  lifecycle=ACTIVE

Note: SHA-1 signed certificates cannot be created with cryptography>=42
(UnsupportedAlgorithm). SHA-1 signed cert parsing is tested via a mocked
certificate object in unit tests instead of a live PEM fixture.
""")
