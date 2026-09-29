"""
Generate presentation-ready certificate fixtures for the ECDAT demo API.

Run once to create the .pem files surfaced on the Certificates dashboard page:
  python generate_demo_certs.py

These fixtures are separate from test_repos/certs/, which remains load-bearing
for the unit and integration test suite.

Fixtures produced:
  citizen_portal_active.pem          RSA-2048, citizen-portal.gov.in, valid 2 years
  payment_gateway_active.pem           ECDSA P-256, payment-gateway.internal, valid 1 year
  data_platform_active.pem             RSA-4096, data-platform.internal, valid 3 years
  citizen_portal_near_expiry.pem       RSA-2048, analytics.citizen-portal.gov.in, expires in 45 days
  legacy_auth_expired.pem              RSA-2048, legacy-auth-service.internal, expired 30 days ago
  legacy_auth_weak.pem                 RSA-1024, dev-sandbox.internal, weak key size, still valid
  internal_pki_root_ca.pem             RSA-2048 self-signed internal CA
"""
from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

HERE = Path(__file__).parent
NOW = datetime.datetime.now(datetime.timezone.utc)


def _subject(
    cn: str,
    *,
    org: str = "ECDAT Demo Environment",
    country: str = "IN",
) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ]
    )


def _build_cert(
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
    signing_key,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    *,
    hash_algo=None,
    is_ca: bool = False,
) -> x509.Certificate:
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
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
    return builder.sign(signing_key, hash_algo)


def _save(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  Written: {path.name}")


# ── Active / healthy certificates ─────────────────────────────────────────────

portal_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
portal_subject = _subject(
    "citizen-portal.gov.in",
    org="Directorate of Digital Governance",
)
_save(
    _build_cert(
        portal_subject,
        portal_subject,
        portal_key.public_key(),
        portal_key,
        NOW,
        NOW + datetime.timedelta(days=730),
    ),
    HERE / "citizen_portal_active.pem",
)

payment_key = ec.generate_private_key(ec.SECP256R1())
payment_subject = _subject(
    "payment-gateway.internal",
    org="FinSecure Payments Pvt Ltd",
)
_save(
    _build_cert(
        payment_subject,
        payment_subject,
        payment_key.public_key(),
        payment_key,
        NOW,
        NOW + datetime.timedelta(days=365),
    ),
    HERE / "payment_gateway_active.pem",
)

platform_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
platform_subject = _subject(
    "data-platform.internal",
    org="Enterprise Data Services",
)
_save(
    _build_cert(
        platform_subject,
        platform_subject,
        platform_key.public_key(),
        platform_key,
        NOW,
        NOW + datetime.timedelta(days=1095),
    ),
    HERE / "data_platform_active.pem",
)

# ── Near expiry ───────────────────────────────────────────────────────────────

near_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
near_subject = _subject(
    "analytics.citizen-portal.gov.in",
    org="Directorate of Digital Governance",
)
_save(
    _build_cert(
        near_subject,
        near_subject,
        near_key.public_key(),
        near_key,
        NOW - datetime.timedelta(days=320),
        NOW + datetime.timedelta(days=45),
    ),
    HERE / "citizen_portal_near_expiry.pem",
)

# ── Expired legacy service ────────────────────────────────────────────────────

expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_subject = _subject(
    "legacy-auth-service.internal",
    org="Legacy Infrastructure Team",
)
_save(
    _build_cert(
        expired_subject,
        expired_subject,
        expired_key.public_key(),
        expired_key,
        NOW - datetime.timedelta(days=395),
        NOW - datetime.timedelta(days=30),
    ),
    HERE / "legacy_auth_expired.pem",
)

# ── Weak key on old dev sandbox ─────────────────────────────────────────────────

weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
weak_subject = _subject(
    "dev-sandbox.internal",
    org="Legacy Infrastructure Team",
)
_save(
    _build_cert(
        weak_subject,
        weak_subject,
        weak_key.public_key(),
        weak_key,
        NOW,
        NOW + datetime.timedelta(days=365),
    ),
    HERE / "legacy_auth_weak.pem",
)

# ── Internal PKI root (self-signed CA) ────────────────────────────────────────

ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_subject = _subject(
    "Internal Services Root CA",
    org="Enterprise PKI Operations",
)
_save(
    _build_cert(
        ca_subject,
        ca_subject,
        ca_key.public_key(),
        ca_key,
        NOW,
        NOW + datetime.timedelta(days=3650),
        is_ca=True,
    ),
    HERE / "internal_pki_root_ca.pem",
)

print("\nAll demo certificate fixtures generated.")
