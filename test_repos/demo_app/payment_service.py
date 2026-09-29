"""
Demo application — payment_service.py
Payment processing with cryptographic usage for ECDAT test coverage.

EXPECTED FINDINGS:
  R-011: ECDSA signing with P-256 — digital_signature — line 22
  R-012: RSA-4096 key (stronger but still quantum-vulnerable) — line 34
  R-013: HMAC-SHA256 — mac — line 44
  R-014: hashlib.sha512 — hashing — line 51 [safe classical, still inventoried]
"""

import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes


# R-011: ECDSA with NIST P-256 — digital_signature
def sign_transaction(transaction_data: bytes):
    """Sign payment transaction with ECDSA P-256."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(transaction_data, ec.ECDSA(hashes.SHA256()))
    return signature, private_key.public_key()


# R-012: RSA-4096 for certificate signing — still quantum-vulnerable
def generate_payment_cert_key():
    """Generate RSA-4096 key for payment processor certificate."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    return key


# R-013: HMAC-SHA256 for API request signing — mac purpose
def sign_api_request(payload: bytes, secret: bytes) -> bytes:
    """HMAC-SHA256 for payment gateway API authentication."""
    return hmac.new(secret, payload, hashlib.sha256).digest()


# R-014: SHA-512 for transaction log integrity
def transaction_hash(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()
