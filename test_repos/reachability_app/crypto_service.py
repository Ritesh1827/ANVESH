"""
Reachability fixture — crypto_service.py

This file is called from api_handler.py to test cross-file reachability.
It also contains functions called from main() to test deep call chains.

GROUND TRUTH — reachability:
  sign_document()   → called by handle_payment() in payment_handler.py
                      → REACHABLE via: handle_payment → sign_document
  encrypt_payload() → called by handle_payment() in payment_handler.py
                      → REACHABLE via: handle_payment → encrypt_payload
  _orphaned_hash()  → NOT called from anywhere → UNREACHABLE

CRYPTO ASSETS:
  ec.generate_private_key() in sign_document()   → REACHABLE
  hashlib.sha512() in sign_document()            → REACHABLE
  RSA.generate(4096) in encrypt_payload()        → REACHABLE
  hashlib.sha1() in _orphaned_hash()             → UNREACHABLE
"""

import hashlib
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


def sign_document(document: bytes) -> tuple:
    """
    Sign a document with ECDSA. Called by handle_payment in payment_handler.py.
    REACHABLE via: handle_payment → sign_document.
    """
    # ECDSA key generation — REACHABLE
    private_key = ec.generate_private_key(ec.SECP256R1())
    # SHA-512 digest — REACHABLE
    digest = hashlib.sha512(document).hexdigest()
    return private_key, digest


def encrypt_payload(data: bytes) -> bytes:
    """
    Encrypt a payload with RSA-4096. Called by handle_payment.
    REACHABLE via: handle_payment → encrypt_payload.
    """
    # RSA-4096 — REACHABLE
    key = RSA.generate(4096)
    return key.export_key()


def _orphaned_hash(data: bytes) -> str:
    """
    Hash function — NOT called from anywhere in this fixture.
    UNREACHABLE.
    """
    # SHA-1 — UNREACHABLE (orphaned function)
    return hashlib.sha1(data).hexdigest()
