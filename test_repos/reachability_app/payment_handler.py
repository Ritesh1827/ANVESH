"""
Reachability fixture — payment_handler.py

Entry point that calls into crypto_service.py — tests cross-file reachability.

GROUND TRUTH:
  handle_payment() → IS an entry point (@route decorator)
  handle_payment() → calls sign_document() in crypto_service.py
  handle_payment() → calls encrypt_payload() in crypto_service.py

  So all crypto in sign_document() and encrypt_payload() is reachable
  via the cross-file call path: handle_payment → sign_document / encrypt_payload

CRYPTO ASSETS:
  hashlib.sha256() in handle_payment()  → REACHABLE (entry point itself)
"""

import hashlib
from crypto_service import sign_document, encrypt_payload


def route(path, methods=None):
    def decorator(func):
        func._is_route = True
        return func
    return decorator


@route("/api/payments/process", methods=["POST"])
def handle_payment(amount: float, payload: bytes) -> dict:
    """
    Payment processing endpoint — entry point.
    Calls crypto_service.sign_document and crypto_service.encrypt_payload.
    """
    # SHA-256 — REACHABLE (this is the entry point)
    payload_hash = hashlib.sha256(payload).hexdigest()
    signature, digest = sign_document(payload)
    encrypted = encrypt_payload(payload)
    return {
        "hash": payload_hash,
        "digest": digest,
        "encrypted_len": len(encrypted),
    }
