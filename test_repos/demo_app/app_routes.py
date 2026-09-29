"""
Demo application — app_routes.py

HTTP-style entry points for the ECDAT demo application.

These route-decorated functions give the call-graph engine genuine entry
points so the ReachabilityEngine can trace paths from HTTP handlers to the
cryptographic operations in auth_service.py and payment_service.py.

Without this file the demo_app has no decorated entry points, so all
crypto calls appear as UNREACHABLE even though they are actively used in
a live web application context.

REACHABILITY GROUND TRUTH (via @route decorators):

  handle_auth_login()     → entry point
    → auth_service.create_session_key()        RSA-2048  REACHABLE (P1, HNDL)
    → auth_service.legacy_password_hash()      MD5       REACHABLE (P1)

  handle_auth_register()  → entry point
    → auth_service.token_hash()                SHA-256   REACHABLE (P4 — safe)
    → auth_service.encrypt_user_data()         AES-128   REACHABLE (P3)

  handle_process_payment() → entry point
    → payment_service.sign_transaction()       ECDSA-P256 REACHABLE (P1, HNDL)
    → payment_service.generate_payment_cert_key() RSA-4096 REACHABLE (P1, HNDL)
    → payment_service.sign_api_request()       HMAC       REACHABLE (P4)
    → payment_service.transaction_hash()       SHA-512    REACHABLE (P4 — safe)

Intentionally NOT connected to entry points (remain UNREACHABLE):
    crypto_utils.py functions        — legacy/utility code, never called by routes
    tls_client.py functions          — infrastructure layer not invoked from app routes
    auth_service.create_legacy_ssl_context() — deprecated TLS config path

This gives the dashboard a realistic and honest mix:
    - Multiple reachable P1 findings (RSA-2048, ECDSA-P256, RSA-4096 from routes)
    - Reachable P1 with HNDL (RSA-2048 in login handler, ECDSA and RSA-4096 in payment)
    - Unreachable P1 findings (DES, SHA-1 in crypto_utils — dead code paths)
    - Infrastructure assets (TLS-1.0, TLS-legacy) correctly UNREACHABLE from app routes
"""

from auth_service import (
    create_session_key,
    legacy_password_hash,
    token_hash,
    encrypt_user_data,
)
from payment_service import (
    sign_transaction,
    generate_payment_cert_key,
    sign_api_request,
    transaction_hash,
)


def route(path, methods=None):
    """Minimal route decorator — mirrors the pattern used in reachability_app."""
    def decorator(func):
        func._is_route = True
        func._route_path = path
        return func
    return decorator


@route("/api/auth/login", methods=["POST"])
def handle_auth_login(username: str, password: str) -> dict:
    """
    User login endpoint.
    Reachable: RSA-2048 session key generation + MD5 legacy password hash.
    RSA-2048 and MD5 will both show as REACHABLE P1 in the dashboard.
    """
    session_key = create_session_key()          # RSA-2048 — P1, HNDL
    token = legacy_password_hash(password)       # MD5      — P1
    return {"session_key_id": str(session_key.n)[:16], "token": token}


@route("/api/auth/register", methods=["POST"])
def handle_auth_register(username: str, password: str) -> dict:
    """
    User registration endpoint.
    Reachable: SHA-256 token hashing + AES-128-CBC encryption.
    """
    hashed = token_hash(password)                # SHA-256 — P4 (safe)
    encrypted, key = encrypt_user_data(password.encode())  # AES-128-CBC — P3
    return {"status": "ok", "hash": hashed}


@route("/api/payments/process", methods=["POST"])
def handle_process_payment(amount: float, payload: bytes) -> dict:
    """
    Payment processing endpoint.
    Reachable: ECDSA-P256 signing + RSA-4096 key + HMAC-SHA256 + SHA-512.
    ECDSA-P256 and RSA-4096 will both show REACHABLE P1 in the dashboard.
    """
    signature, pubkey = sign_transaction(payload)           # ECDSA-P256 — P1, HNDL
    cert_key = generate_payment_cert_key()                  # RSA-4096  — P1, HNDL
    mac = sign_api_request(payload, b"demo-secret")         # HMAC      — P4
    digest = transaction_hash(payload)                       # SHA-512   — P4 (safe)
    return {
        "amount": amount,
        "digest": digest,
        "mac_len": len(mac),
    }
