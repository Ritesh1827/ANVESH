"""
Demo application — auth_service.py
Authentication service with cryptographic usage for ECDAT test coverage.

EXPECTED FINDINGS:
  R-001: RSA.generate(2048) — key_establishment — line 29
  R-007: hashlib.md5 — hashing — line 38
  R-008: hashlib.sha256 — hashing — line 44  [safe, but still inventoried]
  R-009: ssl.PROTOCOL_TLSv1 — infrastructure/TLS — line 54
  R-010: Fernet (AES-128-CBC) — encryption — line 63
"""

import hashlib
import ssl
import hmac
import os
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet


# R-001: RSA session key generation at line 29
def create_session_key():
    """Generate RSA-2048 session key for TLS termination."""
    private_key = RSA.generate(2048)
    return private_key


# R-007: hashlib.md5 — should not be used for passwords
def legacy_password_hash(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# R-008: hashlib.sha256 — acceptable but still tracked
def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# R-009: Explicit TLS version pinning — TLS 1.0 is deprecated
def create_legacy_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1   # deprecated TLS version
    return ctx


# R-010: Fernet symmetric encryption (wraps AES-128-CBC + HMAC-SHA256)
def encrypt_user_data(data: bytes) -> tuple[bytes, bytes]:
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(data)
    return token, key
