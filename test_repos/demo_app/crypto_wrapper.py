"""
Demo application — crypto_wrapper.py

Deliberately ambiguous cryptographic usage for ECDAT Day 7 LLM enrichment testing.

This file contains INDIRECT crypto calls — wrapper functions whose call sites
don't directly invoke a named crypto API (so the deterministic tree-sitter rules
don't match them), but whose implementation uses crypto internally.

The call to `_compute_digest` from `process_user_data` is the canonical ambiguous
case: the discovery engine sees a call to an unknown function and produces an asset
with purpose=UNKNOWN. This is what triggers LLM enrichment.

GROUND TRUTH:
  _compute_digest(data) → purpose should be classified as "hashing"
  _derive_session_secret(password) → purpose should be classified as "key_derivation"

These are NOT direct hashlib/Crypto calls at the call site, so the deterministic
rules produce UNKNOWN purpose — correctly triggering LLM enrichment.
"""

import hashlib
import os
import hmac


# ── Ambiguous wrapper 1: indirect hash call ──────────────────────────────────
# The call site is `_compute_digest(data)` — the discovery engine sees this
# as an unknown function call and cannot determine the purpose without
# understanding the function body.

def _compute_digest(data: bytes) -> str:
    """
    Internal digest function.
    Wraps hashlib.sha256 — purpose is hashing, but not obvious at call site.
    """
    return hashlib.sha256(data).hexdigest()


def process_user_data(user_id: str, payload: bytes) -> dict:
    """
    Process user data — calls _compute_digest indirectly.
    From the call site alone, ECDAT's deterministic rules cannot determine
    that _compute_digest involves hashing.
    """
    digest = _compute_digest(payload)
    return {"user_id": user_id, "digest": digest}


# ── Ambiguous wrapper 2: key derivation ──────────────────────────────────────

def _derive_session_secret(password: str, salt: bytes = b"ecdat-salt") -> bytes:
    """
    Derive a session secret from a password.
    Uses PBKDF2-HMAC-SHA256 — purpose is key_derivation, but indirect.
    """
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)


def authenticate_user(username: str, password: str) -> bytes:
    """
    Authenticate user — calls _derive_session_secret.
    From the call site alone, the purpose is ambiguous.
    """
    secret = _derive_session_secret(password)
    return secret
