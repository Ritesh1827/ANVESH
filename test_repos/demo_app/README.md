# ECDAT Demo Application — Controlled Test Repository

This is a **deliberately vulnerable** test fixture for ECDAT pipeline validation.
It is NOT real application code. Every cryptographic primitive here is intentional
and documented with its expected detection rule ID.

## Ground-Truth Detection Map

| File | Line | Rule ID | Algorithm | Purpose |
|------|------|---------|-----------|---------|
| crypto_utils.py | 17 | R-001 | RSA-2048 | key_establishment |
| crypto_utils.py | 27 | R-002 | MD5 | hashing |
| crypto_utils.py | 33 | R-003 | SHA-1 | hashing |
| crypto_utils.py | 40 | R-004 | DES | encryption |
| crypto_utils.py | 50 | R-005 | AES-128-ECB | encryption |
| auth_service.py | 29 | R-001 | RSA-2048 | key_establishment |
| auth_service.py | 38 | R-007 | MD5 | hashing |
| auth_service.py | 44 | R-008 | SHA-256 | hashing |
| auth_service.py | 63 | R-010 | AES-128-CBC (Fernet) | encryption |
| payment_service.py | 22 | R-011 | ECDSA-P256 | digital_signature |
| payment_service.py | 34 | R-012 | RSA-4096 | key_establishment |
| payment_service.py | 44 | R-013 | HMAC-SHA256 | mac |
| payment_service.py | 51 | R-014 | SHA-512 | hashing |
| tls_client.py | 28 | R-016 | RC4 | encryption |
| tls_client.py | 38 | R-017 | SHA-1 | hashing |

## False Positive Guard

These patterns exist in the repo but must NOT be detected as crypto API calls:
- `config.py:30` — "RSA" in a Python comment
- `config.py:33` — `LOG_ALGORITHM_LABEL = "sha256_audit_log"` — label string, not a call
