"""
Demo application — config.py
Configuration with some crypto-adjacent patterns and one ambiguous usage.

EXPECTED FINDINGS:
  R-015: RC4 string reference — encryption — line 20 [RC4 broken]
  (ambiguous: algorithm name in a config string, not a direct API call)

NOT a finding (should NOT be detected):
  - The comment on line 30 mentions "RSA" — should not match (comment, not code)
  - The string "sha256" in a logging label — not a crypto API call
"""

# Legacy cipher suite string — RC4 reference in configuration
LEGACY_CIPHER_SUITE = "TLS_RSA_WITH_RC4_128_SHA"

# TLS configuration — explicit protocol pinning
TLS_CONFIG = {
    "min_protocol": "TLSv1.2",
    "preferred_ciphers": "ECDHE-RSA-AES256-GCM-SHA384",
    "legacy_cipher": "RC4-SHA",     # RC4 reference — should be flagged
}

# This is just a logging label — NOT a crypto detection
LOG_ALGORITHM_LABEL = "sha256_audit_log"

# RSA in a comment — must NOT be flagged as a detection
# The system uses RSA certificates from our CA

# A safe algorithm reference in data (not a call)
HASH_ALGORITHM_NAME = "sha256"
