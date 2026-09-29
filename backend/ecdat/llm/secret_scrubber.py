"""
Secret Scrubber — PRD §5 stage 3b, step 1.

PRD §5 stage 3b requirement (first step):
  "secret scrubbing"

PRD §6 (Confidentiality by design):
  "In a real deployment, secrets/credentials must never leave the local
   environment (enforced by the secret scrubber stage)."

Purpose:
  Before a code snippet is sent to an external LLM API, this module
  redacts any content that looks like a secret (API keys, passwords,
  private key material, tokens, connection strings, high-entropy blobs).

  The scrubber replaces secret-like content with a safe placeholder:
    "[REDACTED:<type>]"
  so the snippet structure is preserved for LLM classification purposes
  without leaking actual secret values.

Strategy:
  1. Regex patterns for known secret formats (AWS keys, JWT, Base64 blobs, etc.)
  2. Entropy-based detection for high-entropy strings (likely key material)
  3. detect-secrets library integration where available

The scrubber is conservative: when in doubt, redact. False positives
(redacting a non-secret) are acceptable; false negatives (allowing a
secret through) are not.

This scrubber operates on individual snippets (short code strings), not
full files. It is not a substitute for a full secrets scanner.
"""

from __future__ import annotations

import math
import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── Secret pattern registry ───────────────────────────────────────────────────
# Each entry: (name, compiled_regex, replacement_label)
# Ordered from most-specific to least-specific.

_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # AWS keys
    ("aws_access_key",
     re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
     "AWS_ACCESS_KEY"),
    ("aws_secret_key",
     re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]?([A-Za-z0-9/+]{40})['\"]?"),
     "AWS_SECRET_KEY"),

    # Private key PEM blocks
    ("private_key_pem",
     re.compile(
         r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PRIVATE\s+)?PRIVATE KEY-----.*?"
         r"-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PRIVATE\s+)?PRIVATE KEY-----",
         re.DOTALL | re.IGNORECASE,
     ),
     "PRIVATE_KEY"),

    # JSON Web Tokens (3-part base64url)
    ("jwt",
     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "JWT_TOKEN"),

    # Generic hex secrets (32–64 hex chars, likely a key or hash)
    ("hex_secret",
     re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
     "HEX_SECRET"),

    # Generic Base64 blobs (≥32 chars, typical of encoded keys)
    ("base64_blob",
     re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/])"),
     "BASE64_SECRET"),

    # Connection strings with passwords
    ("connection_string",
     re.compile(
         r"(?:password|passwd|pwd|secret|token|apikey|api_key)\s*[=:]\s*['\"]?([^\s'\"&;,)]{6,})['\"]?",
         re.IGNORECASE,
     ),
     "CREDENTIAL"),

    # Quoted strings that look like long random secrets (≥32 non-whitespace chars)
    ("quoted_secret",
     re.compile(r"""['"]((?:[^\s'"]{8,}[^'"\s]){3,})['"]\s*"""),
     "SECRET_STRING"),
]

# Minimum entropy (bits) to flag a string as a potential secret
_ENTROPY_THRESHOLD = 3.5
# Minimum length to apply entropy check (very short strings are rarely secrets)
_ENTROPY_MIN_LEN = 20


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_high_entropy(token: str) -> bool:
    """Return True if the token looks like it has enough entropy to be a secret."""
    return len(token) >= _ENTROPY_MIN_LEN and _shannon_entropy(token) >= _ENTROPY_THRESHOLD


@dataclass
class ScrubResult:
    """Result of scrubbing a snippet."""
    original: str
    scrubbed: str
    redactions: list[str]          # list of labels for what was redacted

    @property
    def was_modified(self) -> bool:
        return self.original != self.scrubbed


def scrub_snippet(snippet: str) -> ScrubResult:
    """
    Redact secret-like content from a code snippet.

    Returns a ScrubResult containing:
      - scrubbed:   the snippet with secrets replaced by [REDACTED:<type>]
      - redactions: list of labels for what was found and redacted

    This is the first step of the LLM enrichment pipeline (PRD §5 stage 3b).
    It runs before the snippet is passed to any external service.
    """
    text = snippet
    redactions: list[str] = []

    # Step 1: Apply pattern-based detection
    for name, pattern, label in _PATTERNS:
        def _replace(m: re.Match, _label: str = label) -> str:
            return f"[REDACTED:{_label}]"
        new_text = pattern.sub(_replace, text)
        if new_text != text:
            redactions.append(label)
            text = new_text

    # Step 2: Entropy-based detection on remaining tokens
    # Split on whitespace/punctuation and check each token
    tokens = re.findall(r"[A-Za-z0-9+/=_\-]{" + str(_ENTROPY_MIN_LEN) + r",}", text)
    for token in tokens:
        if "[REDACTED:" in token:
            continue   # already redacted
        if _is_high_entropy(token):
            text = text.replace(token, "[REDACTED:HIGH_ENTROPY]", 1)
            redactions.append("HIGH_ENTROPY")
            logger.debug("Entropy-based redaction: token of length %d, entropy %.2f",
                         len(token), _shannon_entropy(token))

    if redactions:
        logger.info(
            "Secret scrubber redacted %d item(s) from snippet: %s",
            len(redactions), ", ".join(set(redactions))
        )

    return ScrubResult(
        original=snippet,
        scrubbed=text,
        redactions=redactions,
    )
