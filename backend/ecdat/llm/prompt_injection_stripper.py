"""
Prompt-Injection Stripper — PRD §5 stage 3b, step 2.

PRD §5 stage 3b requirement (second step):
  "prompt-injection stripping"

Purpose:
  Code snippets being analysed by ECDAT may contain crafted strings
  designed to hijack the LLM's behaviour by inserting fake instructions.
  This module neutralises such patterns before the snippet is embedded
  in the LLM prompt.

  Common prompt-injection vectors in code snippets:
    - Strings containing "ignore previous instructions"
    - Strings containing role-change attempts ("you are now a ...")
    - Strings containing instruction delimiters ("[INST]", "###", "---")
    - Strings containing system-prompt override attempts

Strategy:
  1. Pattern-match known injection phrases and neutralise them by replacing
     with a safe marker that preserves snippet structure.
  2. Strip Unicode control characters that could manipulate rendering.
  3. Limit snippet length to prevent context-stuffing attacks.

Conservative approach: only strip what clearly looks like injection.
We must not damage legitimate code comments or strings that happen to
contain English phrases, so patterns are anchored to known attack forms.

Output: the stripped snippet is semantically equivalent to the original
for classification purposes — all crypto API calls are preserved.
"""

from __future__ import annotations

import re
import unicodedata
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Maximum snippet length sent to the LLM.
# Prevents context-stuffing and reduces token cost.
MAX_SNIPPET_LENGTH = 2048

# ── Injection pattern registry ────────────────────────────────────────────────
# Each entry: (description, compiled_regex)
# All matches are replaced with [STRIPPED].

_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Direct instruction override attempts
    ("ignore_instructions",
     re.compile(r"ignore\s+(previous|prior|above|all|your)\s+(instructions?|prompts?|context|rules?)",
                re.IGNORECASE)),
    ("forget_instructions",
     re.compile(r"forget\s+(everything|all|previous|prior|your)\s*(instructions?|context|rules?)?",
                re.IGNORECASE)),
    ("new_instructions",
     re.compile(r"new\s+instructions?\s*[:=]", re.IGNORECASE)),

    # Role-change attempts
    ("you_are_now",
     re.compile(r"you\s+are\s+now\s+(a|an|the)\s+\w+", re.IGNORECASE)),
    ("act_as",
     re.compile(r"act\s+as\s+(a|an|the)\s+\w+", re.IGNORECASE)),
    ("pretend_to_be",
     re.compile(r"pretend\s+to\s+be\s+(a|an|the)\s+\w+", re.IGNORECASE)),
    ("from_now_on",
     re.compile(r"from\s+now\s+on[,\s]+(you\s+(are|will)|your\s+role)", re.IGNORECASE)),

    # Prompt delimiter injection
    ("llama_inst_tag",
     re.compile(r"\[/?INST\]", re.IGNORECASE)),
    ("system_tag",
     re.compile(r"<\|?(system|user|assistant|im_start|im_end)\|?>", re.IGNORECASE)),
    ("triple_dash_separator",
     re.compile(r"^---+\s*$", re.MULTILINE)),
    ("triple_hash_separator",
     re.compile(r"^###\s*(SYSTEM|HUMAN|ASSISTANT|INSTRUCTION|CONTEXT)\s*$",
                re.MULTILINE | re.IGNORECASE)),

    # Direct system prompt override
    ("system_prompt_override",
     re.compile(r"system\s+prompt\s*[:=]", re.IGNORECASE)),
    ("override_prompt",
     re.compile(r"(override|replace|change|update)\s+(the\s+)?(system\s+)?prompt",
                re.IGNORECASE)),

    # Jailbreak patterns
    ("jailbreak_dan",
     re.compile(r"\bDAN\b.*?(mode|enabled?|activated?)", re.IGNORECASE)),
    ("disregard_rules",
     re.compile(r"disregard\s+(your\s+)?(rules?|guidelines?|safety|constraints?|policies?)",
                re.IGNORECASE)),
]

# Unicode categories that are pure control characters (not printable)
_CONTROL_CATEGORIES = {"Cc", "Cf", "Cs"}
# Allowlist: keep tab (\t), newline (\n), carriage return (\r)
_ALLOWED_CONTROL = {"\t", "\n", "\r"}


def _strip_unicode_controls(text: str) -> str:
    """Remove Unicode control/format characters that could manipulate rendering."""
    result = []
    for ch in text:
        if ch in _ALLOWED_CONTROL:
            result.append(ch)
        elif unicodedata.category(ch) in _CONTROL_CATEGORIES:
            continue   # drop invisible control character
        else:
            result.append(ch)
    return "".join(result)


@dataclass
class StripResult:
    """Result of prompt-injection stripping."""
    original: str
    stripped: str
    injections_found: list[str]    # descriptions of patterns that fired
    was_truncated: bool

    @property
    def was_modified(self) -> bool:
        return self.original != self.stripped or self.was_truncated


def strip_prompt_injection(snippet: str) -> StripResult:
    """
    Strip prompt-injection patterns from a code snippet.

    This is the second step of the LLM enrichment pipeline (PRD §5 stage 3b).
    Runs after secret scrubbing, before cache lookup and LLM call.

    Returns a StripResult with the neutralised snippet.
    Injection patterns are replaced with [STRIPPED] to preserve structure.
    """
    text = snippet
    injections_found: list[str] = []

    # Step 1: Strip Unicode control characters
    text = _strip_unicode_controls(text)

    # Step 2: Apply injection pattern neutralisation
    for description, pattern in _INJECTION_PATTERNS:
        new_text = pattern.sub("[STRIPPED]", text)
        if new_text != text:
            injections_found.append(description)
            text = new_text

    # Step 3: Truncate to prevent context-stuffing
    was_truncated = len(text) > MAX_SNIPPET_LENGTH
    if was_truncated:
        text = text[:MAX_SNIPPET_LENGTH] + "\n# [truncated by ECDAT security filter]"
        logger.warning(
            "Snippet truncated from %d to %d chars (context-stuffing prevention)",
            len(snippet), MAX_SNIPPET_LENGTH,
        )

    if injections_found:
        logger.warning(
            "Prompt-injection patterns stripped from snippet: %s",
            ", ".join(injections_found),
        )

    return StripResult(
        original=snippet,
        stripped=text,
        injections_found=injections_found,
        was_truncated=was_truncated,
    )
