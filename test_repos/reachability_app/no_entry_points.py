"""
Reachability fixture — no_entry_points.py

This file contains crypto usage but NO decorated entry points and NO
functions named main/handle/process/etc. It is used to test the
"unknown reachability" path — the engine cannot determine reachability
without any entry points in the graph.

GROUND TRUTH:
  All crypto here → reachability = None (UNKNOWN)
  Reason: no entry points registered from this file.

NOTE: This file is tested in ISOLATION (only this file passed to the engine).
When tested as part of the full reachability_app, other files may provide
entry points that can reach these functions if they are called from there.

CRYPTO ASSETS:
  hashlib.md5() in utility_hash()   → UNKNOWN when tested in isolation
  RSA.generate(2048) in gen_key()   → UNKNOWN when tested in isolation
"""

import hashlib
from Crypto.PublicKey import RSA


def utility_hash(data: str) -> str:
    """Utility function — no entry point in this file."""
    # MD5 — UNKNOWN reachability when tested in isolation
    return hashlib.md5(data.encode()).hexdigest()


def gen_key() -> object:
    """Key generation — no entry point in this file."""
    # RSA-2048 — UNKNOWN reachability when tested in isolation
    return RSA.generate(2048)
