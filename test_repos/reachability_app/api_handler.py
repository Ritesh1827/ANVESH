"""
Reachability fixture — api_handler.py

This file has explicit HTTP entry points (decorated functions).
Crypto calls reachable from entry points should be detected as REACHABLE.

GROUND TRUTH — reachability:
  handle_login()        → IS an entry point (@app.route decorator)
  handle_register()     → IS an entry point (@app.route decorator)
  _internal_helper()    → NOT an entry point, but CALLED by handle_login
                          → reachable via: handle_login → _internal_helper
  _dead_code_function() → NOT an entry point, NOT called by anything
                          → UNREACHABLE (dead code)

GROUND TRUTH — crypto assets expected:
  RSA.generate(2048) in handle_login()       → REACHABLE  (entry point itself)
  hashlib.md5() in _internal_helper()        → REACHABLE  (called from handle_login)
  hashlib.sha256() in handle_register()      → REACHABLE  (entry point itself)
  DES.new() in _dead_code_function()         → UNREACHABLE (dead code path)
"""

import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES


# Simulated route decorator (real apps use Flask/FastAPI)
def route(path, methods=None):
    """Decorator marking a function as an HTTP route handler."""
    def decorator(func):
        func._is_route = True
        func._route_path = path
        return func
    return decorator


app_routes = {}


@route("/api/auth/login", methods=["POST"])
def handle_login(username: str, password: str) -> dict:
    """
    Login endpoint — entry point.
    Calls _internal_helper() which uses MD5.
    Uses RSA key generation.
    """
    # RSA key generation — REACHABLE (this IS the entry point)
    session_key = RSA.generate(2048)
    token = _internal_helper(password)
    return {"token": token, "key_id": session_key.n}


def _internal_helper(data: str) -> str:
    """
    Internal helper — NOT an entry point, but called by handle_login.
    MD5 here is REACHABLE via: handle_login → _internal_helper.
    """
    # MD5 — REACHABLE via handle_login → _internal_helper
    return hashlib.md5(data.encode()).hexdigest()


@route("/api/auth/register", methods=["POST"])
def handle_register(username: str, password: str) -> dict:
    """
    Register endpoint — entry point.
    SHA-256 here is REACHABLE (this IS the entry point).
    """
    # SHA-256 — REACHABLE (this is the entry point itself)
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return {"status": "ok", "hash": hashed}


def _dead_code_function(data: bytes, key: bytes) -> bytes:
    """
    Dead code — NOT reachable from any entry point.
    DES encryption here is UNREACHABLE.
    Nothing in this file calls this function.
    """
    # DES — UNREACHABLE (dead code, no caller)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
