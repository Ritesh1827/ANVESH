# ECDAT Reachability Test Fixture

Deliberately designed test repository for Day 5 Reachability & Context validation.

## Ground-Truth Reachability Map

| File | Function | Crypto Call | Line (approx) | Expected Reachability |
|------|----------|-------------|---------------|----------------------|
| api_handler.py | `handle_login` | `RSA.generate(2048)` | ~43 | **REACHABLE** (entry point) |
| api_handler.py | `_internal_helper` | `hashlib.md5()` | ~53 | **REACHABLE** via handle_login → _internal_helper |
| api_handler.py | `handle_register` | `hashlib.sha256()` | ~62 | **REACHABLE** (entry point) |
| api_handler.py | `_dead_code_function` | `DES.new()` | ~73 | **UNREACHABLE** (dead code) |
| crypto_service.py | `sign_document` | `ec.generate_private_key()` | ~35 | **REACHABLE** via handle_payment → sign_document |
| crypto_service.py | `sign_document` | `hashlib.sha512()` | ~37 | **REACHABLE** via handle_payment → sign_document |
| crypto_service.py | `encrypt_payload` | `RSA.generate(4096)` | ~46 | **REACHABLE** via handle_payment → encrypt_payload |
| crypto_service.py | `_orphaned_hash` | `hashlib.sha1()` | ~55 | **UNREACHABLE** (orphaned) |
| payment_handler.py | `handle_payment` | `hashlib.sha256()` | ~37 | **REACHABLE** (entry point) |
| no_entry_points.py | `utility_hash` | `hashlib.md5()` | ~26 | **UNKNOWN** (no entry points in isolation) |
| no_entry_points.py | `gen_key` | `RSA.generate(2048)` | ~31 | **UNKNOWN** (no entry points in isolation) |

## Entry Points Detected

Entry points are detected via `@route(...)` decorators:
- `api_handler.handle_login`
- `api_handler.handle_register`
- `payment_handler.handle_payment`

## Call Graph

```
handle_login → _internal_helper → (crypto: MD5)
             → (crypto: RSA.generate)
handle_register → (crypto: SHA-256)
handle_payment → sign_document → (crypto: ECDSA, SHA-512)
               → encrypt_payload → (crypto: RSA-4096)
               → (crypto: SHA-256)
_dead_code_function → (crypto: DES)  ← unreachable
_orphaned_hash → (crypto: SHA-1)     ← unreachable
```

## Notes

- `no_entry_points.py` tests the "unknown" path — when tested in isolation
  (no other files with entry points), the engine correctly returns None.
- All Python files use the same `@route` decorator pattern
  (not a real framework — a minimal simulation).
