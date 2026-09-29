"""
Demo application — tls_client.py
TLS/SSL client usage for ECDAT test coverage.

EXPECTED FINDINGS:
  R-016: ssl.wrap_socket with SSLv3 (broken) — infrastructure — line 28
  R-017: OpenSSL EVP_MD_CTX_new / SHA1 via ctypes — hashing — line 38
"""

import ssl
import socket


# R-016: Deprecated ssl.wrap_socket with explicit old protocol
def connect_legacy(host: str, port: int):
    """Legacy TLS connection — uses deprecated API."""
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ssl.PROTOCOL_SSLv3 is broken; PROTOCOL_TLS_CLIENT is the modern equivalent
    wrapped = ssl.wrap_socket(
        raw_sock,
        ssl_version=ssl.PROTOCOL_TLS,
        ciphers="RC4-SHA",
    )
    wrapped.connect((host, port))
    return wrapped


# R-017: Direct SHA-1 usage via hashlib (should be detected by hashlib rule)
import hashlib

def compute_cert_fingerprint(cert_der: bytes) -> str:
    """Compute SHA-1 fingerprint of a DER-encoded certificate."""
    return hashlib.sha1(cert_der).hexdigest()
