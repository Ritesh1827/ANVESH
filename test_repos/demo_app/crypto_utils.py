"""
Demo application — crypto_utils.py
Deliberately uses vulnerable cryptographic primitives for ECDAT test coverage.
Ground-truth expected detections are documented inline.

EXPECTED FINDINGS:
  R-001: RSA key generation (key_establishment) — line 17
  R-002: MD5 digest (hashing) — line 27
  R-003: SHA-1 digest (hashing) — line 33
  R-004: DES cipher (encryption) — line 40
  R-005: AES-128-ECB (encryption) — line 50  [ECB mode — weak]
  R-006: PKCS1v15 encryption with RSA (key_establishment) — line 60
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Hash import MD5, SHA1
from Crypto.Signature import pkcs1_15


# R-001: RSA key generation — 2048-bit
def generate_rsa_key():
    key = RSA.generate(2048)
    return key


# R-002: MD5 digest — broken hash, should not be used for security
def hash_password_md5(password: str) -> str:
    h = MD5.new()
    h.update(password.encode("utf-8"))
    return h.hexdigest()


# R-003: SHA-1 digest — deprecated for security use
def hash_data_sha1(data: bytes) -> str:
    h = SHA1.new()
    h.update(data)
    return h.hexdigest()


# R-004: DES encryption — 56-bit key, broken
def encrypt_des(plaintext: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plaintext)


# R-005: AES-128 in ECB mode — key size acceptable but ECB mode is insecure
def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)  # ECB mode — no IV, patterns leak
    return cipher.encrypt(plaintext)


# R-006: RSA PKCS1v15 encryption — vulnerable to Bleichenbacher attack
def encrypt_rsa_pkcs1v15(data: bytes, public_key) -> bytes:
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)
