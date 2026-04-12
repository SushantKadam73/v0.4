from __future__ import annotations

import os

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except Exception:
    Cipher = None
    algorithms = None


NONCE_SIZE = 16
KEY_SIZE = 32


def is_available() -> bool:
    return Cipher is not None and algorithms is not None


def _ensure_available() -> None:
    if not is_available():
        raise RuntimeError("ChaCha20 backend is unavailable in this environment")


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def encrypt(data: bytes, key: bytes) -> bytes:
    _ensure_available()
    if len(key) != KEY_SIZE:
        raise ValueError("ChaCha20 key must be 32 bytes")

    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data)
    return nonce + ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
    _ensure_available()
    if len(key) != KEY_SIZE:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(data) < NONCE_SIZE:
        raise ValueError("Ciphertext too short")

    nonce = data[:NONCE_SIZE]
    body = data[NONCE_SIZE:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(body)
