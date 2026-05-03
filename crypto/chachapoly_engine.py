from __future__ import annotations

import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except Exception:
    ChaCha20Poly1305 = None


NONCE_SIZE = 12
KEY_SIZE = 32


def is_available() -> bool:
    return ChaCha20Poly1305 is not None


def _ensure_available() -> None:
    if not is_available():
        raise RuntimeError(
            "ChaCha20-Poly1305 backend is unavailable in this environment"
        )


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def encrypt(data: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    _ensure_available()
    if len(key) != KEY_SIZE:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    nonce = os.urandom(NONCE_SIZE)
    cipher = ChaCha20Poly1305(key)
    ciphertext_and_tag = cipher.encrypt(nonce, data, associated_data)
    return nonce + ciphertext_and_tag


def decrypt(payload: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    _ensure_available()
    if len(key) != KEY_SIZE:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    if len(payload) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce = payload[:NONCE_SIZE]
    ciphertext_and_tag = payload[NONCE_SIZE:]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext_and_tag, associated_data)
