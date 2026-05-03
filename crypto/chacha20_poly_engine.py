"""ChaCha20-Poly1305 authenticated encryption engine.

Fixed 256-bit (32-byte) key. Protocol standard.
Output format: nonce (12 bytes) | ciphertext | Poly1305-tag (16 bytes)
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_SIZE = 12
KEY_SIZE_BITS = 256
KEY_SIZE_BYTES = 32


def name() -> str:
    return "ChaCha20-Poly1305"


def supported_key_sizes() -> list[int]:
    return [256]


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE_BYTES)


def encrypt(data: bytes, key: bytes, aad: bytes | None = None) -> bytes:
    """Encrypt data with ChaCha20-Poly1305. Returns nonce + ciphertext + tag."""
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"ChaCha20-Poly1305 key must be 256 bits (32 bytes), got {len(key) * 8} bits")
    nonce = os.urandom(NONCE_SIZE)
    chacha = ChaCha20Poly1305(key)
    ciphertext_with_tag = chacha.encrypt(nonce, data, aad)
    return nonce + ciphertext_with_tag


def decrypt(data: bytes, key: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt ChaCha20-Poly1305 ciphertext. Raises InvalidTag if tampered."""
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"ChaCha20-Poly1305 key must be 256 bits (32 bytes), got {len(key) * 8} bits")
    if len(data) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short for ChaCha20-Poly1305")
    nonce = data[:NONCE_SIZE]
    ciphertext_with_tag = data[NONCE_SIZE:]
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext_with_tag, aad)
