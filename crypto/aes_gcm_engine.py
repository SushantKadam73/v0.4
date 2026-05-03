"""AES-GCM authenticated encryption engine.

Supports 128, 192, and 256-bit keys.
Output format: nonce (12 bytes) | ciphertext | GCM-tag (16 bytes)
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
VALID_KEY_SIZES = {128, 192, 256}


def name() -> str:
    return "AES-GCM"


def supported_key_sizes() -> list[int]:
    return [128, 192, 256]


def generate_key(bit_length: int = 256) -> bytes:
    if bit_length not in VALID_KEY_SIZES:
        raise ValueError(f"AES-GCM key must be 128, 192, or 256 bits, got {bit_length}")
    return os.urandom(bit_length // 8)


def encrypt(data: bytes, key: bytes, aad: bytes | None = None) -> bytes:
    """Encrypt data with AES-GCM. Returns nonce + ciphertext + tag."""
    key_bits = len(key) * 8
    if key_bits not in VALID_KEY_SIZES:
        raise ValueError(f"AES-GCM key must be 128, 192, or 256 bits, got {key_bits}")
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, aad)
    return nonce + ciphertext_with_tag


def decrypt(data: bytes, key: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt AES-GCM ciphertext. Raises InvalidTag if tampered."""
    key_bits = len(key) * 8
    if key_bits not in VALID_KEY_SIZES:
        raise ValueError(f"AES-GCM key must be 128, 192, or 256 bits, got {key_bits}")
    if len(data) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short for AES-GCM")
    nonce = data[:NONCE_SIZE]
    ciphertext_with_tag = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
