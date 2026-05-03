"""Key generation utilities.

Generates symmetric and asymmetric keys with configurable sizes.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

VALID_AES_SIZES = {128, 192, 256}
VALID_RSA_SIZES = {2048, 3072, 4096}
VALID_ECDSA_CURVES = {"P-256", "P-384", "P-521"}

_CURVE_MAP = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


def _deterministic_bytes(seed: str, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        chunk = hashlib.sha256(f"{seed}:{counter}".encode("utf-8")).digest()
        out.extend(chunk)
        counter += 1
    return bytes(out[:length])


def generate_symmetric_key(bit_length: int = 256, seed: str | None = None) -> bytes:
    """Generate a symmetric key for AES-GCM or ChaCha20-Poly1305.

    Args:
        bit_length: 128, 192, or 256 (ChaCha20 only supports 256)
        seed: optional deterministic seed (for reproducible test keys)
    """
    if bit_length not in VALID_AES_SIZES:
        raise ValueError(f"Key size must be 128, 192, or 256 bits, got {bit_length}")
    byte_len = bit_length // 8
    if seed:
        return _deterministic_bytes(seed, byte_len)
    return os.urandom(byte_len)


def generate_rsa_keypair(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate RSA private + public PEM pair.

    Returns:
        (private_pem, public_pem)
    """
    if key_size not in VALID_RSA_SIZES:
        raise ValueError(f"RSA key size must be one of {VALID_RSA_SIZES}, got {key_size}")
    private = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def generate_ecdsa_keypair(curve: str = "P-256") -> tuple[bytes, bytes]:
    """Generate ECDSA private + public PEM pair.

    Args:
        curve: "P-256", "P-384", or "P-521"

    Returns:
        (private_pem, public_pem)
    """
    if curve not in VALID_ECDSA_CURVES:
        raise ValueError(f"ECDSA curve must be one of {VALID_ECDSA_CURVES}, got {curve}")
    private = ec.generate_private_key(_CURVE_MAP[curve])
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem
