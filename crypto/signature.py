"""Standalone digital signature module.

Supports RSA (PKCS1v15 + SHA-256) and ECDSA (P-256, P-384, P-521 + SHA-256).
Decoupled from hybrid engine — any algorithm can optionally sign its output.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

VALID_RSA_KEY_SIZES = {2048, 3072, 4096}
VALID_ECDSA_CURVES = {"P-256", "P-384", "P-521"}

_CURVE_MAP = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


@dataclass
class KeyPair:
    private_pem: bytes
    public_pem: bytes
    algorithm: str
    key_param: str  # key size (RSA) or curve name (ECDSA)


def generate_keypair(algorithm: str, key_param: str | int) -> KeyPair:
    """Generate an RSA or ECDSA keypair.

    Args:
        algorithm: "RSA" or "ECDSA"
        key_param: RSA key size in bits (2048/3072/4096) or ECDSA curve name ("P-256"/"P-384"/"P-521")
    """
    if algorithm == "RSA":
        key_size = int(key_param)
        if key_size not in VALID_RSA_KEY_SIZES:
            raise ValueError(f"RSA key size must be one of {VALID_RSA_KEY_SIZES}, got {key_size}")
        private = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        param_str = str(key_size)
    elif algorithm == "ECDSA":
        curve_name = str(key_param)
        if curve_name not in VALID_ECDSA_CURVES:
            raise ValueError(f"ECDSA curve must be one of {VALID_ECDSA_CURVES}, got {curve_name}")
        private = ec.generate_private_key(_CURVE_MAP[curve_name])
        param_str = curve_name
    else:
        raise ValueError(f"Unsupported signature algorithm: {algorithm}. Use 'RSA' or 'ECDSA'.")

    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyPair(private_pem=private_pem, public_pem=public_pem, algorithm=algorithm, key_param=param_str)


def sign(data: bytes, private_pem: bytes, algorithm: str) -> bytes:
    """Sign data (SHA-256 digest) with the given private key."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if algorithm == "RSA":
        return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif algorithm == "ECDSA":
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported signature algorithm: {algorithm}")


def verify(data: bytes, signature: bytes, public_pem: bytes, algorithm: str) -> bool:
    """Verify a signature. Returns True if valid, False otherwise."""
    public_key = serialization.load_pem_public_key(public_pem)
    try:
        if algorithm == "RSA":
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == "ECDSA":
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        return True
    except InvalidSignature:
        return False


def signature_key_size_bits(algorithm: str, key_param: str | int) -> int:
    """Return the effective key size in bits for display."""
    if algorithm == "RSA":
        return int(key_param)
    curve_bits = {"P-256": 256, "P-384": 384, "P-521": 521}
    return curve_bits.get(str(key_param), 0)
