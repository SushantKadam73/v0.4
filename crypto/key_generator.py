from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


@dataclass
class AsymmetricKeyPair:
    private_pem: bytes
    public_pem: bytes


def _deterministic_bytes(seed: str, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        chunk = hashlib.sha256(f"{seed}:{counter}".encode("utf-8")).digest()
        out.extend(chunk)
        counter += 1
    return bytes(out[:length])


def generate_symmetric_key(seed: str | None = None) -> bytes:
    if seed:
        return _deterministic_bytes(seed, 32)
    return os.urandom(32)


def generate_ecdsa_keypair() -> AsymmetricKeyPair:
    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return AsymmetricKeyPair(private_pem=private_pem, public_pem=public_pem)


def generate_rsa_keypair() -> AsymmetricKeyPair:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return AsymmetricKeyPair(private_pem=private_pem, public_pem=public_pem)
