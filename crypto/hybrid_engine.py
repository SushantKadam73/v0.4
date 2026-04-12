from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from crypto import aes_engine, chacha20_engine


class IntegrityError(Exception):
    pass


@dataclass
class HybridDecryptResult:
    plaintext: bytes
    signature_valid: bool
    signature_bytes: bytes


def _sign_digest(digest: bytes, private_key_pem: bytes, signature_algorithm: str) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if signature_algorithm == "RSA":
        return private_key.sign(
            digest,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    if signature_algorithm == "ECDSA":
        return private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    raise ValueError("Unsupported signature algorithm")


def _verify_digest(signature: bytes, digest: bytes, public_key_pem: bytes, signature_algorithm: str) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        if signature_algorithm == "RSA":
            public_key.verify(signature, digest, padding.PKCS1v15(), hashes.SHA256())
        elif signature_algorithm == "ECDSA":
            public_key.verify(signature, digest, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError("Unsupported signature algorithm")
        return True
    except InvalidSignature:
        return False


def encrypt(
    data: bytes,
    aes_key: bytes,
    chacha20_key: bytes,
    private_key_pem: bytes,
    signature_algorithm: str,
) -> bytes:
    midpoint = len(data) // 2
    first_half = data[:midpoint]
    second_half = data[midpoint:]

    c1 = aes_engine.encrypt(first_half, aes_key)
    c2 = chacha20_engine.encrypt(second_half, chacha20_key)

    digest = hashlib.sha256(c1 + c2).digest()
    signature = _sign_digest(digest, private_key_pem, signature_algorithm)

    payload = (
        struct.pack(">I", len(signature))
        + signature
        + struct.pack(">I", len(c1))
        + c1
        + c2
    )
    return payload


def decrypt(
    payload: bytes,
    aes_key: bytes,
    chacha20_key: bytes,
    public_key_pem: bytes,
    signature_algorithm: str,
) -> HybridDecryptResult:
    if len(payload) < 8:
        raise ValueError("Payload too short")

    sig_len = struct.unpack(">I", payload[:4])[0]
    signature = payload[4 : 4 + sig_len]

    c1_len_offset = 4 + sig_len
    c1_len = struct.unpack(">I", payload[c1_len_offset : c1_len_offset + 4])[0]
    c1_offset = c1_len_offset + 4
    c1 = payload[c1_offset : c1_offset + c1_len]
    c2 = payload[c1_offset + c1_len :]

    digest = hashlib.sha256(c1 + c2).digest()
    is_valid = _verify_digest(signature, digest, public_key_pem, signature_algorithm)
    if not is_valid:
        raise IntegrityError("Signature verification failed")

    p1 = aes_engine.decrypt(c1, aes_key)
    p2 = chacha20_engine.decrypt(c2, chacha20_key)
    return HybridDecryptResult(plaintext=p1 + p2, signature_valid=True, signature_bytes=signature)


def verify_payload_signature(payload: bytes, public_key_pem: bytes, signature_algorithm: str) -> tuple[bool, bytes]:
    if len(payload) < 8:
        return False, b""

    sig_len = struct.unpack(">I", payload[:4])[0]
    signature = payload[4 : 4 + sig_len]
    c1_len_offset = 4 + sig_len
    c1_len = struct.unpack(">I", payload[c1_len_offset : c1_len_offset + 4])[0]
    c1_offset = c1_len_offset + 4
    c1 = payload[c1_offset : c1_offset + c1_len]
    c2 = payload[c1_offset + c1_len :]
    digest = hashlib.sha256(c1 + c2).digest()
    return _verify_digest(signature, digest, public_key_pem, signature_algorithm), signature
