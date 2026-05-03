"""Hybrid encryption engine: AES-GCM + ChaCha20-Poly1305 + optional digital signature.

The plaintext is split at the midpoint:
  first_half  → AES-GCM
  second_half → ChaCha20-Poly1305

Wire format:
  [4B sig_len][sig_bytes (if any)][4B c1_len][c1_bytes][c2_bytes]

If no signature: sig_len = 0, sig_bytes = b"".
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from crypto import aes_gcm_engine, chacha20_poly_engine
from crypto.signature import sign, verify


@dataclass
class HybridDecryptResult:
    plaintext: bytes
    signature_valid: bool
    signature_bytes: bytes


def encrypt(
    data: bytes,
    aes_key: bytes,
    chacha_key: bytes,
    private_pem: bytes | None = None,
    sig_algorithm: str | None = None,
) -> bytes:
    """Encrypt data with AES-GCM + ChaCha20-Poly1305, optionally sign.

    Args:
        data: plaintext bytes
        aes_key: AES-GCM key (16/24/32 bytes)
        chacha_key: ChaCha20-Poly1305 key (32 bytes)
        private_pem: optional private key PEM for signing
        sig_algorithm: "RSA" or "ECDSA" (required if private_pem is provided)
    """
    midpoint = len(data) // 2
    first_half = data[:midpoint]
    second_half = data[midpoint:]

    c1 = aes_gcm_engine.encrypt(first_half, aes_key)
    c2 = chacha20_poly_engine.encrypt(second_half, chacha_key)

    if private_pem and sig_algorithm:
        digest = hashlib.sha256(c1 + c2).digest()
        signature = sign(digest, private_pem, sig_algorithm)
    else:
        signature = b""

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
    chacha_key: bytes,
    public_pem: bytes | None = None,
    sig_algorithm: str | None = None,
) -> HybridDecryptResult:
    """Decrypt a hybrid payload, verify signature if present."""
    if len(payload) < 8:
        raise ValueError("Payload too short to be a valid hybrid ciphertext")

    sig_len = struct.unpack(">I", payload[:4])[0]
    signature = payload[4: 4 + sig_len]

    c1_len_offset = 4 + sig_len
    c1_len = struct.unpack(">I", payload[c1_len_offset: c1_len_offset + 4])[0]
    c1_offset = c1_len_offset + 4
    c1 = payload[c1_offset: c1_offset + c1_len]
    c2 = payload[c1_offset + c1_len:]

    # Verify signature if present
    sig_valid = True
    if sig_len > 0 and public_pem and sig_algorithm:
        digest = hashlib.sha256(c1 + c2).digest()
        sig_valid = verify(digest, signature, public_pem, sig_algorithm)
        if not sig_valid:
            raise ValueError("Signature verification failed — payload may have been tampered")

    p1 = aes_gcm_engine.decrypt(c1, aes_key)
    p2 = chacha20_poly_engine.decrypt(c2, chacha_key)

    return HybridDecryptResult(
        plaintext=p1 + p2,
        signature_valid=sig_valid,
        signature_bytes=signature,
    )


def verify_payload_signature(
    payload: bytes,
    public_pem: bytes,
    sig_algorithm: str,
) -> tuple[bool, bytes]:
    """Standalone signature verification for an existing payload."""
    if len(payload) < 8:
        return False, b""
    sig_len = struct.unpack(">I", payload[:4])[0]
    if sig_len == 0:
        return False, b""
    signature = payload[4: 4 + sig_len]
    c1_len_offset = 4 + sig_len
    c1_len = struct.unpack(">I", payload[c1_len_offset: c1_len_offset + 4])[0]
    c1_offset = c1_len_offset + 4
    c1 = payload[c1_offset: c1_offset + c1_len]
    c2 = payload[c1_offset + c1_len:]
    digest = hashlib.sha256(c1 + c2).digest()
    return verify(digest, signature, public_pem, sig_algorithm), signature
