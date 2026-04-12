from __future__ import annotations

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from crypto.utils import BLOCK_SIZE, pkcs7_pad, pkcs7_unpad


def generate_key() -> bytes:
    return get_random_bytes(32)


def encrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pkcs7_pad(data, BLOCK_SIZE))
    return iv + ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if len(data) < BLOCK_SIZE:
        raise ValueError("Ciphertext too short")
    iv = data[:BLOCK_SIZE]
    body = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext_padded = cipher.decrypt(body)
    return pkcs7_unpad(plaintext_padded, BLOCK_SIZE)
