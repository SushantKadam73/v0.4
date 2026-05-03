from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def key_size_bits(public_or_private_pem: bytes) -> int | None:
    try:
        key = serialization.load_pem_public_key(public_or_private_pem)
    except Exception:
        key = serialization.load_pem_private_key(public_or_private_pem, password=None)
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return key.key_size
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return key.curve.key_size
    return None


def sign(data: bytes, private_key_pem: bytes, signature_algorithm: str) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    digest = hashes.SHA256()
    if signature_algorithm == "RSA":
        return private_key.sign(data, padding.PKCS1v15(), digest)
    if signature_algorithm == "ECDSA":
        return private_key.sign(data, ec.ECDSA(digest))
    raise ValueError("Signature algorithm must be RSA or ECDSA")


def verify(
    data: bytes, signature: bytes, public_key_pem: bytes, signature_algorithm: str
) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem)
    digest = hashes.SHA256()
    try:
        if signature_algorithm == "RSA":
            public_key.verify(signature, data, padding.PKCS1v15(), digest)
        elif signature_algorithm == "ECDSA":
            public_key.verify(signature, data, ec.ECDSA(digest))
        else:
            raise ValueError("Signature algorithm must be RSA or ECDSA")
        return True
    except InvalidSignature:
        return False
