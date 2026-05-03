"""Avalanche effect analysis.

Measures how much the ciphertext changes when a single input bit is flipped.
Ideal: ~50% of bits should change (strict avalanche criterion).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class AvalancheResult:
    bit_change_pct: float
    bits_flipped: int
    total_bits: int
    deviation_from_ideal: float  # |bit_change_pct - 50.0|

    def label(self) -> str:
        if self.deviation_from_ideal <= 5.0:
            return "Excellent"
        if self.deviation_from_ideal <= 10.0:
            return "Good"
        if self.deviation_from_ideal <= 20.0:
            return "Fair"
        return "Poor"


def flip_one_bit(data: bytes, bit_index: int = 0) -> bytes:
    """Flip a single bit in the data at the given bit position."""
    if not data:
        return data
    byte_index = bit_index // 8
    in_byte_index = bit_index % 8
    if byte_index >= len(data):
        byte_index = len(data) - 1
        in_byte_index = 0
    mutable = bytearray(data)
    mutable[byte_index] ^= 1 << in_byte_index
    return bytes(mutable)


def bit_difference_percentage(a: bytes, b: bytes) -> float:
    """Percentage of bits that differ between two byte sequences."""
    if not a and not b:
        return 0.0
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b"\x00")
    b_padded = b.ljust(max_len, b"\x00")
    diff_bits = sum((x ^ y).bit_count() for x, y in zip(a_padded, b_padded))
    total_bits = max_len * 8
    return (diff_bits / total_bits) * 100.0


def bit_difference_map(a: bytes, b: bytes) -> list[int]:
    """Per-byte bit-difference count between two byte sequences."""
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b"\x00")
    b_padded = b.ljust(max_len, b"\x00")
    return [(x ^ y).bit_count() for x, y in zip(a_padded, b_padded)]


def compute_avalanche(
    encrypt_fn: Callable[[bytes, bytes], bytes],
    data: bytes,
    key: bytes,
    flip_bit_index: int = 0,
) -> AvalancheResult:
    """Compute the avalanche effect for any encrypt function.

    Args:
        encrypt_fn: function(data, key) -> ciphertext
        data: original plaintext
        key: encryption key
        flip_bit_index: which bit to flip in the plaintext (default 0)

    Returns:
        AvalancheResult with bit change percentage and deviation from ideal 50%
    """
    if not data:
        return AvalancheResult(0.0, 0, 0, 50.0)

    c_original = encrypt_fn(data, key)
    data_flipped = flip_one_bit(data, flip_bit_index)
    c_flipped = encrypt_fn(data_flipped, key)

    max_len = max(len(c_original), len(c_flipped))
    a_padded = c_original.ljust(max_len, b"\x00")
    b_padded = c_flipped.ljust(max_len, b"\x00")
    bits_flipped = sum((x ^ y).bit_count() for x, y in zip(a_padded, b_padded))
    total_bits = max_len * 8
    pct = (bits_flipped / total_bits * 100.0) if total_bits > 0 else 0.0
    deviation = abs(pct - 50.0)

    return AvalancheResult(
        bit_change_pct=round(pct, 3),
        bits_flipped=bits_flipped,
        total_bits=total_bits,
        deviation_from_ideal=round(deviation, 3),
    )
