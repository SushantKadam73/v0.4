from __future__ import annotations


def flip_one_bit(data: bytes, bit_index: int = 0) -> bytes:
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
    if not a and not b:
        return 0.0
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b"\x00")
    b_padded = b.ljust(max_len, b"\x00")
    diff_bits = 0
    for x, y in zip(a_padded, b_padded):
        diff_bits += (x ^ y).bit_count()
    total_bits = max_len * 8
    return (diff_bits / total_bits) * 100.0


def bit_difference_map(a: bytes, b: bytes) -> list[int]:
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b"\x00")
    b_padded = b.ljust(max_len, b"\x00")
    diff = []
    for x, y in zip(a_padded, b_padded):
        byte_diff = x ^ y
        diff.append(byte_diff.bit_count())
    return diff
