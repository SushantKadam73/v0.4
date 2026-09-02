from __future__ import annotations

import math

from analysis.entropy import shannon_entropy


def key_entropy_score(key_bytes: bytes) -> float:
    return shannon_entropy(key_bytes)


def is_low_entropy_key(key_bytes: bytes) -> bool:
    if not key_bytes:
        return False
    # A fixed 7.0 bits/byte threshold is unreachable for keys under 256 bytes
    # (max is log2(len)), so every 32-byte random key would false-positive.
    # Scale the threshold to the sample length to flag structured keys only.
    sample_cap = min(len(key_bytes), 256)
    return shannon_entropy(key_bytes) < 0.8 * math.log2(sample_cap)


def signature_size_bits(signature: bytes) -> int:
    return len(signature) * 8


def is_all_zero_key(key_bytes: bytes) -> bool:
    return bool(key_bytes) and all(b == 0 for b in key_bytes)


def is_non_standard_key_size(key_bytes: bytes, expected_sizes: set[int]) -> bool:
    return len(key_bytes) not in expected_sizes
