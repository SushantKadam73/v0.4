from __future__ import annotations

from analysis.entropy import shannon_entropy


def key_entropy_score(key_bytes: bytes) -> float:
    return shannon_entropy(key_bytes)


def signature_size_bits(signature: bytes) -> int:
    return len(signature) * 8


def is_all_zero_key(key_bytes: bytes) -> bool:
    return bool(key_bytes) and all(b == 0 for b in key_bytes)


def is_non_standard_key_size(key_bytes: bytes, expected_sizes: set[int]) -> bool:
    return len(key_bytes) not in expected_sizes
