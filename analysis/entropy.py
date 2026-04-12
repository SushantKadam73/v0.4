from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def entropy_label(value: float) -> str:
    if value < 4.0:
        return "Low"
    if value < 6.5:
        return "Medium"
    if value < 7.5:
        return "Good"
    return "Strong"


def byte_frequency(data: bytes) -> list[int]:
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    return freq
