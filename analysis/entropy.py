"""Entropy analysis utilities."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte. Max = 8.0 (perfectly random)."""
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
    """Human-readable label for entropy value."""
    if value < 4.0:
        return "Low"
    if value < 6.5:
        return "Medium"
    if value < 7.5:
        return "Good"
    return "Strong"


def byte_frequency(data: bytes) -> list[int]:
    """Return per-byte frequency count (length 256)."""
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    return freq


def byte_frequency_std_dev(data: bytes) -> float:
    """Standard deviation of the 256-bin byte frequency histogram.

    Ideal random data has all frequencies equal → std_dev approaches 0.
    Structured data with patterns has high std_dev.
    """
    if not data:
        return 0.0
    freq = byte_frequency(data)
    n = len(freq)
    mean = sum(freq) / n
    variance = sum((f - mean) ** 2 for f in freq) / n
    return math.sqrt(variance)
