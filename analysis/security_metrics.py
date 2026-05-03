"""Security metrics and statistical tests for cryptographic analysis."""
from __future__ import annotations

from analysis.entropy import shannon_entropy


def key_entropy_score(key_bytes: bytes) -> float:
    """Shannon entropy of key bytes. Ideal is close to 8.0."""
    return shannon_entropy(key_bytes)


def signature_size_bits(signature: bytes) -> int:
    """Signature length in bits."""
    return len(signature) * 8


def is_all_zero_key(key_bytes: bytes) -> bool:
    """True if key is all zeros — a critical weakness."""
    return bool(key_bytes) and all(b == 0 for b in key_bytes)


def is_non_standard_key_size(key_bytes: bytes, expected_sizes: set[int]) -> bool:
    """True if key length is not in the expected set (bytes)."""
    return len(key_bytes) not in expected_sizes


def ciphertext_expansion_pct(input_size_bytes: int, output_size_bytes: int) -> float:
    """Percentage size increase from input to ciphertext.

    Positive = expansion (normal for AEAD overhead),
    Negative = compression (should not happen with proper encryption).
    """
    if input_size_bytes <= 0:
        return 0.0
    return round(((output_size_bytes - input_size_bytes) / input_size_bytes) * 100.0, 4)


def chi_squared_uniformity(data: bytes) -> float:
    """Chi-squared test for byte uniformity.

    Tests whether the byte distribution is uniform (expected for good ciphertext).
    Returns the chi-squared statistic. Lower = more uniform.
    For 256 bins, perfect uniformity gives chi² ≈ 255 (df = 255).
    Values far above 255 indicate non-uniformity (patterns in ciphertext).
    """
    if len(data) < 256:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    expected = len(data) / 256.0
    chi2 = sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(256))
    return round(chi2, 4)
