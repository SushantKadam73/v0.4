"""CryptoLab core orchestration layer.

Provides EncryptionConfig, OperationResult, and the master run_operation()
function that wires together all crypto engines, analysis, and logging.
"""
from __future__ import annotations

import mimetypes
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from analysis.avalanche import AvalancheResult, compute_avalanche
from analysis.entropy import byte_frequency_std_dev as _byte_freq_std_dev, shannon_entropy
from analysis.performance import MultiIterationMetrics, OperationMetrics, measure_multi, measure_operation
from analysis.security_metrics import chi_squared_uniformity, ciphertext_expansion_pct, key_entropy_score
from crypto import aes_gcm_engine, chacha20_poly_engine, hybrid_engine
from crypto.key_generator import generate_symmetric_key
from crypto.signature import signature_key_size_bits
from storage.log_store import CSV_COLUMNS, append_row

# ──────────────────────────────────────────────
# NIST Security Equivalence Table
# ──────────────────────────────────────────────
NIST_SECURITY_LEVELS = {
    128: {"aes_bits": 128, "rsa_bits": 3072, "ecdsa_curve": "P-256"},
    192: {"aes_bits": 192, "rsa_bits": 7680, "ecdsa_curve": "P-384"},
    256: {"aes_bits": 256, "rsa_bits": 15360, "ecdsa_curve": "P-521"},
}

ALGORITHM_DISPLAY = {
    "aes_gcm": "AES-GCM",
    "chacha20_poly1305": "ChaCha20-Poly1305",
    "hybrid": "Hybrid (AES-GCM + ChaCha20-Poly1305)",
}


# ──────────────────────────────────────────────
# Configuration Dataclass
# ──────────────────────────────────────────────
@dataclass
class EncryptionConfig:
    algorithm: str               # "aes_gcm" | "chacha20_poly1305" | "hybrid"
    sym_key_size_bits: int = 256  # 128/192/256 (ChaCha20 forced to 256)
    sig_algorithm: str | None = None  # None | "RSA" | "ECDSA"
    sig_key_param: str = "2048"  # RSA size or ECDSA curve name
    operation: str = "both"      # "encrypt" | "decrypt" | "both"
    iterations: int = 1


# ──────────────────────────────────────────────
# Result Dataclass
# ──────────────────────────────────────────────
@dataclass
class OperationResult:
    # Encrypted output
    ciphertext: bytes = b""
    decrypted: bytes = b""

    # Timing & RAM (single run)
    enc_time_ms: float = 0.0
    dec_time_ms: float = 0.0
    enc_ram_kb: float = 0.0
    dec_ram_kb: float = 0.0
    enc_throughput_kbps: float = 0.0
    dec_throughput_kbps: float = 0.0

    # Multi-run stats (populated only when iterations > 1)
    enc_mean_ms: float = 0.0
    enc_std_ms: float = 0.0
    dec_mean_ms: float = 0.0
    dec_std_ms: float = 0.0
    enc_mean_ram_kb: float = 0.0
    enc_std_ram_kb: float = 0.0
    enc_mean_throughput: float = 0.0
    enc_std_throughput: float = 0.0

    # Entropy stages
    entropy_plaintext: float = 0.0
    entropy_aes_half: float = 0.0
    entropy_chacha_half: float = 0.0
    entropy_final: float = 0.0

    # Avalanche
    avalanche: AvalancheResult | None = None

    # Ciphertext quality
    ciphertext_expansion_pct: float = 0.0
    byte_freq_std_dev: float = 0.0
    chi_squared: float = 0.0

    # Signature
    sig_valid: bool = True
    sig_bytes: bytes = b""
    sig_size_bits: int = 0

    # Key entropies
    aes_key_entropy: float = 0.0
    chacha_key_entropy: float = 0.0

    # Error (if something went wrong)
    error: str | None = None


# ──────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────
def op_id() -> str:
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"op_{ts}_{uuid.uuid4().hex[:4]}"


def batch_id() -> str:
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"batch_{ts}_{uuid.uuid4().hex[:4]}"


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_category(extension: str) -> str:
    text_ext = {".txt", ".csv", ".json", ".xml", ".md"}
    doc_ext = {".pdf", ".docx", ".pptx", ".xlsx"}
    img_ext = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}
    aud_ext = {".mp3", ".wav", ".aac", ".flac", ".ogg"}
    vid_ext = {".mp4", ".mkv", ".avi", ".mov", ".webm"}
    arc_ext = {".zip", ".tar", ".gz", ".7z", ".rar"}
    ext = extension.lower()
    if ext in text_ext:
        return "text"
    if ext in doc_ext:
        return "document"
    if ext in img_ext:
        return "image"
    if ext in aud_ext:
        return "audio"
    if ext in vid_ext:
        return "video"
    if ext in arc_ext:
        return "archive"
    return "other"


def hex_preview(data: bytes, max_bytes: int = 256) -> str:
    return data[:max_bytes].hex()


def _get_encrypt_fn(algorithm: str, aes_key: bytes, chacha_key: bytes,
                    private_pem: bytes | None, sig_algorithm: str | None):
    """Return a simple (data, key) -> ciphertext lambda for avalanche computation."""
    if algorithm == "aes_gcm":
        return lambda d, k: aes_gcm_engine.encrypt(d, k)
    elif algorithm == "chacha20_poly1305":
        return lambda d, k: chacha20_poly_engine.encrypt(d, k)
    elif algorithm == "hybrid":
        return lambda d, k: hybrid_engine.encrypt(
            d, aes_key, chacha_key, private_pem, sig_algorithm
        )
    raise ValueError(f"Unknown algorithm: {algorithm}")


# ──────────────────────────────────────────────
# Master Operation Function
# ──────────────────────────────────────────────
def run_operation(
    config: EncryptionConfig,
    data: bytes,
    aes_key: bytes,
    chacha_key: bytes,
    private_pem: bytes | None = None,
    public_pem: bytes | None = None,
) -> OperationResult:
    """Run encrypt/decrypt and compute all analysis metrics.

    This is the single entry point for the Encryption Lab page.
    """
    result = OperationResult()

    # Force ChaCha20 key to 256-bit
    if config.algorithm == "chacha20_poly1305" and len(chacha_key) != 32:
        chacha_key = generate_symmetric_key(256)

    # Key entropies
    result.aes_key_entropy = round(key_entropy_score(aes_key), 4)
    result.chacha_key_entropy = round(key_entropy_score(chacha_key), 4)

    try:
        # ── ENCRYPT ──────────────────────────────
        if config.iterations > 1:
            # Multi-iteration: use the last ciphertext as the actual output
            if config.algorithm == "aes_gcm":
                enc_multi = measure_multi(
                    aes_gcm_engine.encrypt, data, aes_key,
                    iterations=config.iterations, input_size_bytes=len(data)
                )
            elif config.algorithm == "chacha20_poly1305":
                enc_multi = measure_multi(
                    chacha20_poly_engine.encrypt, data, chacha_key,
                    iterations=config.iterations, input_size_bytes=len(data)
                )
            else:  # hybrid
                enc_multi = measure_multi(
                    hybrid_engine.encrypt, data, aes_key, chacha_key,
                    private_pem, config.sig_algorithm,
                    iterations=config.iterations, input_size_bytes=len(data)
                )
            result.ciphertext = enc_multi.results[-1]
            result.enc_time_ms = enc_multi.mean_ms
            result.enc_ram_kb = enc_multi.mean_ram_kb
            result.enc_throughput_kbps = enc_multi.mean_throughput_kbps
            result.enc_mean_ms = enc_multi.mean_ms
            result.enc_std_ms = enc_multi.std_ms
            result.enc_mean_ram_kb = enc_multi.mean_ram_kb
            result.enc_std_ram_kb = enc_multi.std_ram_kb
            result.enc_mean_throughput = enc_multi.mean_throughput_kbps
            result.enc_std_throughput = enc_multi.std_throughput_kbps
        else:
            if config.algorithm == "aes_gcm":
                enc_m = measure_operation(aes_gcm_engine.encrypt, data, aes_key, input_size_bytes=len(data))
            elif config.algorithm == "chacha20_poly1305":
                enc_m = measure_operation(chacha20_poly_engine.encrypt, data, chacha_key, input_size_bytes=len(data))
            else:  # hybrid
                enc_m = measure_operation(
                    hybrid_engine.encrypt, data, aes_key, chacha_key,
                    private_pem, config.sig_algorithm, input_size_bytes=len(data)
                )
            result.ciphertext = enc_m.result
            result.enc_time_ms = enc_m.elapsed_ms
            result.enc_ram_kb = enc_m.ram_kb
            result.enc_throughput_kbps = enc_m.throughput_kbps

        # ── DECRYPT ──────────────────────────────
        if config.operation in {"decrypt", "both"}:
            if config.algorithm == "aes_gcm":
                dec_m = measure_operation(
                    aes_gcm_engine.decrypt, result.ciphertext, aes_key,
                    input_size_bytes=len(result.ciphertext)
                )
                result.decrypted = dec_m.result
                result.sig_valid = True
                result.sig_bytes = b""
                result.sig_size_bits = 0
            elif config.algorithm == "chacha20_poly1305":
                dec_m = measure_operation(
                    chacha20_poly_engine.decrypt, result.ciphertext, chacha_key,
                    input_size_bytes=len(result.ciphertext)
                )
                result.decrypted = dec_m.result
                result.sig_valid = True
                result.sig_bytes = b""
                result.sig_size_bits = 0
            else:  # hybrid
                dec_m = measure_operation(
                    hybrid_engine.decrypt, result.ciphertext, aes_key, chacha_key,
                    public_pem, config.sig_algorithm,
                    input_size_bytes=len(result.ciphertext)
                )
                dec_res = dec_m.result
                result.decrypted = dec_res.plaintext
                result.sig_valid = dec_res.signature_valid
                result.sig_bytes = dec_res.signature_bytes
                result.sig_size_bits = len(dec_res.signature_bytes) * 8

            result.dec_time_ms = dec_m.elapsed_ms
            result.dec_ram_kb = dec_m.ram_kb
            result.dec_throughput_kbps = dec_m.throughput_kbps

        # ── ENTROPY STAGES ───────────────────────
        midpoint = len(data) // 2
        result.entropy_plaintext = round(shannon_entropy(data), 4)
        result.entropy_aes_half = round(shannon_entropy(data[:midpoint]), 4)
        result.entropy_chacha_half = round(shannon_entropy(data[midpoint:]), 4)
        result.entropy_final = round(shannon_entropy(result.ciphertext), 4)

        # ── CIPHERTEXT QUALITY ───────────────────
        result.ciphertext_expansion_pct = ciphertext_expansion_pct(len(data), len(result.ciphertext))
        result.byte_freq_std_dev = round(_byte_freq_std_dev(result.ciphertext), 4)
        result.chi_squared = chi_squared_uniformity(result.ciphertext)

        # ── AVALANCHE EFFECT ─────────────────────
        if len(data) >= 1:
            try:
                if config.algorithm == "aes_gcm":
                    avalanche_fn = lambda d, k: aes_gcm_engine.encrypt(d, k)
                    result.avalanche = compute_avalanche(avalanche_fn, data, aes_key)
                elif config.algorithm == "chacha20_poly1305":
                    avalanche_fn = lambda d, k: chacha20_poly_engine.encrypt(d, k)
                    result.avalanche = compute_avalanche(avalanche_fn, data, chacha_key)
                else:  # hybrid — use AES-GCM half for avalanche (more deterministic)
                    avalanche_fn = lambda d, k: aes_gcm_engine.encrypt(d, k)
                    result.avalanche = compute_avalanche(avalanche_fn, data[:max(1, len(data)//2)], aes_key)
            except Exception:
                result.avalanche = None

    except Exception as exc:
        result.error = str(exc)

    return result


# ──────────────────────────────────────────────
# CSV Row Builder
# ──────────────────────────────────────────────
def build_and_log_row(
    config: EncryptionConfig,
    input_filename: str,
    input_data: bytes,
    output_filename: str,
    result: OperationResult,
    batch_id_val: str = "",
    iteration: int = 1,
) -> dict[str, Any]:
    """Build a flat CSV row dict and append it to the log."""
    ext = Path(input_filename).suffix.lower()
    mime = mimetypes.guess_type(input_filename)[0] or "application/octet-stream"

    sig_key_str = config.sig_key_param if config.sig_algorithm else ""
    sig_key_size = signature_key_size_bits(config.sig_algorithm or "", sig_key_str) if config.sig_algorithm else 0

    row: dict[str, Any] = {
        "id": op_id(),
        "timestamp": now_iso(),
        "batch_id": batch_id_val,
        "iteration": iteration,
        "operation": config.operation,
        "algorithm": config.algorithm,
        "sym_key_size_bits": config.sym_key_size_bits,
        "sig_algorithm": config.sig_algorithm or "",
        "sig_key_param": sig_key_str,
        # Input
        "input_filename": input_filename,
        "input_extension": ext,
        "input_mime": mime,
        "input_size_bytes": len(input_data),
        "input_size_kb": round(len(input_data) / 1024.0, 3),
        "input_file_category": file_category(ext),
        "input_entropy": result.entropy_plaintext,
        # Output
        "output_filename": output_filename,
        "output_size_bytes": len(result.ciphertext),
        "output_size_kb": round(len(result.ciphertext) / 1024.0, 3),
        "output_entropy": result.entropy_final,
        "ciphertext_expansion_pct": result.ciphertext_expansion_pct,
        # Performance
        "enc_time_ms": result.enc_time_ms,
        "dec_time_ms": result.dec_time_ms,
        "total_time_ms": round(result.enc_time_ms + result.dec_time_ms, 4),
        "enc_ram_kb": result.enc_ram_kb,
        "dec_ram_kb": result.dec_ram_kb,
        "enc_throughput_kbps": result.enc_throughput_kbps,
        "dec_throughput_kbps": result.dec_throughput_kbps,
        # Keys
        "aes_key_entropy": result.aes_key_entropy,
        "chacha_key_entropy": result.chacha_key_entropy,
        "sig_size_bits": result.sig_size_bits,
        "sig_valid": result.sig_valid,
        # Entropy pipeline
        "entropy_plaintext": result.entropy_plaintext,
        "entropy_aes_half": result.entropy_aes_half,
        "entropy_chacha_half": result.entropy_chacha_half,
        "entropy_final": result.entropy_final,
        # Avalanche
        "avalanche_pct": result.avalanche.bit_change_pct if result.avalanche else None,
        "avalanche_bits_flipped": result.avalanche.bits_flipped if result.avalanche else None,
        "avalanche_total_bits": result.avalanche.total_bits if result.avalanche else None,
        "avalanche_deviation": result.avalanche.deviation_from_ideal if result.avalanche else None,
        # Randomness
        "byte_freq_std_dev": result.byte_freq_std_dev,
        "chi_squared": result.chi_squared,
    }

    append_row(row)
    return row


def byte_freq_std_dev(data: bytes) -> float:
    """Convenience re-export for use in pages."""
    return _byte_freq_std_dev(data)
