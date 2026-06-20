"""JSONL-based flat log store.

All operations are appended as one JSON object per line in `logs/operations.jsonl`.
This keeps the app database-free while still making the data easy to load into
pandas and export to CSV for research analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

DEFAULT_LOG_PATH = Path("logs/operations.jsonl")
DEFAULT_EXPORT_DIR = Path("logs/exports")

CSV_COLUMNS = [
    "id",
    "timestamp",
    "batch_id",
    "iteration",
    "operation",
    "algorithm",
    "sym_key_size_bits",
    "aes_key_size_bits",
    "chacha_key_size_bits",
    "sig_algorithm",
    "sig_key_param",
    "sig_key_size_bits",
    "memory_backend",
    "input_filename",
    "input_extension",
    "input_mime",
    "input_size_bytes",
    "input_size_kb",
    "input_file_category",
    "input_entropy",
    "output_filename",
    "output_size_bytes",
    "output_size_kb",
    "output_entropy",
    "ciphertext_expansion_pct",
    "enc_time_ms",
    "dec_time_ms",
    "total_time_ms",
    "enc_ram_kb",
    "dec_ram_kb",
    "enc_throughput_kbps",
    "dec_throughput_kbps",
    "aes_key_entropy",
    "chacha_key_entropy",
    "sig_size_bits",
    "sig_valid",
    "plaintext_sha256",
    "ciphertext_sha256",
    "decrypted_sha256",
    "hash_match",
    "entropy_plaintext",
    "entropy_aes_half",
    "entropy_chacha_half",
    "entropy_final",
    "avalanche_pct",
    "avalanche_bits_flipped",
    "avalanche_total_bits",
    "avalanche_deviation",
    "byte_freq_std_dev",
    "chi_squared",
]

NUMERIC_COLUMNS = [
    "input_size_bytes",
    "input_size_kb",
    "input_entropy",
    "output_size_bytes",
    "output_size_kb",
    "output_entropy",
    "ciphertext_expansion_pct",
    "enc_time_ms",
    "dec_time_ms",
    "total_time_ms",
    "enc_ram_kb",
    "dec_ram_kb",
    "enc_throughput_kbps",
    "dec_throughput_kbps",
    "aes_key_entropy",
    "chacha_key_entropy",
    "sig_size_bits",
    "entropy_plaintext",
    "entropy_aes_half",
    "entropy_chacha_half",
    "entropy_final",
    "avalanche_pct",
    "avalanche_bits_flipped",
    "avalanche_total_bits",
    "avalanche_deviation",
    "byte_freq_std_dev",
    "chi_squared",
    "iteration",
    "sym_key_size_bits",
    "aes_key_size_bits",
    "chacha_key_size_bits",
    "sig_key_size_bits",
]


def _ensure_paths(
    log_path: Path = DEFAULT_LOG_PATH, export_dir: Path = DEFAULT_EXPORT_DIR
) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    export_dir.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.touch()


def append_row(row: dict[str, Any], log_path: Path = DEFAULT_LOG_PATH) -> None:
    """Append one operation row to the JSONL log."""
    _ensure_paths(log_path=log_path)
    payload = {col: row.get(col, "") for col in CSV_COLUMNS}
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, default=str) + "\n")


def load_all(log_path: Path = DEFAULT_LOG_PATH) -> pd.DataFrame:
    """Load the entire JSONL log into a DataFrame."""
    _ensure_paths(log_path=log_path)
    if not log_path.exists() or log_path.stat().st_size == 0:
        return pd.DataFrame(columns=CSV_COLUMNS)

    rows: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not rows:
        return pd.DataFrame(columns=CSV_COLUMNS)

    df = pd.DataFrame(rows)
    for col in CSV_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = df[CSV_COLUMNS]

    for col in NUMERIC_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "sig_valid" in df.columns:
        df["sig_valid"] = df["sig_valid"].apply(
            lambda value: (
                True if value == "True" else False if value == "False" else None
            )
        )
    if "hash_match" in df.columns:
        df["hash_match"] = df["hash_match"].apply(
            lambda value: (
                True if value == "True" else False if value == "False" else None
            )
        )
    return pd.DataFrame(df)


def export_csv(
    df: pd.DataFrame, file_name: str, export_dir: Path = DEFAULT_EXPORT_DIR
) -> Path:
    _ensure_paths(export_dir=export_dir)
    out_path = export_dir / file_name
    df.to_csv(out_path, index=False, encoding="utf-8")
    return out_path


def export_json(
    data: Any, file_name: str, export_dir: Path = DEFAULT_EXPORT_DIR
) -> Path:
    _ensure_paths(export_dir=export_dir)
    out_path = export_dir / file_name
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return out_path


def clear_log(log_path: Path = DEFAULT_LOG_PATH) -> None:
    _ensure_paths(log_path=log_path)
    log_path.write_text("", encoding="utf-8")
