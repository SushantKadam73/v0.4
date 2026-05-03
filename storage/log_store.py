"""CSV-based flat log store.

All operations are appended as rows to a single CSV file.
No nested JSON — every metric is a flat column for direct pandas analysis.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import pandas as pd

DEFAULT_LOG_PATH = Path("logs/operations.csv")
DEFAULT_EXPORT_DIR = Path("logs/exports")

# All columns in the CSV — order matters for readability
CSV_COLUMNS = [
    "id",
    "timestamp",
    "batch_id",
    "iteration",
    "operation",
    "algorithm",
    "sym_key_size_bits",
    "sig_algorithm",
    "sig_key_param",
    # Input file metadata
    "input_filename",
    "input_extension",
    "input_mime",
    "input_size_bytes",
    "input_size_kb",
    "input_file_category",
    "input_entropy",
    # Output metadata
    "output_filename",
    "output_size_bytes",
    "output_size_kb",
    "output_entropy",
    "ciphertext_expansion_pct",
    # Performance
    "enc_time_ms",
    "dec_time_ms",
    "total_time_ms",
    "enc_ram_kb",
    "dec_ram_kb",
    "enc_throughput_kbps",
    "dec_throughput_kbps",
    # Key metadata
    "aes_key_entropy",
    "chacha_key_entropy",
    "sig_size_bits",
    "sig_valid",
    # Entropy pipeline
    "entropy_plaintext",
    "entropy_aes_half",
    "entropy_chacha_half",
    "entropy_final",
    # Avalanche
    "avalanche_pct",
    "avalanche_bits_flipped",
    "avalanche_total_bits",
    "avalanche_deviation",
    # Randomness
    "byte_freq_std_dev",
    "chi_squared",
]


def _ensure_paths(log_path: Path = DEFAULT_LOG_PATH, export_dir: Path = DEFAULT_EXPORT_DIR) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    export_dir.mkdir(parents=True, exist_ok=True)


def append_row(row: dict[str, Any], log_path: Path = DEFAULT_LOG_PATH) -> None:
    """Append one operation row to the CSV. Creates header if file is new."""
    _ensure_paths(log_path=log_path)
    file_exists = log_path.exists() and log_path.stat().st_size > 0
    with log_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        # Fill any missing columns with empty string
        complete_row = {col: row.get(col, "") for col in CSV_COLUMNS}
        writer.writerow(complete_row)


def load_all(log_path: Path = DEFAULT_LOG_PATH) -> pd.DataFrame:
    """Load the entire CSV into a DataFrame. Returns empty DataFrame if no data."""
    _ensure_paths(log_path=log_path)
    if not log_path.exists() or log_path.stat().st_size == 0:
        return pd.DataFrame(columns=CSV_COLUMNS)
    df = pd.read_csv(log_path, dtype=str)
    # Parse numeric columns
    numeric_cols = [
        "input_size_bytes", "input_size_kb", "input_entropy",
        "output_size_bytes", "output_size_kb", "output_entropy", "ciphertext_expansion_pct",
        "enc_time_ms", "dec_time_ms", "total_time_ms",
        "enc_ram_kb", "dec_ram_kb", "enc_throughput_kbps", "dec_throughput_kbps",
        "aes_key_entropy", "chacha_key_entropy", "sig_size_bits",
        "entropy_plaintext", "entropy_aes_half", "entropy_chacha_half", "entropy_final",
        "avalanche_pct", "avalanche_bits_flipped", "avalanche_total_bits", "avalanche_deviation",
        "byte_freq_std_dev", "chi_squared", "iteration", "sym_key_size_bits",
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "sig_valid" in df.columns:
        df["sig_valid"] = df["sig_valid"].map({"True": True, "False": False, "": None})
    return df


def export_csv(df: pd.DataFrame, file_name: str, export_dir: Path = DEFAULT_EXPORT_DIR) -> Path:
    """Export a DataFrame slice to a CSV file in the exports directory."""
    _ensure_paths(export_dir=export_dir)
    out_path = export_dir / file_name
    df.to_csv(out_path, index=False, encoding="utf-8")
    return out_path


def export_json(data: Any, file_name: str, export_dir: Path = DEFAULT_EXPORT_DIR) -> Path:
    """Export any serializable object as JSON."""
    import json
    _ensure_paths(export_dir=export_dir)
    out_path = export_dir / file_name
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return out_path


def clear_log(log_path: Path = DEFAULT_LOG_PATH) -> None:
    """Delete the CSV log (irreversible)."""
    if log_path.exists():
        log_path.unlink()
