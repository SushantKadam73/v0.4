from __future__ import annotations

import json
from datetime import datetime, UTC
from pathlib import Path
from typing import Any


DEFAULT_LOG_PATH = Path("logs/operations.jsonl")
DEFAULT_EXPORT_DIR = Path("logs/exports")


def ensure_paths(log_path: Path = DEFAULT_LOG_PATH, export_dir: Path = DEFAULT_EXPORT_DIR) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    export_dir.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.touch()


def timestamp_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_entry(entry: dict[str, Any], log_path: Path = DEFAULT_LOG_PATH) -> None:
    ensure_paths(log_path=log_path)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def load_all(log_path: Path = DEFAULT_LOG_PATH) -> list[dict[str, Any]]:
    ensure_paths(log_path=log_path)
    rows: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def export_json(payload: dict[str, Any], file_name: str, export_dir: Path = DEFAULT_EXPORT_DIR) -> Path:
    ensure_paths(export_dir=export_dir)
    out_path = export_dir / file_name
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return out_path


def clear_log(log_path: Path = DEFAULT_LOG_PATH) -> None:
    ensure_paths(log_path=log_path)
    log_path.write_text("", encoding="utf-8")
