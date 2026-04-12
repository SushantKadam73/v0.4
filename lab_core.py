from __future__ import annotations

import json
import mimetypes
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

import tomllib

from analysis.entropy import shannon_entropy
from analysis.performance import measure_operation
from analysis.security_metrics import signature_size_bits
from crypto import aes_engine, chacha20_engine, hybrid_engine
from crypto.key_generator import generate_ecdsa_keypair, generate_rsa_keypair, generate_symmetric_key
from crypto.utils import hex_preview
from storage.log_store import append_entry, export_json


CHACHA20_AVAILABLE = chacha20_engine.is_available()


@dataclass
class OperationArtifacts:
    payload: bytes
    restored: bytes
    enc_time_ms: float
    dec_time_ms: float
    enc_ram_kb: float
    dec_ram_kb: float
    signature_valid: bool
    signature_size_bits: int
    signature_algorithm: str | None


def load_config() -> dict[str, Any]:
    with open("config.toml", "rb") as f:
        return tomllib.load(f)


def op_id() -> str:
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"op_{ts}_{uuid.uuid4().hex[:4]}"


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_meta(file_name: str, data: bytes) -> dict[str, Any]:
    ext = Path(file_name).suffix.lower()
    mime = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
    return {
        "filename": file_name,
        "extension": ext,
        "mime_type": mime,
        "size_kb": round(len(data) / 1024.0, 3),
        "entropy_bits_per_byte": round(shannon_entropy(data), 4),
    }


def run_algorithm(
    algorithm: str,
    data: bytes,
    *,
    aes_key: bytes,
    chacha20_key: bytes,
    private_pem: bytes | None,
    public_pem: bytes | None,
) -> OperationArtifacts:
    if algorithm == "aes_256":
        enc_payload, enc_time, enc_ram = measure_operation(aes_engine.encrypt, data, aes_key)
        restored, dec_time, dec_ram = measure_operation(aes_engine.decrypt, enc_payload, aes_key)
        return OperationArtifacts(enc_payload, restored, enc_time, dec_time, enc_ram, dec_ram, True, 0, None)

    if algorithm == "chacha20_256":
        if not CHACHA20_AVAILABLE:
            raise ValueError("ChaCha20 is unavailable in this environment")
        enc_payload, enc_time, enc_ram = measure_operation(chacha20_engine.encrypt, data, chacha20_key)
        restored, dec_time, dec_ram = measure_operation(chacha20_engine.decrypt, enc_payload, chacha20_key)
        return OperationArtifacts(enc_payload, restored, enc_time, dec_time, enc_ram, dec_ram, True, 0, None)

    if algorithm == "hybrid_rsa":
        if not CHACHA20_AVAILABLE:
            raise ValueError("Hybrid modes are unavailable because ChaCha20 is unavailable")
        if not private_pem or not public_pem:
            raise ValueError("Hybrid RSA requires private and public keys")
        enc_payload, enc_time, enc_ram = measure_operation(
            hybrid_engine.encrypt, data, aes_key, chacha20_key, private_pem, "RSA"
        )
        dec_result, dec_time, dec_ram = measure_operation(
            hybrid_engine.decrypt, enc_payload, aes_key, chacha20_key, public_pem, "RSA"
        )
        return OperationArtifacts(
            enc_payload,
            dec_result.plaintext,
            enc_time,
            dec_time,
            enc_ram,
            dec_ram,
            dec_result.signature_valid,
            signature_size_bits(dec_result.signature_bytes),
            "RSA",
        )

    if algorithm == "hybrid_ecdsa":
        if not CHACHA20_AVAILABLE:
            raise ValueError("Hybrid modes are unavailable because ChaCha20 is unavailable")
        if not private_pem or not public_pem:
            raise ValueError("Hybrid ECDSA requires private and public keys")
        enc_payload, enc_time, enc_ram = measure_operation(
            hybrid_engine.encrypt, data, aes_key, chacha20_key, private_pem, "ECDSA"
        )
        dec_result, dec_time, dec_ram = measure_operation(
            hybrid_engine.decrypt, enc_payload, aes_key, chacha20_key, public_pem, "ECDSA"
        )
        return OperationArtifacts(
            enc_payload,
            dec_result.plaintext,
            enc_time,
            dec_time,
            enc_ram,
            dec_ram,
            dec_result.signature_valid,
            signature_size_bits(dec_result.signature_bytes),
            "ECDSA",
        )

    raise ValueError("Unsupported algorithm")


def build_log_entry(
    operation: str,
    algorithm: str,
    input_name: str,
    input_data: bytes,
    output_name: str,
    output_data: bytes,
    artifacts: OperationArtifacts,
) -> dict[str, Any]:
    input_meta = file_meta(input_name, input_data)
    output_meta = file_meta(output_name, output_data)

    midpoint = len(input_data) // 2
    aes_half = input_data[:midpoint]
    chacha20_half = input_data[midpoint:]

    entry: dict[str, Any] = {
        "id": op_id(),
        "timestamp": now_iso(),
        "operation": operation,
        "algorithm": algorithm,
        "input": input_meta,
        "output": output_meta,
        "performance": {
            "enc_time_ms": round(artifacts.enc_time_ms, 3),
            "dec_time_ms": round(artifacts.dec_time_ms, 3),
            "enc_ram_kb": round(artifacts.enc_ram_kb, 3),
            "dec_ram_kb": round(artifacts.dec_ram_kb, 3),
        },
        "keys": {
            "aes_key_size_bits": 256,
            "chacha20_key_size_bits": 256,
            "signature_algorithm": artifacts.signature_algorithm,
            "signature_size_bits": artifacts.signature_size_bits,
            "key_hex_preview": "generated_runtime",
        },
        "security": {
            "entropy_stages": {
                "plaintext": round(shannon_entropy(input_data), 4),
                "ciphertext_aes_half": round(shannon_entropy(aes_half), 4),
                "ciphertext_chacha20_half": round(shannon_entropy(chacha20_half), 4),
                "final_combined_ciphertext": round(shannon_entropy(output_data), 4),
            },
            "signature_valid": artifacts.signature_valid,
            "avalanche_bit_change_pct": None,
        },
    }
    return entry


def persist_operation(entry: dict[str, Any]) -> Path:
    append_entry(entry)
    export_name = f"{entry['id']}.json"
    return export_json(entry, export_name)


def default_runtime_keys() -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    aes_key = generate_symmetric_key()
    chacha20_key = generate_symmetric_key()
    ecdsa = generate_ecdsa_keypair()
    rsa_pair = generate_rsa_keypair()
    return (
        aes_key,
        chacha20_key,
        ecdsa.private_pem,
        ecdsa.public_pem,
        rsa_pair.private_pem,
        rsa_pair.public_pem,
    )


def encode_json_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, indent=2).encode("utf-8")


def to_hex_preview(data: bytes, max_bytes: int = 256) -> str:
    return hex_preview(data, max_bytes=max_bytes)


def classify_extension(ext: str) -> str:
    text_ext = {".txt", ".csv", ".json", ".xml", ".md"}
    doc_ext = {".pdf", ".docx", ".pptx", ".xlsx"}
    img_ext = {".png", ".jpg", ".jpeg", ".bmp", ".gif"}
    aud_ext = {".mp3", ".wav", ".aac", ".flac"}
    vid_ext = {".mp4", ".mkv", ".avi", ".mov"}
    arc_ext = {".zip", ".tar", ".gz"}

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
