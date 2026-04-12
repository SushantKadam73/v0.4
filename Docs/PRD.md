# Product Requirements Document
## CryptoLab — Hybrid Encryption Analysis Dashboard
**Version:** 1.1  
**Date:** April 2026  
**Stack:** Python · Streamlit · JSON File Store

---

## 1. Overview

CryptoLab is a local, Python-based Streamlit dashboard that lets researchers and students encrypt/decrypt any type of file or plaintext using AES-256, ChaCha20-256, Hybrid+RSA, or Hybrid+ECDSA, then instantly analyze cryptographic metrics — entropy, performance, key security, and avalanche effect. Every operation is logged as a structured JSON entry appended to a flat `.jsonl` (JSON Lines) file on disk, enabling trend analysis without any database dependency.

---

## 2. Goals

| Goal | Description |
|------|-------------|
| **Encryption Workbench** | Encrypt/decrypt any file type or inline text using 4 algorithm modes |
| **Key Generator** | Generate and export AES, ChaCha20, ECDSA, and RSA keys |
| **Security Analysis** | Entropy per stage, HEX viewers, avalanche effect, signature validation |
| **Performance Profiling** | Encryption/decryption time (ms) and RAM usage (KB) per operation |
| **Algorithm Comparator** | Run all 4 algorithms on the same input and compare side-by-side |
| **Trend Analysis** | Load historical `.jsonl` log, render trend charts — no DB required |

---

## 3. Scope

**In Scope**
- 4 algorithm modes: AES-256, ChaCha20-256, Hybrid+RSA, Hybrid+ECDSA
- File upload: `.txt`, `.pdf`, `.docx`, `.mp3`, `.mp4`, `.png`, `.jpg`, `.csv`, `.zip`, and any binary format
- Inline text input for quick testing
- Key generation and download (`.key`, `.pem`)
- Per-operation JSON Lines logging to `logs/operations.jsonl`
- Trend charts loaded from the log file
- Entropy, HEX analysis, avalanche effect

**Out of Scope**
- Any database (SQLite, PostgreSQL, etc.)
- Network transmission or remote key exchange
- User authentication / multi-user sessions
- Production deployment (research/demo tool only)

---

## 4. Users

- Students and researchers working on hybrid cryptography projects
- Security professionals benchmarking algorithm trade-offs
- Anyone needing a visual testbench for AES, ChaCha20, and hybrid encryption

---

## 5. File Type Handling Strategy

All file types are treated as **raw bytes** by the encryption engines — the algorithm does not care what the file contains. The file type matters only for:

1. **Display** — text files show a plaintext preview; binary files (PDF, MP3, MP4) show only metadata (filename, size, MIME type) before encryption
2. **Entropy baseline** — different file types have different natural entropy levels, which is surfaced as context in the analysis panel

| Category | Extensions | Preview in UI |
|----------|-----------|---------------|
| Text | `.txt`, `.csv`, `.json`, `.xml`, `.md` | First 500 characters shown |
| Document | `.pdf`, `.docx`, `.pptx`, `.xlsx` | Filename + size only |
| Image | `.png`, `.jpg`, `.jpeg`, `.bmp`, `.gif` | Thumbnail shown |
| Audio | `.mp3`, `.wav`, `.aac`, `.flac` | Filename + size + duration if readable |
| Video | `.mp4`, `.mkv`, `.avi`, `.mov` | Filename + size only |
| Archive | `.zip`, `.tar`, `.gz` | Filename + size only |
| Other / Unknown | any other extension | Raw byte size shown |

**Upload limit:** 200 MB per file (configurable in `config.toml`).

> All files are read into memory as `bytes`, encrypted, and output as `.enc` binary files. Decryption reverses this and restores the original file extension.

---

## 6. Persistence Strategy — JSON Lines (No Database)

Every encrypt/decrypt operation appends **one JSON object** as a new line to `logs/operations.jsonl`. This file is the single source of truth for trend analysis.

### Why JSON Lines?
- Zero dependencies — plain file I/O with Python's `json` stdlib
- Human-readable and Git-friendly
- Easily loaded into `pandas` with `pd.read_json(..., lines=True)`
- Portable — copy the file anywhere to transfer history
- Appendable without loading the whole file

### File Layout

```
CryptoLab/
└── logs/
    ├── operations.jsonl          # append-only operation log
    └── exports/
        ├── op_20260412_143022.json   # per-operation sidecar (downloadable)
        └── comparison_20260412.json  # comparator run exports
```

### Single Log Entry Schema (one line in `operations.jsonl`)

```json
{
  "id": "op_20260412_143022_7f3a",
  "timestamp": "2026-04-12T14:30:22Z",
  "operation": "encrypt",
  "algorithm": "hybrid_ecdsa",
  "input": {
    "filename": "lecture_notes.pdf",
    "extension": ".pdf",
    "mime_type": "application/pdf",
    "size_kb": 498.0,
    "entropy_bits_per_byte": 6.21
  },
  "output": {
    "filename": "lecture_notes.pdf.enc",
    "size_kb": 499.3,
    "entropy_bits_per_byte": 7.98
  },
  "performance": {
    "enc_time_ms": 22.4,
    "dec_time_ms": 25.1,
    "enc_ram_kb": 318.0,
    "dec_ram_kb": 301.0
  },
  "keys": {
    "aes_key_size_bits": 256,
    "chacha20_key_size_bits": 256,
    "signature_algorithm": "ECDSA",
    "signature_size_bits": 512,
    "key_hex_preview": "3a7f9b2c1d..."
  },
  "security": {
    "entropy_stages": {
      "plaintext": 6.21,
      "ciphertext_aes_half": 7.95,
      "ciphertext_chacha20_half": 7.97,
      "final_combined_ciphertext": 7.98
    },
    "signature_valid": true,
    "avalanche_bit_change_pct": 49.8
  }
}
```

### Reading the Log for Trend Analysis

```python
import pandas as pd
import json

def load_log(path="logs/operations.jsonl") -> pd.DataFrame:
    rows = []
    with open(path) as f:
        for line in f:
            rows.append(json.loads(line))
    return pd.json_normalize(rows)   # flattens nested keys with dot notation
```

---

## 7. System Architecture

```
CryptoLab/
│
├── app.py                        # Streamlit entry point, page router
├── config.toml                   # Max upload size, log path, UI settings
│
├── crypto/
│   ├── aes_engine.py             # AES-256-CBC encrypt/decrypt
│   ├── chacha20_engine.py         # ChaCha20 stream-cipher encrypt/decrypt
│   ├── hybrid_engine.py          # Hybrid: split → AES+ChaCha20 → sign
│   ├── key_generator.py          # AES, ChaCha20, ECDSA, RSA key gen
│   └── utils.py                  # HEX dump, PKCS7 padding, byte helpers
│
├── analysis/
│   ├── entropy.py                # Shannon entropy on raw bytes
│   ├── avalanche.py              # 1-bit flip → ciphertext diff %
│   ├── performance.py            # time.perf_counter + tracemalloc wrapper
│   └── security_metrics.py       # Key entropy, signature size info
│
├── storage/
│   └── log_store.py              # append_entry(), load_all(), export_json()
│
├── pages/
│   ├── 01_Encrypt_Decrypt.py
│   ├── 02_Key_Generator.py
│   ├── 03_Algorithm_Comparator.py
│   ├── 04_Security_Analysis.py
│   └── 05_Trend_Dashboard.py
│
├── logs/
│   ├── operations.jsonl          # auto-created on first run
│   └── exports/                  # per-run JSON exports
│
└── requirements.txt
```

---

## 8. Pages & Features

### Page 1 — Encrypt / Decrypt Workbench

**Inputs**
- Input mode: `Text Input` | `File Upload` (any file type, up to 200 MB)
- Algorithm: `AES-256` | `ChaCha20-256` | `Hybrid + RSA` | `Hybrid + ECDSA`
- Key: Upload existing key file | Generate new key on the fly
- Mode: `Encrypt` | `Decrypt`

**File Upload Behavior**
- Text files → show content preview before encrypting
- Binary files (PDF, MP3, MP4, etc.) → show filename, size, MIME type, and natural entropy
- On encrypt → outputs `.enc` binary file (downloadable)
- On decrypt → restores original file with original extension (downloadable)

**Output Panels (shown after every run)**

| Panel | Content |
|-------|---------|
| Ciphertext Viewer | First 256 bytes as HEX dump, full file downloadable |
| Performance | Enc time (ms), Dec time (ms), RAM used (KB) |
| Entropy | Shannon entropy: plaintext → cipher half 1 → cipher half 2 → final |
| Signature | Signature size (bits), algorithm, pass/fail badge |
| Log Entry | Formatted JSON of this operation (expandable, downloadable) |

**Auto-logging:** Every run appends to `logs/operations.jsonl` automatically.

---

### Page 2 — Key Generator

**Inputs**
- Key type: `AES-256` | `ChaCha20-256` | `ECDSA (P-256)` | `RSA-2048`
- Optional seed (for reproducible test keys)

**Outputs**

| Key Type | What is shown | Download format |
|----------|--------------|-----------------|
| AES / ChaCha20 | 256-bit key in HEX, entropy score | `.key` binary |
| ECDSA | Private PEM + Public PEM | `.pem` files |
| RSA-2048 | Private PEM + Public PEM | `.pem` files |

**Info Panel:** Key size in bits, Shannon entropy of key bytes, flag if entropy < 7.0 (weak randomness warning).

---

### Page 3 — Algorithm Comparator

**Purpose:** Run all 4 algorithms on the same input in one click and compare.

**Inputs**
- Input mode: `Text Input` | `File Upload` | `Synthetic Test File`
- Synthetic file sizes: `150 KB` | `498 KB` | `750 KB` | `1012 KB` (random bytes generated in-memory — no disk write)

**Outputs**

Comparison table (auto-populated after run):

| Algorithm | Enc Time (ms) | Dec Time (ms) | Enc RAM (KB) | Dec RAM (KB) | Output Size (KB) | Sig Size (bits) | Final Entropy |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| AES-256 | | | | | | — | |
| ChaCha20-256 | | | | | | — | |
| Hybrid + RSA | | | | | | 2048 | |
| Hybrid + ECDSA | | | | | | 512 | |

**Charts (Plotly)**
1. Grouped bar: Encryption Time across 4 file sizes × 4 algorithms
2. Grouped bar: RAM Usage across 4 file sizes × 4 algorithms
3. Line: Output entropy vs input file type
4. Bar: Signature size — RSA vs ECDSA

**Export:** Download full comparison as a single `.json` file saved to `logs/exports/`.

---

### Page 4 — Security Analysis

#### 4a. Entropy Analyzer
- Upload any file or paste text
- Compute Shannon entropy at each pipeline stage:

| Stage | HEX Preview (first 64 bytes) | Entropy (bits/byte) |
|-------|------------------------------|---------------------|
| Plaintext / Raw Input | shown | computed |
| Ciphertext Half 1 (AES) | shown | computed |
| Ciphertext Half 2 (ChaCha20) | shown | computed |
| Final Combined Ciphertext | shown | computed |

- Byte frequency histogram (256-bar chart)
- Interpretation label: `< 4.0` Low · `4.0–6.5` Medium · `6.5–7.5` Good · `> 7.5` Strong

#### 4b. Key Security Viewer
- Upload or paste key bytes
- Full HEX representation
- Shannon entropy of key
- Weakness flags: all-zero key, low entropy (< 7.0), non-standard size

#### 4c. Avalanche Effect Tester
- Input plaintext → encrypt → flip 1 bit in plaintext → re-encrypt with same key
- Compare original vs modified ciphertext bit-by-bit
- Outputs: % bits changed (ideal ≈ 50%), bit-difference heatmap
- Runs for whichever algorithm is selected

#### 4d. Signature Verification
- Upload signed `.enc` file + corresponding public key (`.pem`)
- Verify and display: VALID ✅ or INVALID ❌
- Show signature bytes in HEX

---

### Page 5 — Trend Dashboard

**Data source:** `logs/operations.jsonl` — loaded fresh on each page visit.

**Filters (sidebar)**
- Algorithm multi-select
- Date range picker
- File type filter (text, image, audio, video, document, other)
- Operation type: Encrypt | Decrypt | Both

**Charts**
1. Line: Average encryption time over time (per algorithm)
2. Line: Average RAM usage over time
3. Scatter: File size (KB) vs Encryption time (ms)
4. Bar: Number of operations by algorithm
5. Box plot: Final ciphertext entropy distribution per algorithm
6. Bar: Average enc time by file type (txt, pdf, mp3, mp4, etc.)

**Data Table**
Paginated log of all operations: timestamp, algorithm, file type, size (KB), enc time, dec time, RAM, entropy, signature valid.

**Export Options**
- Download filtered view as `.csv`
- Download filtered view as `.json`
- Clear log (with confirmation dialog — irreversible)

---

## 9. Algorithm Specifications

### AES-256
- Library: `pycryptodome` → `Crypto.Cipher.AES`
- Mode: CBC with random IV prepended to ciphertext
- Key: 256 bits (32 bytes), PKCS7 padding

### ChaCha20-256
- Library: `cryptography` (`algorithms.ChaCha20`)
- Mode: stream cipher with random 16-byte nonce prepended to ciphertext
- Key: 256 bits (32 bytes), no padding required

### Hybrid Encryption (AES + ChaCha20 + Digital Signature)

**Encrypt**
```
plaintext bytes
    ├── first half  → AES-256-CBC  → cipher_block_1
    └── second half → ChaCha20 encrypt → cipher_block_2

combined = cipher_block_1 + cipher_block_2
hash     = SHA-256(combined)
sig      = ECDSA_sign(hash, private_key)   ← OR RSA_sign(hash, private_key)

output = [4-byte sig length] + [sig bytes] + [combined ciphertext]
```

**Decrypt**
```
input
    ├── read 4-byte sig length header
    ├── extract sig bytes
    └── extract combined ciphertext

verify SHA-256(combined ciphertext) against sig using public key
    → FAIL: raise IntegrityError, abort
    → PASS: continue

split combined ciphertext at midpoint
    ├── AES-256-CBC decrypt → first_half
    └── ChaCha20 decrypt → second_half

plaintext = first_half + second_half
```

### Key Generation
| Key | Method |
|-----|--------|
| AES / ChaCha20 | `os.urandom(32)` |
| ECDSA | `cryptography` · `ec.generate_private_key(ec.SECP256R1())` |
| RSA-2048 | `cryptography` · `rsa.generate_private_key(e=65537, key_size=2048)` |

---

## 10. Metrics Definitions

| Metric | Definition | Implementation |
|--------|------------|----------------|
| Encryption Time | Wall-clock from bytes-in to ciphertext-out | `time.perf_counter()` |
| Decryption Time | Wall-clock from ciphertext-in to plaintext-out | `time.perf_counter()` |
| RAM Usage | Peak memory delta during operation | `tracemalloc` |
| Shannon Entropy | H = −Σ p(x) log₂ p(x) over byte frequencies | `analysis/entropy.py` |
| Avalanche Effect | % of ciphertext bits changed when 1 input bit is flipped | XOR + bit count |
| Key Entropy | Shannon entropy of key byte sequence (ideal ≈ 8.0) | `analysis/entropy.py` |
| Signature Size | `len(signature_bytes) × 8` bits | direct |
| Ciphertext Expansion | `(output_size − input_size) / input_size × 100` % | direct |

---

## 11. Tech Stack

| Component | Library |
|-----------|---------|
| UI | `streamlit >= 1.35` |
| AES | `pycryptodome` |
| ChaCha20 | `cryptography` |
| ECDSA / RSA | `cryptography` |
| Hashing | `hashlib` (stdlib) |
| Profiling | `time`, `tracemalloc` (stdlib) |
| Charts | `plotly` |
| Data Loading | `pandas` |
| Persistence | `json`, plain file I/O (stdlib — no DB) |
| MIME detection | `python-magic` or `mimetypes` (stdlib) |

**Install:**
```bash
pip install streamlit pycryptodome cryptography plotly pandas python-magic
streamlit run app.py
```

---

## 12. Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| File upload size | Up to 200 MB |
| Supported file types | Any (treated as raw bytes) |
| Encryption of 10 MB file | < 2 s on a standard laptop |
| Log file growth | ~1 KB per operation; 10,000 ops ≈ 10 MB |
| No external services | Fully offline, no internet required |
| Portability | Works on Windows, macOS, Linux with Python 3.10+ |

---

## 13. Future Scope (v2.0 Hooks)

| Feature | Where to add |
|---------|--------------|
| Differential / frequency attack analysis | New tab in Page 4 |
| Alternate block interleaving (AES/ChaCha20 segments alternating) | `hybrid_engine.py` new mode |
| Swap in ChaChaPoly20, Blowfish, Keccak | New engine files in `crypto/`, plug into comparator |
| Batch file encryption (folder upload) | New option in Page 1 |
| Log viewer with search | Extend Page 5 |

---

## 14. Development Phases

| Phase | Deliverable | Est. Effort |
|-------|-------------|-------------|
| 1 | `crypto/` engines: AES, ChaCha20, Hybrid + Key Gen | 2 days |
| 2 | `analysis/` modules: entropy, avalanche, performance | 1 day |
| 3 | `storage/log_store.py` + JSON Lines append/read | 0.5 days |
| 4 | Page 1: Workbench (all file types, all algorithms) | 1.5 days |
| 5 | Page 3: Comparator + charts | 1 day |
| 6 | Page 4: Security Analysis (entropy, avalanche, HEX) | 1.5 days |
| 7 | Page 2: Key Generator + Page 5: Trend Dashboard | 1 day |
| 8 | Error handling, edge cases, README | 0.5 days |

**Total: ~9 days solo**

---

*End of PRD — CryptoLab v1.1*

