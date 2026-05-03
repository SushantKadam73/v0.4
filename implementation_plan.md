# CryptoLab v0.4 — Full Restructure for Research-Grade Analysis

## Problem Statement

The current CryptoLab v0.4 has a foundation (AES-CBC, raw ChaCha20, Hybrid engines, 5 Streamlit pages), but cannot answer the core research question: **"Which algorithm/key-size combination is best in which situation?"**

### What's Changing

| Area | Current | New |
|------|---------|-----|
| AES | AES-256-CBC (no auth) | **AES-GCM** (AEAD) — supports 128/192/256-bit keys |
| ChaCha20 | Raw ChaCha20 (no auth) | **ChaCha20-Poly1305** (AEAD) — 256-bit key only |
| Key sizes | Hardcoded 256-bit | **User-selectable**: AES 128/192/256, ChaCha20 256, RSA 2048/3072/4096, ECDSA P-256/P-384/P-521 |
| Signature | Baked into Hybrid only | **Separate choice**: None, RSA, or ECDSA — applicable to any algorithm |
| Data store | JSONL (nested JSON) | **CSV** (flat columns) — easy export, pandas-native, Excel-compatible |
| Main page | Separate Encrypt/Decrypt + Security Analysis | **Unified Encryption Lab** — choose everything, run, get full analysis |
| Trend page | Basic line charts | **Research Trend Dashboard** — heatmaps, algorithm recommendations, CSV export |
| Avalanche | Never computed | **Auto-computed** on every encrypt operation |
| Iterations | Not supported | **User-selectable** (1–10) with mean ± std dev |
| Old data | 5 entries | **Discarded** — fresh start |

---

## Proposed Architecture

```
CryptoLab/
├── app.py                           # Entry point + home page
├── config.toml                      # Settings
├── requirements.txt
│
├── crypto/
│   ├── __init__.py
│   ├── aes_gcm_engine.py            # [NEW] AES-GCM (128/192/256)
│   ├── chacha20_poly_engine.py      # [NEW] ChaCha20-Poly1305 (256)
│   ├── hybrid_engine.py             # [REWRITE] uses new AEAD engines
│   ├── signature.py                 # [NEW] standalone RSA/ECDSA sign+verify
│   ├── key_generator.py             # [MODIFY] multi-size key generation
│   └── utils.py                     # [KEEP] hex helpers, byte utils
│
├── analysis/
│   ├── __init__.py
│   ├── entropy.py                   # [MODIFY] add byte_frequency_std_dev
│   ├── avalanche.py                 # [MODIFY] add auto-compute for any algo
│   ├── performance.py               # [MODIFY] add throughput, multi-iteration
│   └── security_metrics.py          # [MODIFY] add ciphertext expansion
│
├── storage/
│   ├── __init__.py
│   └── log_store.py                 # [REWRITE] CSV-based flat store
│
├── pages/
│   ├── 01_Encryption_Lab.py         # [NEW] unified workbench — THE main page
│   ├── 02_Key_Generator.py          # [MODIFY] multi-size support
│   ├── 03_Algorithm_Comparator.py   # [REWRITE] enriched, logs to CSV
│   ├── 04_Batch_Runner.py           # [NEW] bulk benchmarking
│   └── 05_Trend_Analysis.py         # [REWRITE] research dashboard
│
├── logs/
│   ├── operations.csv               # primary data store (flat)
│   └── exports/                     # per-run JSON/CSV exports
│
└── Docs/
    └── PRD.md
```

---

## Key Size & Security Level Reference

This table is shown in the UI when users pick key sizes, so they understand equivalences:

| Security Level | AES-GCM | ChaCha20-Poly1305 | RSA | ECDSA |
|:-:|:-:|:-:|:-:|:-:|
| **128-bit** | 128-bit key | — | 3072-bit key | P-256 |
| **192-bit** | 192-bit key | — | 7680-bit key | P-384 |
| **256-bit** | 256-bit key | 256-bit key (fixed) | 15360-bit key* | P-521 |

*\*RSA-15360 is impractical — we cap at RSA-4096 and note the security gap.*

---

## Proposed Changes

### Component 1: Crypto Engines (complete rewrite of encryption layer)

---

#### [NEW] [aes_gcm_engine.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/crypto/aes_gcm_engine.py)

Replaces `aes_engine.py`. Uses `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.

- **Key sizes**: 128, 192, 256 bits (user-selectable)
- **Nonce**: 12 bytes (GCM standard), randomly generated per encryption
- **Output format**: `nonce (12 bytes) + ciphertext + tag (16 bytes)`
- **Authentication**: Built-in — tampered ciphertext raises `InvalidTag` on decrypt
- Functions: `generate_key(bit_length)`, `encrypt(data, key)`, `decrypt(data, key)`, `name()`, `supported_key_sizes()`

#### [NEW] [chacha20_poly_engine.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/crypto/chacha20_poly_engine.py)

Replaces `chacha20_engine.py`. Uses `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.

- **Key size**: 256 bits only (protocol-fixed)
- **Nonce**: 12 bytes, randomly generated per encryption
- **Output format**: `nonce (12 bytes) + ciphertext + tag (16 bytes)`
- Functions: `generate_key()`, `encrypt(data, key)`, `decrypt(data, key)`, `name()`, `supported_key_sizes()`

#### [NEW] [signature.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/crypto/signature.py)

Standalone digital signature module — decoupled from hybrid engine so any algorithm can optionally sign.

- RSA signing/verification with configurable key sizes (2048, 3072, 4096)
- ECDSA signing/verification with configurable curves (P-256, P-384, P-521)
- Functions: `sign(data, private_pem, algorithm)`, `verify(data, signature, public_pem, algorithm)`, `generate_keypair(algorithm, key_size_or_curve)`

#### [REWRITE] [hybrid_engine.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/crypto/hybrid_engine.py)

- Uses the new `aes_gcm_engine` + `chacha20_poly_engine`
- Signature is now **optional** and uses the standalone `signature.py` module
- Key sizes are passed through: `aes_key_bits` parameter determines AES key size
- Wire format: `[4B sig_len][sig_bytes][4B c1_len][c1][c2]` (same structure, but c1/c2 now use AEAD)

#### [MODIFY] [key_generator.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/crypto/key_generator.py)

- `generate_symmetric_key(bit_length=256)` — supports 128, 192, 256
- `generate_rsa_keypair(key_size=2048)` — supports 2048, 3072, 4096
- `generate_ecdsa_keypair(curve="P-256")` — supports P-256, P-384, P-521

#### [DELETE] [aes_engine.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/crypto/aes_engine.py)

Replaced by `aes_gcm_engine.py`.

#### [DELETE] [chacha20_engine.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/crypto/chacha20_engine.py)

Replaced by `chacha20_poly_engine.py`.

---

### Component 2: Analysis Modules

---

#### [MODIFY] [entropy.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/analysis/entropy.py)

- Add `byte_frequency_std_dev(data: bytes) -> float` — std dev of 256-bin histogram. Ideal ciphertext → ~0 (perfectly uniform). High value → patterns remain.

#### [MODIFY] [avalanche.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/analysis/avalanche.py)

- Add `compute_avalanche(encrypt_fn, data, key) -> AvalancheResult` — given an encrypt function, data, and key:
  1. `c1 = encrypt_fn(data, key)`
  2. `data_flipped = flip_one_bit(data, 0)`
  3. `c2 = encrypt_fn(data_flipped, key)`
  4. Returns `AvalancheResult(bit_change_pct, bits_flipped, total_bits, deviation_from_ideal)`
- Works for any algorithm since it takes the encrypt function as a parameter

#### [MODIFY] [performance.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/analysis/performance.py)

- Add `throughput_kbps(data_size_bytes, elapsed_ms) -> float`
- Add `measure_multi(fn, *args, iterations=3) -> MultiResult` — runs N iterations, returns mean/std for time and RAM
- Use `psutil.Process().memory_info().rss` for more accurate RAM measurement (delta before/after)

#### [MODIFY] [security_metrics.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/analysis/security_metrics.py)

- Add `ciphertext_expansion_pct(input_bytes, output_bytes) -> float`
- Add `chi_squared_uniformity(data: bytes) -> float` — chi-squared test for byte uniformity (p-value; high p → good randomness)

---

### Component 3: Storage (CSV-based)

---

#### [REWRITE] [log_store.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/storage/log_store.py)

Complete rewrite to use CSV as primary data store.

**CSV Column Schema** (flat — no nesting):

```
id, timestamp, batch_id, iteration, operation, algorithm,
sym_key_size_bits, sig_algorithm, sig_key_size,
input_filename, input_extension, input_mime, input_size_bytes, input_size_kb, input_file_category, input_entropy,
output_filename, output_size_bytes, output_size_kb, output_entropy, ciphertext_expansion_pct,
enc_time_ms, dec_time_ms, total_time_ms, enc_ram_kb, dec_ram_kb, enc_throughput_kbps, dec_throughput_kbps,
aes_key_entropy, chacha_key_entropy, sig_size_bits, sig_valid,
entropy_plaintext, entropy_aes_half, entropy_chacha_half, entropy_final,
avalanche_pct, avalanche_bits_flipped, avalanche_total_bits, avalanche_deviation,
byte_freq_std_dev
```

- `append_row(row_dict)` — appends one row to `logs/operations.csv` (creates header if file is empty)
- `load_all() -> pd.DataFrame` — reads the CSV into a DataFrame
- `export_csv(df, name)` — exports filtered DataFrame
- `clear_log()` — deletes the CSV

---

### Component 4: Lab Core

---

#### [REWRITE] [lab_core.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/lab_core.py)

Major restructure to serve the new unified Encryption Lab page:

- **`EncryptionConfig`** dataclass — holds all user selections:
  - `algorithm`: `"aes_gcm"`, `"chacha20_poly1305"`, `"hybrid"`
  - `sym_key_size_bits`: 128/192/256
  - `sig_algorithm`: `None`, `"RSA"`, `"ECDSA"`
  - `sig_key_size`: RSA key size or ECDSA curve
  - `operation`: `"encrypt"`, `"decrypt"`, `"both"`
  - `iterations`: 1–10

- **`OperationResult`** dataclass — all metrics from one operation:
  - Enc/dec time, RAM, throughput
  - Entropy at each stage
  - Avalanche result
  - Ciphertext expansion
  - Byte frequency std dev
  - Signature validity and size

- **`run_operation(config, data, keys) -> OperationResult`** — the master function:
  1. Encrypts using selected algorithm + key size
  2. Decrypts (if operation is "decrypt" or "both")
  3. Auto-computes avalanche effect
  4. Computes all entropy stages
  5. Computes throughput, expansion, byte frequency
  6. Returns everything in one result object

- **`run_multi_iteration(config, data, keys, iterations) -> list[OperationResult]`** — runs N times, each result is a separate log row

- **`build_csv_row(config, data, result) -> dict`** — flattens result into CSV-compatible dict

- **`get_encrypt_fn(algorithm, key)`** — returns the appropriate encrypt function for avalanche computation

---

### Component 5: Streamlit Pages

---

#### [NEW] [01_Encryption_Lab.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/pages/01_Encryption_Lab.py)

**The primary research page.** Unified workflow:

**Step 1 — Key Size Selection**
- Show the NIST security equivalence table
- AES-GCM: radio buttons for 128 / 192 / 256 bit
- ChaCha20-Poly1305: locked at 256 bit (shown for reference)
- Visual indicator of equivalent security level

**Step 2 — Algorithm Selection**
- Radio: `AES-GCM` | `ChaCha20-Poly1305` | `Hybrid (AES-GCM + ChaCha20-Poly1305)`

**Step 3 — Digital Signature Selection**
- Radio: `None` | `RSA` | `ECDSA`
- If RSA: select key size (2048 / 3072 / 4096)
- If ECDSA: select curve (P-256 / P-384 / P-521)

**Step 4 — Input Selection**
- Radio: `Text Input` | `File Upload`
- File upload accepts any type
- Shows file metadata: name, size, MIME, category, natural entropy
- Text files: content preview. Images: thumbnail. Others: metadata only.

**Step 5 — Operation**
- Radio: `Encrypt` | `Decrypt` | `Both (Encrypt then Decrypt)`
- Iterations slider: 1–10 (default 1), with tooltip explaining averaging
- "Run" button

**Results Panel** (shown after run):

| Section | Content |
|---------|---------|
| **Performance** | Enc time, Dec time, Total time, Enc RAM, Dec RAM, Enc throughput (KB/s), Dec throughput (KB/s). If iterations > 1: mean ± std dev |
| **Entropy Pipeline** | 4-stage table: Plaintext → AES half → ChaCha half → Final. Each with value + label (Low/Medium/Good/Strong) + HEX preview |
| **Avalanche Effect** | % bits changed, deviation from ideal 50%, bit-difference heatmap |
| **Ciphertext Analysis** | Expansion %, byte frequency histogram, byte frequency std dev, chi-squared uniformity p-value |
| **Signature** | Algorithm, key size, size in bits, valid/invalid badge |
| **HEX Viewer** | First 256 bytes of ciphertext |
| **Download** | Output file (.enc or decrypted), operation JSON |
| **Log Entry** | Expandable JSON of the full log entry |

All results auto-logged to `logs/operations.csv`.

#### [DELETE] [01_Encrypt_Decrypt.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/pages/01_Encrypt_Decrypt.py)

Replaced by `01_Encryption_Lab.py`.

#### [DELETE] [04_Security_Analysis.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/pages/04_Security_Analysis.py)

Merged into `01_Encryption_Lab.py` — all analysis is now shown inline after each operation.

---

#### [MODIFY] [02_Key_Generator.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/pages/02_Key_Generator.py)

- Add key size selection for each type
- AES: dropdown for 128/192/256 bit
- RSA: dropdown for 2048/3072/4096
- ECDSA: dropdown for P-256/P-384/P-521
- Show entropy gauge for generated keys
- Show NIST security level for the chosen size
- Byte frequency chart of key bytes

---

#### [REWRITE] [03_Algorithm_Comparator.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/pages/03_Algorithm_Comparator.py)

- Run **all algorithm + key size combinations** on the same input
- Configurable iteration count
- Each run logged to CSV with a shared `batch_id`
- **Enriched comparison table** with ALL metrics:

| Algorithm | Key Size | Sig | Enc Time | Dec Time | Throughput | RAM | Expansion % | Avalanche % | Final Entropy | Byte Freq σ |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|

- **Charts**:
  - Grouped bar: enc time per algorithm × key size
  - Grouped bar: throughput per algorithm × key size
  - Radar/spider chart: normalized multi-metric comparison
  - Scatter: file size vs throughput (if multiple sizes tested)
  - Bar: ciphertext expansion comparison
  - Bar: avalanche % comparison (with 50% ideal line)

---

#### [NEW] [04_Batch_Runner.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/pages/04_Batch_Runner.py)

- Upload **multiple files** at once
- Checkboxes: which algorithms to test
- Checkboxes: which key sizes to test
- Checkboxes: which signatures to test
- Iterations slider
- Runs all combinations with progress bar
- All results logged to CSV with shared `batch_id`
- Summary table + downloadable CSV at the end

---

#### [REWRITE] [05_Trend_Analysis.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/pages/05_Trend_Analysis.py)

Replaces `05_Trend_Dashboard.py`. Reads from `logs/operations.csv`.

**Sidebar Filters:**
- Algorithm multi-select
- Key size multi-select
- Signature algorithm multi-select
- File category multi-select (text, document, image, audio, video, archive)
- Operation type (encrypt/decrypt/both)
- Date range picker
- File size range slider (KB)

**Analysis Panels:**

1. **Summary Statistics Table** — per-algorithm aggregated stats:
   | Algorithm | Key Size | Avg Enc Time | Avg Dec Time | Avg Throughput | Avg RAM | Avg Avalanche % | Avg Entropy | # Operations |
   |:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|

2. **Performance Charts:**
   - Line: Avg encryption time over time (per algorithm)
   - Line: Avg throughput over time
   - Scatter: File size (KB) vs encryption time (colored by algorithm)
   - Scatter: File size (KB) vs throughput (scaling behavior)
   - Box: Encryption time distribution per algorithm
   - Box: Throughput distribution per algorithm

3. **Security Charts:**
   - Heatmap: Algorithm × File Category → avg throughput (answers "which algo is best for which file type?")
   - Heatmap: Algorithm × Key Size → avg enc time (answers "how does key size affect speed?")
   - Box: Avalanche % distribution per algorithm (should cluster around 50%)
   - Box: Final entropy distribution per algorithm
   - Bar: Ciphertext expansion per algorithm
   - Bar: Byte frequency std dev per algorithm (lower = more uniform = better)

4. **Best Algorithm Recommendation Panel:**
   - For each file category, show which algorithm had: fastest enc time, best throughput, best avalanche, best entropy
   - Overall "winner" per category based on weighted score

5. **Raw Data Table** — paginated, sortable, with all columns

6. **Export:**
   - Download filtered data as CSV
   - Download filtered data as JSON
   - Clear log button (with confirmation)

#### [DELETE] [05_Trend_Dashboard.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/pages/05_Trend_Dashboard.py)

Replaced by `05_Trend_Analysis.py`.

---

### Component 6: Configuration & Dependencies

---

#### [MODIFY] [config.toml](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/config.toml)

```toml
[app]
name = "CryptoLab"
max_upload_mb = 200
log_path = "logs/operations.csv"
export_dir = "logs/exports"

[defaults]
iterations = 1
max_iterations = 10

[algorithms]
symmetric = ["aes_gcm", "chacha20_poly1305", "hybrid"]
signatures = ["RSA", "ECDSA"]
aes_key_sizes = [128, 192, 256]
rsa_key_sizes = [2048, 3072, 4096]
ecdsa_curves = ["P-256", "P-384", "P-521"]

[ui]
show_json_preview = true
hex_preview_bytes = 256
```

#### [MODIFY] [requirements.txt](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/requirements.txt)

```
streamlit>=1.35
pycryptodome
cryptography
plotly
pandas
psutil
scipy
```

> [!NOTE]
> Removed `python-magic` — using stdlib `mimetypes` instead (works cross-platform without system dependencies).

#### [MODIFY] [app.py](file:///c:/Users/susha/OneDrive/Desktop/Projects/Hybrid%20Cryptography/v0.4/app.py)

- Updated navigation description
- Shows version info
- Lists the 5 pages with descriptions

---

## Verification Plan

### Automated Tests

Run from project root after all changes:

1. **Encrypt/decrypt roundtrip** for each algorithm × each key size:
   - `AES-GCM` with 128, 192, 256-bit keys
   - `ChaCha20-Poly1305` with 256-bit key
   - `Hybrid` with each AES key size
   - Test with: empty bytes, 1 byte, 1 KB, 1 MB random data

2. **AEAD authentication test**: Tamper with 1 byte of ciphertext → verify `InvalidTag` raised

3. **Signature roundtrip**: Sign + verify with each RSA size and each ECDSA curve

4. **Avalanche sanity**: Verify 40% < avalanche < 60% for random data

5. **CSV logging**: Run an operation, verify CSV row has all expected columns

6. **Run `streamlit run app.py`** — verify no import errors, all pages load

### Manual Verification

1. Walk through Encryption Lab: select each algorithm, key size, signature, run encrypt+decrypt
2. Run Algorithm Comparator with a test file
3. Run Batch Runner with 3 files × all algorithms
4. Open Trend Analysis → verify charts populate with the test data
5. Export CSV from Trend Analysis → open in Excel, verify columns and data
