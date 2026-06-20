"""CryptoLab v0.5 — Hybrid Encryption Research Dashboard."""

from __future__ import annotations

import streamlit as st

st.set_page_config(
    page_title="CryptoLab v0.5",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🔐 CryptoLab — Cryptographic Analysis Dashboard")
st.caption(
    "v0.5 · Local research tool · All operations logged to `logs/operations.jsonl`"
)

st.markdown("""
## Welcome to CryptoLab

A research-grade dashboard for analyzing cryptographic algorithms.
Use the **sidebar** to navigate:

| Page | Description |
|------|-------------|
| 🔬 **Encryption Lab** | Encrypt/decrypt with any algorithm + key size + signature. Full security analysis inline. |
| 🔑 **Key Generator** | Generate AES-GCM, ChaCha20-Poly1305, RSA, and ECDSA keys with configurable sizes. |
| ⚖️ **Algorithm Comparator** | Run all algorithms on the same input and compare side-by-side. |
| 🚀 **Batch Runner** | Benchmark multiple files × multiple algorithms automatically. |
| 📊 **Trend Analysis** | Research dashboard — charts, heatmaps, algorithm recommendations from logged data. |

---

### Algorithm Modes
- **AES-GCM** — Authenticated block cipher, 128/192/256-bit keys
- **ChaCha20-Poly1305** — Authenticated stream cipher, 256-bit key (fixed)
- **Hybrid** — AES-GCM + ChaCha20-Poly1305 combined, with optional RSA or ECDSA signature

### Key Size Security Equivalence (NIST)

| Security Level | AES-GCM | ChaCha20-Poly1305 | RSA | ECDSA |
|:-:|:-:|:-:|:-:|:-:|
| 128-bit | 128-bit key | — | 3072-bit | P-256 |
| 192-bit | 192-bit key | — | 7680-bit | P-384 |
| 256-bit | 256-bit key | 256-bit (fixed) | 15360-bit* | P-521 |

*RSA-15360 is impractical; RSA-4096 is the practical maximum.*
""")

st.info("🔒 Fully offline — no network access. All data stays on your machine.")
