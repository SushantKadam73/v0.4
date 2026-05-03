"""Page 4 — Batch Runner

Upload multiple files, select algorithm combinations, run automated benchmarks.
All results are logged to CSV with a shared batch_id.
"""
from __future__ import annotations

import os

import pandas as pd
import plotly.express as px
import streamlit as st

from crypto.key_generator import generate_ecdsa_keypair, generate_rsa_keypair, generate_symmetric_key
from lab_core import (
    ALGORITHM_DISPLAY,
    EncryptionConfig,
    batch_id,
    build_and_log_row,
    run_operation,
)

st.set_page_config(page_title="Batch Runner — CryptoLab", layout="wide")
st.title("🚀 Batch Runner")
st.caption("Benchmark multiple files × multiple algorithm combinations automatically.")

# ─────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────
st.header("Batch Configuration", divider="blue")

col_a, col_b = st.columns(2)

with col_a:
    st.subheader("Upload Files")
    uploaded_files = st.file_uploader(
        "Upload one or more files",
        accept_multiple_files=True,
        help="Each file will be tested against all selected algorithm combinations.",
    )

    st.subheader("Synthetic Files (optional)")
    use_synthetic = st.checkbox("Add synthetic test files")
    synth_sizes = []
    if use_synthetic:
        synth_options = st.multiselect(
            "Synthetic sizes",
            ["10 KB", "50 KB", "100 KB", "500 KB", "1 MB"],
            default=["50 KB"],
        )
        size_map = {"10 KB": 10, "50 KB": 50, "100 KB": 100, "500 KB": 500, "1 MB": 1024}
        synth_sizes = [(f"synthetic_{size_map[s]}kb.bin", size_map[s] * 1024) for s in synth_options]

with col_b:
    st.subheader("Algorithms")
    run_aes128 = st.checkbox("AES-GCM 128-bit", value=True)
    run_aes256 = st.checkbox("AES-GCM 256-bit", value=True)
    run_chacha = st.checkbox("ChaCha20-Poly1305 (256-bit)", value=True)
    run_hybrid = st.checkbox("Hybrid (AES-GCM 256 + ChaCha20)", value=True)

    st.subheader("Signatures")
    sig_none = st.checkbox("No Signature", value=True)
    sig_rsa = st.checkbox("RSA-2048", value=False)
    sig_ecdsa = st.checkbox("ECDSA-P256", value=False)

    iterations = st.slider("Iterations per combination", 1, 5, 1)

# ─────────────────────────────────────────────────────────
# BUILD BATCH MATRIX
# ─────────────────────────────────────────────────────────
combos: list[dict] = []
for algo, bits, enabled in [
    ("aes_gcm", 128, run_aes128),
    ("aes_gcm", 256, run_aes256),
    ("chacha20_poly1305", 256, run_chacha),
    ("hybrid", 256, run_hybrid),
]:
    if not enabled:
        continue
    for sig, sig_param, sig_enabled in [
        (None, "", sig_none),
        ("RSA", "2048", sig_rsa),
        ("ECDSA", "P-256", sig_ecdsa),
    ]:
        if sig_enabled:
            combos.append({"algorithm": algo, "bits": bits, "sig": sig, "sig_param": sig_param})

total_files = len(uploaded_files) + len(synth_sizes)
total_runs = total_files * len(combos) * iterations

st.metric("Total Runs", f"{total_runs}", help=f"{total_files} files × {len(combos)} combos × {iterations} iterations")

if total_runs == 0:
    st.info("Select at least one file and one algorithm combination.")

# ─────────────────────────────────────────────────────────
# EXECUTE BATCH
# ─────────────────────────────────────────────────────────
if st.button("▶ Start Batch", type="primary", disabled=total_runs == 0):
    # Generate shared keys for the batch
    with st.spinner("Generating keys…"):
        keys = {
            "aes_128": generate_symmetric_key(128),
            "aes_256": generate_symmetric_key(256),
            "chacha": generate_symmetric_key(256),
        }
        keys["rsa_priv"], keys["rsa_pub"] = generate_rsa_keypair(2048)
        keys["ecdsa_priv"], keys["ecdsa_pub"] = generate_ecdsa_keypair("P-256")

    bid = batch_id()
    rows_out: list[dict] = []
    progress = st.progress(0, text="Starting batch…")
    run_count = 0

    # Collect all (name, bytes) pairs
    all_files: list[tuple[str, bytes]] = []
    for uf in uploaded_files:
        all_files.append((uf.name, uf.read()))
    for synth_name, synth_size in synth_sizes:
        all_files.append((synth_name, os.urandom(synth_size)))

    for fname, fdata in all_files:
        for combo in combos:
            algo = combo["algorithm"]
            bits = combo["bits"]
            sig = combo["sig"]
            sig_param = combo["sig_param"]

            aes_key = keys[f"aes_{bits}" if algo != "chacha20_poly1305" else "aes_256"]
            chacha_key = keys["chacha"]
            priv = keys["rsa_priv"] if sig == "RSA" else (keys["ecdsa_priv"] if sig == "ECDSA" else None)
            pub = keys["rsa_pub"] if sig == "RSA" else (keys["ecdsa_pub"] if sig == "ECDSA" else None)

            config = EncryptionConfig(
                algorithm=algo,
                sym_key_size_bits=bits,
                sig_algorithm=sig,
                sig_key_param=sig_param,
                operation="both",
                iterations=iterations,
            )

            for it in range(1, iterations + 1):
                result = run_operation(config, fdata, aes_key, chacha_key, priv, pub)
                run_count += 1
                progress.progress(
                    run_count / total_runs,
                    text=f"[{run_count}/{total_runs}] {fname} | {ALGORITHM_DISPLAY[algo]} | iter {it}",
                )

                label = f"{ALGORITHM_DISPLAY[algo]} ({bits}b" + (f" +{sig}" if sig else "") + ")"
                row_dict = {
                    "file": fname,
                    "algorithm": ALGORITHM_DISPLAY[algo],
                    "key_size": f"{bits}-bit",
                    "signature": sig or "None",
                    "iteration": it,
                    "enc_time_ms": round(result.enc_time_ms, 3),
                    "dec_time_ms": round(result.dec_time_ms, 3),
                    "enc_ram_kb": round(result.enc_ram_kb, 2),
                    "enc_throughput_kbps": round(result.enc_throughput_kbps, 1),
                    "avalanche_pct": round(result.avalanche.bit_change_pct, 2) if result.avalanche else None,
                    "final_entropy": round(result.entropy_final, 4),
                    "expansion_pct": round(result.ciphertext_expansion_pct, 4),
                    "status": "Error: " + result.error if result.error else "OK",
                }
                rows_out.append(row_dict)

                if not result.error:
                    build_and_log_row(config, fname, fdata, fname + ".enc", result, bid, it)

    progress.empty()
    st.success(f"✅ Batch complete! {run_count} runs. Batch ID: `{bid}`")

    df = pd.DataFrame(rows_out)
    st.session_state["last_batch_df"] = df
    st.session_state["last_batch_bid"] = bid

# ─────────────────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────────────────
if "last_batch_df" in st.session_state:
    df = st.session_state["last_batch_df"]
    bid = st.session_state.get("last_batch_bid", "")
    st.header("📊 Batch Results", divider="green")

    ok_df = df[df["status"] == "OK"]

    st.dataframe(df, use_container_width=True)

    if not ok_df.empty:
        tab1, tab2, tab3 = st.tabs(["⚡ Timing", "💾 Throughput", "💥 Avalanche"])
        with tab1:
            fig = px.box(ok_df, x="algorithm", y="enc_time_ms", color="signature",
                         title="Encryption Time Distribution per Algorithm")
            fig.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

        with tab2:
            fig = px.box(ok_df, x="algorithm", y="enc_throughput_kbps", color="key_size",
                         title="Throughput Distribution per Algorithm")
            fig.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

        with tab3:
            ava_df = ok_df.dropna(subset=["avalanche_pct"])
            if not ava_df.empty:
                fig = px.box(ava_df, x="algorithm", y="avalanche_pct", color="signature",
                             title="Avalanche Effect Distribution (ideal = 50%)")
                fig.add_hline(y=50, line_dash="dash", line_color="green", annotation_text="Ideal 50%")
                fig.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
                st.plotly_chart(fig, use_container_width=True)

    st.download_button(
        "⬇️ Download Batch Results (CSV)",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name=f"batch_{bid}.csv",
        mime="text/csv",
    )
