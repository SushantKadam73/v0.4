"""Page 3 — Algorithm Comparator

Run all algorithm × key size combinations on the same input and compare side-by-side.
All runs are logged to CSV with a shared batch_id.
"""
from __future__ import annotations

import os

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from analysis.entropy import shannon_entropy
from crypto.key_generator import generate_ecdsa_keypair, generate_rsa_keypair, generate_symmetric_key
from lab_core import (
    ALGORITHM_DISPLAY,
    EncryptionConfig,
    OperationResult,
    batch_id,
    build_and_log_row,
    file_category,
    run_operation,
)

st.set_page_config(page_title="Algorithm Comparator — CryptoLab", layout="wide")
st.title("⚖️ Algorithm Comparator")
st.caption("Run all algorithms on the same input — compare performance, entropy, and security side-by-side.")

# ─────────────────────────────────────────────────────────
# INPUT SELECTION
# ─────────────────────────────────────────────────────────
st.header("Input", divider="blue")

input_mode = st.selectbox("Input Mode", ["Text Input", "File Upload", "Synthetic Test Data"])
input_data = b""
input_name = "input.bin"

if input_mode == "Text Input":
    txt = st.text_area("Input Text", height=120)
    input_data = txt.encode("utf-8")
    input_name = "inline.txt"
elif input_mode == "File Upload":
    up = st.file_uploader("Upload a file", key="comp_file")
    if up:
        input_data = up.read()
        input_name = up.name
else:
    size_options = {"10 KB": 10, "50 KB": 50, "100 KB": 100, "250 KB": 250, "500 KB": 500, "1 MB": 1024}
    size_label = st.selectbox("Synthetic Size", list(size_options.keys()))
    size_kb = size_options[size_label]
    input_data = os.urandom(size_kb * 1024)
    input_name = f"synthetic_{size_kb}kb.bin"
    st.caption(f"Random bytes: {size_kb} KB — entropy ≈ 8.0 bits/byte")

# ─────────────────────────────────────────────────────────
# COMPARISON CONFIGURATION
# ─────────────────────────────────────────────────────────
st.header("Comparison Settings", divider="blue")

col_cfg1, col_cfg2 = st.columns(2)
with col_cfg1:
    st.subheader("Algorithms to Test")
    run_aes = st.checkbox("AES-GCM", value=True)
    run_chacha = st.checkbox("ChaCha20-Poly1305", value=True)
    run_hybrid = st.checkbox("Hybrid (AES-GCM + ChaCha20-Poly1305)", value=True)

    st.subheader("Key Sizes (AES-GCM)")
    test_128 = st.checkbox("128-bit", value=True)
    test_192 = st.checkbox("192-bit", value=False)
    test_256 = st.checkbox("256-bit", value=True)

with col_cfg2:
    st.subheader("Signature")
    run_no_sig = st.checkbox("No Signature", value=True)
    run_rsa = st.checkbox("RSA-2048 Signature", value=True)
    run_ecdsa = st.checkbox("ECDSA-P256 Signature", value=True)

    iterations = st.slider("Iterations per combination", 1, 5, 1,
                           help="Run each combination N times and use the mean.")

# ─────────────────────────────────────────────────────────
# BUILD COMPARISON MATRIX
# ─────────────────────────────────────────────────────────
if st.button("▶ Run Comparison", type="primary", disabled=not input_data):
    if not input_data:
        st.error("Provide input first.")
        st.stop()

    # Build test matrix
    combos: list[dict] = []
    aes_sizes = [s for s, enabled in [(128, test_128), (192, test_192), (256, test_256)] if enabled]
    algos = [a for a, e in [("aes_gcm", run_aes), ("chacha20_poly1305", run_chacha), ("hybrid", run_hybrid)] if e]
    sigs = [s for s, e in [(None, run_no_sig), ("RSA", run_rsa), ("ECDSA", run_ecdsa)] if e]

    for algo in algos:
        for key_bits in (aes_sizes if algo in ("aes_gcm", "hybrid") else [256]):
            for sig in sigs:
                if algo == "chacha20_poly1305" and key_bits != 256:
                    continue
                combos.append({
                    "algorithm": algo,
                    "sym_key_size_bits": key_bits,
                    "sig_algorithm": sig,
                    "sig_key_param": "2048" if sig == "RSA" else "P-256",
                })

    if not combos:
        st.warning("No algorithm combinations selected.")
        st.stop()

    # Pre-generate keys
    with st.spinner("Generating keys…"):
        keys: dict = {}
        for bits in [128, 192, 256]:
            keys[f"aes_{bits}"] = generate_symmetric_key(bits)
        keys["chacha"] = generate_symmetric_key(256)
        keys["rsa_priv"], keys["rsa_pub"] = generate_rsa_keypair(2048)
        keys["ecdsa_priv"], keys["ecdsa_pub"] = generate_ecdsa_keypair("P-256")

    bid = batch_id()
    rows_data: list[dict] = []

    total = len(combos)
    prog = st.progress(0, text="Running comparison…")

    for i, combo in enumerate(combos):
        algo = combo["algorithm"]
        bits = combo["sym_key_size_bits"]
        sig = combo["sig_algorithm"]
        sig_param = combo["sig_key_param"]

        aes_key = keys[f"aes_{bits}"]
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

        result = run_operation(config, input_data, aes_key, chacha_key, priv, pub)

        label_parts = [ALGORITHM_DISPLAY[algo], f"{bits}b"]
        if sig:
            label_parts.append(f"+{sig}")
        label = " | ".join(label_parts)

        row = {
            "Label": label,
            "Algorithm": ALGORITHM_DISPLAY[algo],
            "Key Size": f"{bits}-bit",
            "Signature": sig or "None",
            "Enc Time (ms)": round(result.enc_time_ms, 3),
            "Dec Time (ms)": round(result.dec_time_ms, 3),
            "Total Time (ms)": round(result.enc_time_ms + result.dec_time_ms, 3),
            "Enc RAM (KB)": round(result.enc_ram_kb, 2),
            "Throughput (KB/s)": round(result.enc_throughput_kbps, 1),
            "Expansion (%)": round(result.ciphertext_expansion_pct, 4),
            "Avalanche (%)": round(result.avalanche.bit_change_pct, 2) if result.avalanche else None,
            "Final Entropy": round(result.entropy_final, 4),
            "Byte Freq σ": round(result.byte_freq_std_dev, 4),
            "χ² Statistic": round(result.chi_squared, 2),
            "Sig Size (bits)": result.sig_size_bits or None,
            "Status": "Error: " + result.error if result.error else "OK",
        }
        rows_data.append(row)

        if not result.error:
            build_and_log_row(config, input_name, input_data, input_name + ".enc", result, bid, i + 1)

        prog.progress((i + 1) / total, text=f"Completed {i + 1}/{total}: {label}")

    prog.empty()
    st.success(f"✅ Comparison complete — {len(combos)} combinations tested | batch_id: `{bid}`")

    df = pd.DataFrame(rows_data)

    # ── RESULTS TABLE ────────────────────────────────────
    st.header("📋 Comparison Table", divider="green")
    st.dataframe(df, use_container_width=True)

    # ── CHARTS ───────────────────────────────────────────
    st.header("📊 Charts", divider="green")
    ok_df = df[df["Status"] == "OK"].copy()

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "⚡ Time", "💾 RAM & Throughput", "📈 Entropy", "💥 Avalanche", "🔬 Expansion", "🕸 Radar"
    ])

    with tab1:
        fig_t = go.Figure()
        fig_t.add_trace(go.Bar(name="Enc Time (ms)", x=ok_df["Label"], y=ok_df["Enc Time (ms)"], marker_color="#4e8df5"))
        fig_t.add_trace(go.Bar(name="Dec Time (ms)", x=ok_df["Label"], y=ok_df["Dec Time (ms)"], marker_color="#f5a44e"))
        fig_t.update_layout(barmode="group", title="Encryption vs Decryption Time",
                            xaxis_tickangle=-30, plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(fig_t, use_container_width=True)

    with tab2:
        fig_r = px.bar(ok_df, x="Label", y="Enc RAM (KB)", title="Encryption RAM Usage",
                       color="Algorithm", barmode="group")
        fig_tp = px.bar(ok_df, x="Label", y="Throughput (KB/s)", title="Encryption Throughput",
                        color="Algorithm", barmode="group")
        for f in [fig_r, fig_tp]:
            f.update_layout(xaxis_tickangle=-30, plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(fig_r, use_container_width=True)
        st.plotly_chart(fig_tp, use_container_width=True)

    with tab3:
        fig_e = px.bar(ok_df, x="Label", y="Final Entropy", title="Final Ciphertext Entropy",
                       color="Algorithm", barmode="group", range_y=[7.5, 8.1])
        fig_e.add_hline(y=8.0, line_dash="dash", line_color="green", annotation_text="Max (8.0)")
        fig_e.update_layout(xaxis_tickangle=-30, plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(fig_e, use_container_width=True)

    with tab4:
        ava_df = ok_df.dropna(subset=["Avalanche (%)"])
        if not ava_df.empty:
            fig_av = px.bar(ava_df, x="Label", y="Avalanche (%)", title="Avalanche Effect (ideal = 50%)",
                            color="Algorithm", barmode="group")
            fig_av.add_hline(y=50, line_dash="dash", line_color="green", annotation_text="Ideal (50%)")
            fig_av.add_hrect(y0=40, y1=60, fillcolor="green", opacity=0.1, annotation_text="Good range (40-60%)")
            fig_av.update_layout(xaxis_tickangle=-30, plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
            st.plotly_chart(fig_av, use_container_width=True)

    with tab5:
        fig_ex = px.bar(ok_df, x="Label", y="Expansion (%)", title="Ciphertext Expansion %",
                        color="Algorithm", barmode="group")
        fig_ex.update_layout(xaxis_tickangle=-30, plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(fig_ex, use_container_width=True)

    with tab6:
        metrics = ["Enc Time (ms)", "Enc RAM (KB)", "Avalanche (%)", "Final Entropy", "Throughput (KB/s)"]
        available = [m for m in metrics if m in ok_df.columns and ok_df[m].notna().any()]
        if available and len(ok_df) > 0:
            radar_fig = go.Figure()
            for _, row_d in ok_df.iterrows():
                vals = [row_d.get(m, 0) or 0 for m in available]
                radar_fig.add_trace(go.Scatterpolar(
                    r=vals, theta=available, fill="toself", name=str(row_d["Label"])[:30]
                ))
            radar_fig.update_layout(
                polar=dict(radialaxis=dict(visible=True)),
                title="Multi-Metric Radar (raw values)",
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white",
            )
            st.plotly_chart(radar_fig, use_container_width=True)
            st.caption("Note: Radar shows raw values — scales differ per metric.")

    # ── EXPORT ───────────────────────────────────────────
    st.header("⬇️ Export", divider="blue")
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Download Comparison CSV", csv_bytes, file_name=f"comparison_{bid}.csv", mime="text/csv")
