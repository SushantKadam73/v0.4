"""Page 1 — Encryption Lab

Unified research workbench:
Step 1: Choose key size
Step 2: Choose algorithm
Step 3: Choose digital signature (optional)
Step 4: Choose input (text or file)
Step 5: Run encrypt / decrypt / both
→ Full analysis panel: performance, entropy, avalanche, ciphertext quality, signature
"""
from __future__ import annotations

from pathlib import Path

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from analysis.avalanche import bit_difference_map
from analysis.entropy import byte_frequency, entropy_label, shannon_entropy
from crypto.key_generator import (
    generate_ecdsa_keypair,
    generate_rsa_keypair,
    generate_symmetric_key,
)
from lab_core import (
    ALGORITHM_DISPLAY,
    NIST_SECURITY_LEVELS,
    EncryptionConfig,
    batch_id,
    build_and_log_row,
    hex_preview,
    run_operation,
)

st.set_page_config(page_title="Encryption Lab — CryptoLab", layout="wide")
st.title("🔬 Encryption Lab")
st.caption("Full cryptographic analysis — encrypt, decrypt, and measure everything.")

# ─────────────────────────────────────────────────────────
# SESSION STATE: Runtime Keys
# ─────────────────────────────────────────────────────────
def _init_keys(sym_bits: int = 256, rsa_size: int = 2048, ecdsa_curve: str = "P-256") -> None:
    st.session_state.lab_aes_key = generate_symmetric_key(sym_bits)
    st.session_state.lab_chacha_key = generate_symmetric_key(256)  # always 256 for ChaCha20
    st.session_state.lab_rsa_priv, st.session_state.lab_rsa_pub = generate_rsa_keypair(rsa_size)
    st.session_state.lab_ecdsa_priv, st.session_state.lab_ecdsa_pub = generate_ecdsa_keypair(ecdsa_curve)
    st.session_state.lab_key_sym_bits = sym_bits
    st.session_state.lab_key_rsa_size = rsa_size
    st.session_state.lab_key_ecdsa_curve = ecdsa_curve


if "lab_aes_key" not in st.session_state:
    _init_keys()

# ─────────────────────────────────────────────────────────
# STEP 1 — KEY SIZE SELECTION
# ─────────────────────────────────────────────────────────
st.header("Step 1 — Key Size", divider="blue")

with st.expander("ℹ️ NIST Security Equivalence Table", expanded=False):
    st.markdown("""
| Security Level | AES-GCM | ChaCha20-Poly1305 | RSA | ECDSA |
|:-:|:-:|:-:|:-:|:-:|
| **128-bit** | 128-bit key | — | 3072-bit key | P-256 |
| **192-bit** | 192-bit key | — | 7680-bit key | P-384 |
| **256-bit** | 256-bit key | 256-bit (fixed) | 15360-bit key* | P-521 |

*RSA-15360 is impractical. RSA-4096 is used as the practical 256-bit level option.*
""")

col_ks1, col_ks2, col_ks3 = st.columns(3)
with col_ks1:
    sym_key_bits = st.radio(
        "Symmetric Key Size (AES-GCM)",
        [128, 192, 256],
        index=2,
        format_func=lambda x: f"{x}-bit",
        help="ChaCha20-Poly1305 always uses 256-bit.",
    )
    sec_level = {128: "128-bit (good)", 192: "192-bit (high)", 256: "256-bit (maximum)"}
    st.caption(f"🔒 Security level: **{sec_level[sym_key_bits]}**")

with col_ks2:
    rsa_key_size = st.radio(
        "RSA Key Size",
        [2048, 3072, 4096],
        index=0,
        format_func=lambda x: f"{x}-bit",
    )
    rsa_sec = {2048: "112-bit (adequate)", 3072: "128-bit (good)", 4096: "≈140-bit (strong)"}
    st.caption(f"🔒 RSA equivalent: **{rsa_sec[rsa_key_size]}**")

with col_ks3:
    ecdsa_curve = st.radio(
        "ECDSA Curve",
        ["P-256", "P-384", "P-521"],
        index=0,
    )
    ecdsa_sec = {"P-256": "128-bit", "P-384": "192-bit", "P-521": "256-bit"}
    st.caption(f"🔒 ECDSA equivalent: **{ecdsa_sec[ecdsa_curve]}**")

# Regenerate keys if size selection changed
if (
    st.session_state.get("lab_key_sym_bits") != sym_key_bits
    or st.session_state.get("lab_key_rsa_size") != rsa_key_size
    or st.session_state.get("lab_key_ecdsa_curve") != ecdsa_curve
):
    _init_keys(sym_key_bits, rsa_key_size, ecdsa_curve)

if st.button("🔄 Regenerate All Keys"):
    _init_keys(sym_key_bits, rsa_key_size, ecdsa_curve)
    st.success("New keys generated for this session.")

# ─────────────────────────────────────────────────────────
# STEP 2 — ALGORITHM SELECTION
# ─────────────────────────────────────────────────────────
st.header("Step 2 — Algorithm", divider="blue")

algorithm = st.radio(
    "Encryption Algorithm",
    ["aes_gcm", "chacha20_poly1305", "hybrid"],
    format_func=lambda x: ALGORITHM_DISPLAY[x],
    horizontal=True,
)

if algorithm == "chacha20_poly1305":
    st.info("ChaCha20-Poly1305 always uses a 256-bit key regardless of the symmetric key size selection above.")
elif algorithm == "hybrid":
    st.info(
        "Hybrid mode encrypts the **first half** of the data with AES-GCM "
        "and the **second half** with ChaCha20-Poly1305, then optionally signs the combined ciphertext."
    )

# ─────────────────────────────────────────────────────────
# STEP 3 — DIGITAL SIGNATURE
# ─────────────────────────────────────────────────────────
st.header("Step 3 — Digital Signature (Optional)", divider="blue")

sig_choice = st.radio(
    "Signature Algorithm",
    ["None", "RSA", "ECDSA"],
    horizontal=True,
    help="Sign the ciphertext hash to enable integrity verification.",
)
sig_algorithm = None if sig_choice == "None" else sig_choice
sig_key_param = str(rsa_key_size) if sig_algorithm == "RSA" else ecdsa_curve

if sig_algorithm:
    key_param_display = f"RSA-{rsa_key_size}" if sig_algorithm == "RSA" else f"ECDSA-{ecdsa_curve}"
    st.caption(f"Signing with **{sig_algorithm}** using key: **{key_param_display}**")

# ─────────────────────────────────────────────────────────
# STEP 4 — INPUT
# ─────────────────────────────────────────────────────────
st.header("Step 4 — Input", divider="blue")

input_mode = st.radio("Input Mode", ["Text Input", "File Upload"], horizontal=True)
input_data = b""
input_name = "input.bin"

if input_mode == "Text Input":
    txt = st.text_area("Plaintext / Message", height=150)
    input_data = txt.encode("utf-8")
    input_name = "inline.txt"
    if input_data:
        st.caption(f"Size: {len(input_data)} bytes | Entropy: {shannon_entropy(input_data):.3f} bits/byte")
else:
    up = st.file_uploader(
        "Upload any file",
        help="Supports all file types up to 200 MB",
        key="lab_file_upload",
    )
    if up:
        input_data = up.read()
        input_name = up.name
        ext = Path(up.name).suffix.lower()
        ent = shannon_entropy(input_data)
        st.caption(f"**{up.name}** | {len(input_data)/1024:.2f} KB | {up.type} | Entropy: {ent:.3f} bits/byte")
        if ext in {".txt", ".csv", ".json", ".xml", ".md"}:
            with st.expander("File preview"):
                st.code(input_data[:500].decode("utf-8", errors="replace"))
        elif ext in {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}:
            st.image(input_data, caption=up.name, use_container_width=True)

# ─────────────────────────────────────────────────────────
# STEP 5 — OPERATION
# ─────────────────────────────────────────────────────────
st.header("Step 5 — Run", divider="blue")

col_op1, col_op2 = st.columns(2)
with col_op1:
    operation = st.radio(
        "Operation",
        ["both", "encrypt", "decrypt"],
        format_func=lambda x: {"both": "Encrypt then Decrypt", "encrypt": "Encrypt only", "decrypt": "Decrypt only"}[x],
        horizontal=True,
    )
with col_op2:
    iterations = st.slider(
        "Iterations (for averaging)",
        min_value=1,
        max_value=10,
        value=1,
        help="Run the operation multiple times and report mean ± std dev. Useful for stable benchmarks.",
    )

run_clicked = st.button("▶ Run Operation", type="primary", disabled=not input_data)

if not input_data and not run_clicked:
    st.info("Provide text or upload a file to continue.")

# ─────────────────────────────────────────────────────────
# EXECUTE
# ─────────────────────────────────────────────────────────
if run_clicked and input_data:
    config = EncryptionConfig(
        algorithm=algorithm,
        sym_key_size_bits=sym_key_bits,
        sig_algorithm=sig_algorithm,
        sig_key_param=sig_key_param,
        operation=operation,
        iterations=iterations,
    )

    aes_key = st.session_state.lab_aes_key
    chacha_key = st.session_state.lab_chacha_key
    private_pem = (
        st.session_state.lab_rsa_priv if sig_algorithm == "RSA" else st.session_state.lab_ecdsa_priv
    ) if sig_algorithm else None
    public_pem = (
        st.session_state.lab_rsa_pub if sig_algorithm == "RSA" else st.session_state.lab_ecdsa_pub
    ) if sig_algorithm else None

    with st.spinner("Running operation…"):
        result = run_operation(config, input_data, aes_key, chacha_key, private_pem, public_pem)

    if result.error:
        st.error(f"Operation failed: {result.error}")
        st.stop()

    output_filename = input_name + ".enc" if operation in {"encrypt", "both"} else input_name
    bid = batch_id() if iterations > 1 else ""
    row = build_and_log_row(config, input_name, input_data, output_filename, result, bid, 1)

    st.success("✅ Operation complete — results logged to `logs/operations.csv`")

    # ─────────────────────────────────────────────────────
    # RESULTS PANEL
    # ─────────────────────────────────────────────────────
    st.header("📊 Analysis Results", divider="green")
    tabs = st.tabs(["⚡ Performance", "🔐 Entropy Pipeline", "💥 Avalanche", "📈 Ciphertext Quality", "✍️ Signature", "🔍 HEX Viewer", "⬇️ Downloads"])

    # ── Tab 1: Performance ──────────────────────────────
    with tabs[0]:
        st.subheader("Performance Metrics")

        if iterations > 1:
            st.caption(f"Showing **mean ± std dev** over {iterations} iterations")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Enc Time (ms)", f"{result.enc_mean_ms:.3f}", f"±{result.enc_std_ms:.3f}")
            c2.metric("Dec Time (ms)", f"{result.dec_mean_ms:.3f}", f"±{result.dec_std_ms:.3f}")
            c3.metric("Enc RAM (KB)", f"{result.enc_mean_ram_kb:.1f}", f"±{result.enc_std_ram_kb:.1f}")
            c4.metric("Enc Throughput (KB/s)", f"{result.enc_mean_throughput:.0f}", f"±{result.enc_std_throughput:.0f}")
        else:
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Enc Time (ms)", f"{result.enc_time_ms:.3f}")
            c2.metric("Dec Time (ms)", f"{result.dec_time_ms:.3f}")
            c3.metric("Total Time (ms)", f"{result.enc_time_ms + result.dec_time_ms:.3f}")
            c4.metric("Enc RAM (KB)", f"{result.enc_ram_kb:.1f}")
            c5.metric("Enc Throughput", f"{result.enc_throughput_kbps:.0f} KB/s")

        # Performance bar chart
        if operation == "both":
            perf_fig = go.Figure(data=[
                go.Bar(name="Encrypt", x=["Time (ms)", "RAM (KB)"],
                       y=[result.enc_time_ms, result.enc_ram_kb], marker_color="#4e8df5"),
                go.Bar(name="Decrypt", x=["Time (ms)", "RAM (KB)"],
                       y=[result.dec_time_ms, result.dec_ram_kb], marker_color="#f59d4e"),
            ])
            perf_fig.update_layout(barmode="group", title="Encrypt vs Decrypt Performance",
                                   plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
            st.plotly_chart(perf_fig, use_container_width=True)

    # ── Tab 2: Entropy Pipeline ──────────────────────────
    with tabs[1]:
        st.subheader("Entropy at Each Stage")
        stages = [
            ("Plaintext", result.entropy_plaintext),
            ("AES-GCM Half", result.entropy_aes_half),
            ("ChaCha20 Half", result.entropy_chacha_half),
            ("Final Ciphertext", result.entropy_final),
        ]
        col_e1, col_e2, col_e3, col_e4 = st.columns(4)
        for col, (label, val) in zip([col_e1, col_e2, col_e3, col_e4], stages):
            col.metric(label, f"{val:.4f} bits/byte", entropy_label(val))

        # Entropy flow chart
        ent_fig = go.Figure()
        stage_names = [s[0] for s in stages]
        stage_vals = [s[1] for s in stages]
        ent_fig.add_trace(go.Scatter(
            x=stage_names, y=stage_vals, mode="lines+markers+text",
            text=[f"{v:.4f}" for v in stage_vals],
            textposition="top center",
            line=dict(color="#4e8df5", width=3),
            marker=dict(size=12, color="#4e8df5"),
        ))
        ent_fig.add_hline(y=8.0, line_dash="dash", line_color="green", annotation_text="Max (8.0)")
        ent_fig.add_hline(y=7.5, line_dash="dot", line_color="orange", annotation_text="Strong threshold (7.5)")
        ent_fig.update_layout(
            title="Shannon Entropy Pipeline",
            yaxis=dict(range=[0, 8.5], title="Entropy (bits/byte)"),
            xaxis_title="Stage",
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white",
        )
        st.plotly_chart(ent_fig, use_container_width=True)

        # Byte frequency of plaintext
        st.subheader("Byte Frequency — Input")
        freq = byte_frequency(input_data)
        freq_fig = px.bar(
            x=list(range(256)), y=freq,
            title="Input Byte Frequency Histogram (256 bins)",
            labels={"x": "Byte Value", "y": "Count"},
            color_discrete_sequence=["#4e8df5"],
        )
        freq_fig.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(freq_fig, use_container_width=True)

        # Byte frequency of ciphertext
        st.subheader("Byte Frequency — Ciphertext")
        cipher_freq = byte_frequency(result.ciphertext)
        cipher_freq_fig = px.bar(
            x=list(range(256)), y=cipher_freq,
            title="Ciphertext Byte Frequency Histogram (ideal = flat)",
            labels={"x": "Byte Value", "y": "Count"},
            color_discrete_sequence=["#f5a44e"],
        )
        cipher_freq_fig.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(cipher_freq_fig, use_container_width=True)

    # ── Tab 3: Avalanche ────────────────────────────────
    with tabs[2]:
        st.subheader("Avalanche Effect")
        if result.avalanche:
            av = result.avalanche
            ca, cb, cc = st.columns(3)
            ca.metric("Bits Changed", f"{av.bit_change_pct:.2f}%",
                      help="Ideal: ~50% of bits should change when 1 input bit is flipped")
            cb.metric("Deviation from Ideal", f"{av.deviation_from_ideal:.2f}%",
                      help="Deviation from 50%. Lower = better avalanche effect.")
            cc.metric("Quality", av.label())

            # Gauge chart
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=av.bit_change_pct,
                title={"text": "Avalanche Effect (%)"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#4e8df5"},
                    "steps": [
                        {"range": [0, 30], "color": "#e74c3c"},
                        {"range": [30, 40], "color": "#f39c12"},
                        {"range": [40, 60], "color": "#2ecc71"},
                        {"range": [60, 70], "color": "#f39c12"},
                        {"range": [70, 100], "color": "#e74c3c"},
                    ],
                    "threshold": {"line": {"color": "white", "width": 4}, "thickness": 0.75, "value": 50},
                },
                number={"suffix": "%"},
            ))
            fig_gauge.update_layout(
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white", height=300
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

            # Bit difference heatmap on a sample
            if len(input_data) >= 2:
                from crypto import aes_gcm_engine
                from analysis.avalanche import flip_one_bit
                key_for_ava = st.session_state.lab_aes_key
                sample = input_data[:min(512, len(input_data))]
                try:
                    c_orig = aes_gcm_engine.encrypt(sample, key_for_ava)
                    c_flip = aes_gcm_engine.encrypt(flip_one_bit(sample, 0), key_for_ava)
                    diff_map = bit_difference_map(c_orig, c_flip)
                    heatmap_data = [diff_map[:min(len(diff_map), 512)]]
                    hm_fig = px.imshow(
                        heatmap_data, aspect="auto",
                        title="Bit-Difference Heatmap (per byte, first 512 bytes)",
                        color_continuous_scale="Blues",
                        labels={"color": "Bits different"},
                    )
                    hm_fig.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
                    st.plotly_chart(hm_fig, use_container_width=True)
                except Exception:
                    pass
        else:
            st.info("Avalanche analysis not available for this input.")

    # ── Tab 4: Ciphertext Quality ────────────────────────
    with tabs[3]:
        st.subheader("Ciphertext Quality Metrics")
        cq1, cq2, cq3 = st.columns(3)
        cq1.metric(
            "Ciphertext Expansion",
            f"{result.ciphertext_expansion_pct:.3f}%",
            help="% size increase. AEAD overhead: AES-GCM/ChaCha20 add 28 bytes (nonce + tag).",
        )
        cq2.metric(
            "Byte Freq Std Dev",
            f"{result.byte_freq_std_dev:.4f}",
            help="Standard deviation of byte frequency histogram. Ideal ciphertext → ~0 (uniform).",
        )
        cq3.metric(
            "Chi-Squared Statistic",
            f"{result.chi_squared:.2f}",
            help="Chi-squared test for uniformity. Values close to 255 (df=255) indicate good randomness.",
        )

        st.caption(f"Input: {len(input_data):,} bytes → Output: {len(result.ciphertext):,} bytes")

    # ── Tab 5: Signature ────────────────────────────────
    with tabs[4]:
        st.subheader("Digital Signature")
        if sig_algorithm:
            sv1, sv2, sv3 = st.columns(3)
            sv1.metric("Algorithm", sig_algorithm)
            sv2.metric("Key", f"{sig_key_param}")
            sv3.metric("Signature Size", f"{result.sig_size_bits} bits")
            if result.sig_valid:
                st.success("✅ Signature VALID — integrity confirmed")
            else:
                st.error("❌ Signature INVALID — payload may have been tampered")
            if result.sig_bytes:
                with st.expander("Signature HEX"):
                    st.code(result.sig_bytes.hex())
        else:
            st.info("No digital signature selected for this operation. Choose RSA or ECDSA in Step 3 to enable.")

    # ── Tab 6: HEX Viewer ───────────────────────────────
    with tabs[5]:
        st.subheader("Ciphertext HEX Preview (first 256 bytes)")
        st.code(hex_preview(result.ciphertext, 256), language="")
        st.caption(f"Full ciphertext: {len(result.ciphertext):,} bytes")

    # ── Tab 7: Downloads ────────────────────────────────
    with tabs[6]:
        st.subheader("Download Results")
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.download_button(
                "⬇️ Download Ciphertext (.enc)",
                data=result.ciphertext,
                file_name=output_filename,
                mime="application/octet-stream",
            )
            if result.decrypted:
                st.download_button(
                    "⬇️ Download Decrypted File",
                    data=result.decrypted,
                    file_name=input_name,
                    mime="application/octet-stream",
                )
        with col_d2:
            import json
            st.download_button(
                "⬇️ Download Log Row (JSON)",
                data=json.dumps(row, indent=2, default=str).encode("utf-8"),
                file_name=f"{row['id']}.json",
                mime="application/json",
            )
