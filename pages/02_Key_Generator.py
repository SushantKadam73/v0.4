"""Page 2 — Key Generator

Generate keys for AES-GCM, ChaCha20-Poly1305, RSA, and ECDSA
with configurable sizes and entropy analysis.
"""
from __future__ import annotations

import plotly.express as px
import streamlit as st

from analysis.entropy import byte_frequency, entropy_label, shannon_entropy
from analysis.security_metrics import is_all_zero_key
from crypto.key_generator import (
    VALID_AES_SIZES,
    generate_ecdsa_keypair,
    generate_rsa_keypair,
    generate_symmetric_key,
)

st.set_page_config(page_title="Key Generator — CryptoLab", layout="wide")
st.title("🔑 Key Generator")
st.caption("Generate cryptographic keys with configurable sizes. Keys are generated locally and never stored.")

# ─────────────────────────────────────────────────────────
# KEY TYPE SELECTION
# ─────────────────────────────────────────────────────────
key_type = st.selectbox(
    "Key Type",
    ["AES-GCM (Symmetric)", "ChaCha20-Poly1305 (Symmetric)", "RSA (Asymmetric)", "ECDSA (Asymmetric)"],
)

seed = st.text_input(
    "Optional seed (for symmetric keys)",
    help="Enter a string to generate a reproducible deterministic key. Leave blank for secure random.",
)

# ─────────────────────────────────────────────────────────
# NIST REFERENCE
# ─────────────────────────────────────────────────────────
with st.expander("ℹ️ Key Size Security Reference (NIST)"):
    st.markdown("""
| Security Level | AES-GCM | ChaCha20-Poly1305 | RSA | ECDSA |
|:-:|:-:|:-:|:-:|:-:|
| **128-bit** | 128-bit key | — | 3072-bit key | P-256 |
| **192-bit** | 192-bit key | — | 7680-bit key | P-384 |
| **256-bit** | 256-bit key | 256-bit (fixed) | 15360-bit* | P-521 |
""")

# ─────────────────────────────────────────────────────────
# SIZE SELECTION + GENERATE
# ─────────────────────────────────────────────────────────
key_size_param = None

if key_type == "AES-GCM (Symmetric)":
    key_size_bits = st.radio("Key Size", [128, 192, 256], index=2, horizontal=True, format_func=lambda x: f"{x}-bit")
    sec_level = {128: "128-bit security", 192: "192-bit security", 256: "256-bit security"}
    st.caption(f"🔒 {sec_level[key_size_bits]} | AEAD — authenticated encryption with associated data")
    key_size_param = key_size_bits

elif key_type == "ChaCha20-Poly1305 (Symmetric)":
    st.info("ChaCha20-Poly1305 uses a **fixed 256-bit key** — no size selection needed.")
    key_size_param = 256

elif key_type == "RSA (Asymmetric)":
    rsa_size = st.radio("Key Size", [2048, 3072, 4096], index=0, horizontal=True, format_func=lambda x: f"{x}-bit")
    rsa_sec = {2048: "112-bit (adequate)", 3072: "128-bit (good)", 4096: "≈140-bit (strong)"}
    st.caption(f"🔒 {rsa_sec[rsa_size]} equivalent security | Used for digital signatures")
    key_size_param = rsa_size

elif key_type == "ECDSA (Asymmetric)":
    ecdsa_curve = st.radio("Curve", ["P-256", "P-384", "P-521"], horizontal=True)
    ecdsa_sec = {"P-256": "128-bit", "P-384": "192-bit", "P-521": "256-bit"}
    st.caption(f"🔒 {ecdsa_sec[ecdsa_curve]} equivalent security | Much smaller key than RSA for same security level")
    key_size_param = ecdsa_curve

if st.button("⚡ Generate Key", type="primary"):
    st.divider()

    # ── SYMMETRIC KEYS ───────────────────────────────────
    if key_type in ("AES-GCM (Symmetric)", "ChaCha20-Poly1305 (Symmetric)"):
        bits = key_size_param
        key = generate_symmetric_key(bits, seed if seed else None)
        entropy = shannon_entropy(key)
        algo_name = "aes_gcm" if "AES" in key_type else "chacha20"

        st.subheader(f"Generated {bits}-bit Key")

        m1, m2, m3 = st.columns(3)
        m1.metric("Key Size", f"{bits} bits ({bits // 8} bytes)")
        m2.metric("Key Entropy", f"{entropy:.4f} bits/byte")
        m3.metric("Entropy Quality", entropy_label(entropy))

        if is_all_zero_key(key):
            st.error("⚠️ Weak key: all-zero bytes detected. This indicates a seeding problem.")
        elif entropy < 7.0:
            st.warning(f"⚠️ Low entropy ({entropy:.4f}). A good key should have entropy > 7.0.")
        else:
            st.success("✅ Key looks strong.")

        st.code(key.hex(), language="")

        # Byte frequency chart
        freq = byte_frequency(key)
        fig = px.bar(
            x=list(range(256)), y=freq,
            title="Key Byte Frequency Distribution",
            labels={"x": "Byte Value", "y": "Count"},
            color_discrete_sequence=["#4e8df5"],
        )
        fig.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(fig, use_container_width=True)

        st.download_button(
            f"⬇️ Download Key (.key)",
            data=key,
            file_name=f"{algo_name}_{bits}bit.key",
            mime="application/octet-stream",
        )

    # ── RSA KEYS ─────────────────────────────────────────
    elif key_type == "RSA (Asymmetric)":
        with st.spinner(f"Generating RSA-{key_size_param} keypair…"):
            private_pem, public_pem = generate_rsa_keypair(key_size_param)

        st.subheader(f"Generated RSA-{key_size_param} Keypair")
        st.caption("⚠️ Keep the private key secret. The public key can be shared freely.")

        col_priv, col_pub = st.columns(2)
        with col_priv:
            st.text_area("Private Key (PEM)", private_pem.decode(), height=200, key="rsa_priv_display")
            st.download_button("⬇️ Download Private Key", private_pem, file_name=f"rsa_{key_size_param}_private.pem")
        with col_pub:
            st.text_area("Public Key (PEM)", public_pem.decode(), height=200, key="rsa_pub_display")
            st.download_button("⬇️ Download Public Key", public_pem, file_name=f"rsa_{key_size_param}_public.pem")

    # ── ECDSA KEYS ───────────────────────────────────────
    elif key_type == "ECDSA (Asymmetric)":
        with st.spinner(f"Generating ECDSA-{key_size_param} keypair…"):
            private_pem, public_pem = generate_ecdsa_keypair(key_size_param)

        st.subheader(f"Generated ECDSA Keypair ({key_size_param})")
        st.caption("⚠️ Keep the private key secret. The public key can be shared freely.")

        col_priv, col_pub = st.columns(2)
        with col_priv:
            st.text_area("Private Key (PEM)", private_pem.decode(), height=200, key="ecdsa_priv_display")
            st.download_button("⬇️ Download Private Key", private_pem, file_name=f"ecdsa_{key_size_param}_private.pem")
        with col_pub:
            st.text_area("Public Key (PEM)", public_pem.decode(), height=200, key="ecdsa_pub_display")
            st.download_button("⬇️ Download Public Key", public_pem, file_name=f"ecdsa_{key_size_param}_public.pem")
