from __future__ import annotations

import plotly.express as px
import streamlit as st

from analysis.avalanche import bit_difference_map, bit_difference_percentage, flip_one_bit
from analysis.entropy import byte_frequency, entropy_label, shannon_entropy
from analysis.security_metrics import is_all_zero_key, is_low_entropy_key, is_non_standard_key_size
from crypto import aes_engine, chacha20_engine, hybrid_engine
from crypto.key_generator import generate_symmetric_key
from lab_core import to_hex_preview

st.title("Security Analysis")

chacha20_available = chacha20_engine.is_available()
if not chacha20_available:
    st.warning("ChaCha20 backend is unavailable. ChaCha20 and hybrid sections stay visible, but related actions are disabled.")

tab1, tab2, tab3, tab4 = st.tabs(["Entropy Analyzer", "Key Security Viewer", "Avalanche Tester", "Signature Verification"])

with tab1:
    mode = st.radio("Source", ["Text", "File"], horizontal=True, key="entropy_src")
    if mode == "Text":
        raw = st.text_area("Input text", key="entropy_text").encode("utf-8")
    else:
        up = st.file_uploader("Upload file", key="entropy_file")
        raw = up.read() if up else b""

    if raw:
        k1 = generate_symmetric_key()
        c1 = aes_engine.encrypt(raw, k1)
        stages = [
            ("Plaintext / Raw Input", raw),
            ("Ciphertext (AES)", c1),
        ]

        if chacha20_available:
            k2 = generate_symmetric_key()
            c2 = chacha20_engine.encrypt(raw[len(raw) // 2 :], k2)
            combined = c1 + c2
            stages = [
                ("Plaintext / Raw Input", raw),
                ("Ciphertext Half 1 (AES)", c1),
                ("Ciphertext Half 2 (ChaCha20)", c2),
                ("Final Combined Ciphertext", combined),
            ]

        for title, data in stages:
            st.markdown(f"### {title}")
            ent = shannon_entropy(data)
            st.code(to_hex_preview(data, 64))
            st.write(f"Entropy: {ent:.4f} bits/byte ({entropy_label(ent)})")

        freq = byte_frequency(raw)
        fig = px.bar(x=list(range(256)), y=freq, title="Byte Frequency Histogram")
        st.plotly_chart(fig, use_container_width=True)

with tab2:
    key_text = st.text_area("Paste key HEX")
    key_up = st.file_uploader("Or upload key file", key="key_viewer")
    key_bytes = b""
    if key_text.strip():
        try:
            key_bytes = bytes.fromhex(key_text.strip())
        except ValueError:
            st.error("Invalid HEX.")
    elif key_up:
        key_bytes = key_up.read()

    if key_bytes:
        ent = shannon_entropy(key_bytes)
        st.code(key_bytes.hex())
        st.write(f"Entropy: {ent:.4f}")
        if is_all_zero_key(key_bytes):
            st.error("Weakness: all-zero key")
        if is_low_entropy_key(key_bytes):
            st.warning("Weakness: low entropy key")
        if is_non_standard_key_size(key_bytes, {16, 24, 32}):
            st.warning("Weakness: non-standard key size")

with tab3:
    algo_options = ["AES-256", "ChaCha20-256"]
    algo = st.selectbox("Algorithm", algo_options, key="ava_algo")
    txt = st.text_area("Plaintext", key="ava_text")
    if st.button("Run Avalanche Test"):
        plain = txt.encode("utf-8")
        if not plain:
            st.error("Enter plaintext.")
            st.stop()

        if algo == "ChaCha20-256" and not chacha20_available:
            st.error("ChaCha20 backend is unavailable for this avalanche test.")
            st.stop()

        key = generate_symmetric_key()
        modified = flip_one_bit(plain, 0)

        if algo == "AES-256":
            c_a = aes_engine.encrypt(plain, key)
            c_b = aes_engine.encrypt(modified, key)
        else:
            c_a = chacha20_engine.encrypt(plain, key)
            c_b = chacha20_engine.encrypt(modified, key)

        pct = bit_difference_percentage(c_a, c_b)
        diff_map = bit_difference_map(c_a, c_b)

        st.metric("Changed bits %", f"{pct:.2f}%")
        fig = px.imshow([diff_map], aspect="auto", title="Bit-Difference Heatmap (per byte)")
        st.plotly_chart(fig, use_container_width=True)

with tab4:
    if not chacha20_available:
        st.info("Hybrid signature verification is unavailable because ChaCha20 is unavailable.")
    else:
        payload_up = st.file_uploader("Upload signed .enc payload", key="sig_payload")
        pub_up = st.file_uploader("Upload public key (.pem)", key="sig_pub")
        sig_algo = st.selectbox("Signature algorithm", ["RSA", "ECDSA"])

        if st.button("Verify Signature"):
            if not payload_up or not pub_up:
                st.error("Upload payload and public key.")
                st.stop()
            payload = payload_up.read()
            pub = pub_up.read()
            is_valid, sig_bytes = hybrid_engine.verify_payload_signature(payload, pub, sig_algo)
            st.success("VALID" if is_valid else "INVALID")
            st.code(sig_bytes.hex())
