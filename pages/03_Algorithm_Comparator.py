from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from crypto import chacha20_engine
from crypto.key_generator import generate_ecdsa_keypair, generate_rsa_keypair, generate_symmetric_key
from lab_core import export_json, run_algorithm

st.title("Algorithm Comparator")

chacha20_available = chacha20_engine.is_available()
if not chacha20_available:
    st.warning("ChaCha20 backend is unavailable. Hybrid and ChaCha20 rows are shown as unavailable.")

input_mode = st.selectbox("Input mode", ["Text Input", "File Upload", "Synthetic Test File"])

input_data = b""
input_name = "input.bin"

if input_mode == "Text Input":
    txt = st.text_area("Input text", height=160)
    input_data = txt.encode("utf-8")
    input_name = "inline.txt"
elif input_mode == "File Upload":
    up = st.file_uploader("Upload input file")
    if up:
        input_data = up.read()
        input_name = up.name
else:
    size_label = st.selectbox("Synthetic size", ["150 KB", "498 KB", "750 KB", "1012 KB"])
    size_kb = int(size_label.split()[0])
    input_data = bytes([i % 256 for i in range(size_kb * 1024)])
    input_name = f"synthetic_{size_kb}kb.bin"

if st.button("Run comparison", type="primary"):
    if not input_data:
        st.error("Provide input first.")
        st.stop()

    aes_key = generate_symmetric_key()
    chacha20_key = generate_symmetric_key()
    ecdsa = generate_ecdsa_keypair()
    rsa_pair = generate_rsa_keypair()

    rows = []
    algorithm_runs = [
        ("aes_256", "AES-256"),
        ("chacha20_256", "ChaCha20-256"),
        ("hybrid_rsa", "Hybrid + RSA"),
        ("hybrid_ecdsa", "Hybrid + ECDSA"),
    ]

    for algo, label in algorithm_runs:
        if not chacha20_available and algo in {"chacha20_256", "hybrid_rsa", "hybrid_ecdsa"}:
            rows.append(
                {
                    "Algorithm": label,
                    "Status": "Unavailable (ChaCha20 backend missing)",
                    "Enc Time (ms)": None,
                    "Dec Time (ms)": None,
                    "Enc RAM (KB)": None,
                    "Dec RAM (KB)": None,
                    "Output Size (KB)": None,
                    "Sig Size (bits)": None,
                }
            )
            continue

        private_pem = None
        public_pem = None
        if algo == "hybrid_rsa":
            private_pem = rsa_pair.private_pem
            public_pem = rsa_pair.public_pem
        elif algo == "hybrid_ecdsa":
            private_pem = ecdsa.private_pem
            public_pem = ecdsa.public_pem

        result = run_algorithm(
            algo,
            input_data,
            aes_key=aes_key,
            chacha20_key=chacha20_key,
            private_pem=private_pem,
            public_pem=public_pem,
        )

        rows.append(
            {
                "Algorithm": label,
                "Status": "OK",
                "Enc Time (ms)": round(result.enc_time_ms, 3),
                "Dec Time (ms)": round(result.dec_time_ms, 3),
                "Enc RAM (KB)": round(result.enc_ram_kb, 3),
                "Dec RAM (KB)": round(result.dec_ram_kb, 3),
                "Output Size (KB)": round(len(result.payload) / 1024.0, 3),
                "Sig Size (bits)": result.signature_size_bits if result.signature_size_bits else None,
            }
        )

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)

    chart_df = df.fillna(0)
    c1 = px.bar(chart_df, x="Algorithm", y="Enc Time (ms)", title="Encryption Time by Algorithm")
    c2 = px.bar(chart_df, x="Algorithm", y="Enc RAM (KB)", title="Encryption RAM by Algorithm")
    c3 = px.bar(chart_df, x="Algorithm", y="Sig Size (bits)", title="Signature Size (RSA vs ECDSA)")

    st.plotly_chart(c1, use_container_width=True)
    st.plotly_chart(c2, use_container_width=True)
    st.plotly_chart(c3, use_container_width=True)

    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input_name": input_name,
        "input_size_kb": round(len(input_data) / 1024.0, 3),
        "rows": rows,
    }
    out_name = f"comparison_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    out_path = export_json(payload, out_name)
    st.success(f"Exported comparison to {out_path}")
