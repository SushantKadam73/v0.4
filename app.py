from __future__ import annotations

import streamlit as st

st.set_page_config(page_title="CryptoLab", layout="wide")

st.title("CryptoLab - Hybrid Encryption Analysis Dashboard")
st.markdown(
    """
Use the left sidebar to navigate pages:
- Encrypt / Decrypt Workbench
- Key Generator
- Algorithm Comparator
- Security Analysis
- Trend Dashboard
"""
)

st.info("Local-only demo tool. Operations are logged to JSON Lines in logs/operations.jsonl.")
