from __future__ import annotations

import streamlit as st

from analysis.security_metrics import is_low_entropy_key, key_entropy_score
from crypto import chacha20_engine
from crypto.key_generator import generate_ecdsa_keypair, generate_rsa_keypair, generate_symmetric_key

st.title("Key Generator")

chacha20_available = chacha20_engine.is_available()
if not chacha20_available:
    st.warning("ChaCha20 backend is unavailable. ChaCha20 key option remains visible for consistency.")

key_types = ["AES-256", "ChaCha20-256", "ECDSA (P-256)", "RSA-2048"]
key_type = st.selectbox("Key type", key_types)
seed = st.text_input("Optional seed (deterministic for symmetric keys)")

if st.button("Generate", type="primary"):
    if key_type == "ChaCha20-256" and not chacha20_available:
        st.error("ChaCha20 backend is unavailable, so ChaCha20 key generation is disabled.")
        st.stop()

    if key_type in {"AES-256", "ChaCha20-256"}:
        key = generate_symmetric_key(seed if seed else None)
        entropy = key_entropy_score(key)
        st.code(key.hex())
        st.metric("Key entropy", f"{entropy:.4f}")
        if is_low_entropy_key(key):
            st.warning("Weak randomness warning: low entropy key")
        st.download_button("Download .key", key, file_name=f"{key_type.lower().replace('-', '_')}.key")
    elif key_type == "ECDSA (P-256)":
        pair = generate_ecdsa_keypair()
        st.code(pair.private_pem.decode("utf-8"))
        st.code(pair.public_pem.decode("utf-8"))
        st.download_button("Download private PEM", pair.private_pem, file_name="ecdsa_private.pem")
        st.download_button("Download public PEM", pair.public_pem, file_name="ecdsa_public.pem")
    else:
        pair = generate_rsa_keypair()
        st.code(pair.private_pem.decode("utf-8"))
        st.code(pair.public_pem.decode("utf-8"))
        st.download_button("Download private PEM", pair.private_pem, file_name="rsa_private.pem")
        st.download_button("Download public PEM", pair.public_pem, file_name="rsa_public.pem")
