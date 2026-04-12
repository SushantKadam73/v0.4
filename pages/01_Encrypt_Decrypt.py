from __future__ import annotations

from pathlib import Path

import streamlit as st

from analysis.entropy import shannon_entropy
from analysis.performance import measure_operation
from crypto import aes_engine, chacha20_engine, hybrid_engine
from crypto.key_generator import generate_ecdsa_keypair, generate_rsa_keypair, generate_symmetric_key
from crypto.utils import restore_filename_from_enc
from lab_core import build_log_entry, encode_json_bytes, persist_operation, run_algorithm, to_hex_preview

st.title("Encrypt / Decrypt Workbench")

chacha20_available = chacha20_engine.is_available()
if not chacha20_available:
    st.warning("ChaCha20 backend is unavailable. ChaCha20 and hybrid modes are visible but cannot run.")

if "runtime_keys" not in st.session_state:
    ecdsa_pair = generate_ecdsa_keypair()
    rsa_pair = generate_rsa_keypair()
    st.session_state.runtime_keys = {
        "aes": generate_symmetric_key(),
        "chacha20": generate_symmetric_key(),
        "ecdsa_private": ecdsa_pair.private_pem,
        "ecdsa_public": ecdsa_pair.public_pem,
        "rsa_private": rsa_pair.private_pem,
        "rsa_public": rsa_pair.public_pem,
    }

mode = st.radio("Mode", ["Encrypt", "Decrypt"], horizontal=True)
input_mode = st.radio("Input", ["Text Input", "File Upload"], horizontal=True)
algorithm_labels = ["AES-256", "ChaCha20-256", "Hybrid + RSA", "Hybrid + ECDSA"]
algo_label = st.selectbox("Algorithm", algorithm_labels)

algo_map = {
    "AES-256": "aes_256",
    "ChaCha20-256": "chacha20_256",
    "Hybrid + RSA": "hybrid_rsa",
    "Hybrid + ECDSA": "hybrid_ecdsa",
}
algorithm = algo_map[algo_label]

if st.button("Generate New Runtime Keys"):
    ecdsa_pair = generate_ecdsa_keypair()
    rsa_pair = generate_rsa_keypair()
    st.session_state.runtime_keys = {
        "aes": generate_symmetric_key(),
        "chacha20": generate_symmetric_key(),
        "ecdsa_private": ecdsa_pair.private_pem,
        "ecdsa_public": ecdsa_pair.public_pem,
        "rsa_private": rsa_pair.private_pem,
        "rsa_public": rsa_pair.public_pem,
    }
    st.success("New runtime keys generated.")

uploaded_key = st.file_uploader("Optional symmetric key (.key, 32 bytes)", type=["key"], key="symmetric_key")

input_name = "input.bin"
input_data = b""

if input_mode == "Text Input":
    txt = st.text_area("Plaintext / Payload", height=180)
    input_data = txt.encode("utf-8")
    input_name = "inline.txt"
else:
    up = st.file_uploader("Upload file", key="data_file")
    if up:
        input_data = up.read()
        input_name = up.name
        ext = Path(up.name).suffix.lower()
        st.caption(f"File: {up.name} | Size: {len(input_data)/1024:.2f} KB | Entropy: {shannon_entropy(input_data):.3f}")
        if ext in {".txt", ".csv", ".json", ".xml", ".md"}:
            st.code(input_data[:500].decode("utf-8", errors="replace"))
        elif ext in {".png", ".jpg", ".jpeg", ".bmp", ".gif"}:
            st.image(input_data, caption=up.name)

if st.button(f"Run {mode}", type="primary"):
    if not input_data:
        st.error("Provide input text or upload a file.")
        st.stop()

    aes_key = uploaded_key.read() if uploaded_key else st.session_state.runtime_keys["aes"]
    chacha20_key = st.session_state.runtime_keys.get("chacha20", b"")
    rsa_private = st.session_state.runtime_keys["rsa_private"]
    rsa_public = st.session_state.runtime_keys["rsa_public"]
    ecdsa_private = st.session_state.runtime_keys["ecdsa_private"]
    ecdsa_public = st.session_state.runtime_keys["ecdsa_public"]

    if not chacha20_available and algorithm in {"chacha20_256", "hybrid_rsa", "hybrid_ecdsa"}:
        st.error("Selected algorithm needs ChaCha20, but the ChaCha20 backend is unavailable.")
        st.stop()

    try:
        if mode == "Encrypt":
            private_pem = rsa_private if algorithm == "hybrid_rsa" else ecdsa_private
            public_pem = rsa_public if algorithm == "hybrid_rsa" else ecdsa_public
            if algorithm in {"aes_256", "chacha20_256"}:
                private_pem = None
                public_pem = None

            artifacts = run_algorithm(
                algorithm,
                input_data,
                aes_key=aes_key,
                chacha20_key=chacha20_key,
                private_pem=private_pem,
                public_pem=public_pem,
            )
            output_data = artifacts.payload
            download_name = input_name + ".enc"
            operation_type = "encrypt"
        else:
            if algorithm == "aes_256":
                restored, dec_time, dec_ram = measure_operation(aes_engine.decrypt, input_data, aes_key)
                payload, enc_time, enc_ram = measure_operation(aes_engine.encrypt, restored, aes_key)
                signature_valid = True
                signature_bits = 0
                signature_algo = None
            elif algorithm == "chacha20_256":
                restored, dec_time, dec_ram = measure_operation(chacha20_engine.decrypt, input_data, chacha20_key)
                payload, enc_time, enc_ram = measure_operation(chacha20_engine.encrypt, restored, chacha20_key)
                signature_valid = True
                signature_bits = 0
                signature_algo = None
            elif algorithm == "hybrid_rsa":
                dec_result, dec_time, dec_ram = measure_operation(
                    hybrid_engine.decrypt, input_data, aes_key, chacha20_key, rsa_public, "RSA"
                )
                restored = dec_result.plaintext
                payload, enc_time, enc_ram = measure_operation(
                    hybrid_engine.encrypt, restored, aes_key, chacha20_key, rsa_private, "RSA"
                )
                signature_valid = dec_result.signature_valid
                signature_bits = len(dec_result.signature_bytes) * 8
                signature_algo = "RSA"
            else:
                dec_result, dec_time, dec_ram = measure_operation(
                    hybrid_engine.decrypt, input_data, aes_key, chacha20_key, ecdsa_public, "ECDSA"
                )
                restored = dec_result.plaintext
                payload, enc_time, enc_ram = measure_operation(
                    hybrid_engine.encrypt, restored, aes_key, chacha20_key, ecdsa_private, "ECDSA"
                )
                signature_valid = dec_result.signature_valid
                signature_bits = len(dec_result.signature_bytes) * 8
                signature_algo = "ECDSA"

            from lab_core import OperationArtifacts

            artifacts = OperationArtifacts(
                payload=payload,
                restored=restored,
                enc_time_ms=enc_time,
                dec_time_ms=dec_time,
                enc_ram_kb=enc_ram,
                dec_ram_kb=dec_ram,
                signature_valid=signature_valid,
                signature_size_bits=signature_bits,
                signature_algorithm=signature_algo,
            )
            output_data = restored
            download_name = restore_filename_from_enc(input_name)
            operation_type = "decrypt"

        col1, col2 = st.columns(2)
        col1.metric("Enc Time (ms)", f"{artifacts.enc_time_ms:.3f}")
        col1.metric("Dec Time (ms)", f"{artifacts.dec_time_ms:.3f}")
        col2.metric("Enc RAM (KB)", f"{artifacts.enc_ram_kb:.3f}")
        col2.metric("Dec RAM (KB)", f"{artifacts.dec_ram_kb:.3f}")

        st.subheader("Ciphertext / Output HEX Preview")
        st.code(to_hex_preview(output_data, 256))

        st.subheader("Entropy")
        st.write(f"Input: {shannon_entropy(input_data):.4f} bits/byte")
        st.write(f"Output: {shannon_entropy(output_data):.4f} bits/byte")

        st.subheader("Signature")
        if artifacts.signature_algorithm:
            st.write(f"Algorithm: {artifacts.signature_algorithm}")
            st.write(f"Signature size: {artifacts.signature_size_bits} bits")
            st.write(f"Valid: {artifacts.signature_valid}")
        else:
            st.write("Not applicable for this algorithm.")

        entry = build_log_entry(
            operation=operation_type,
            algorithm=algorithm,
            input_name=input_name,
            input_data=input_data,
            output_name=download_name,
            output_data=output_data,
            artifacts=artifacts,
        )
        export_path = persist_operation(entry)

        st.download_button("Download output", output_data, file_name=download_name)
        st.download_button("Download operation JSON", encode_json_bytes(entry), file_name=f"{entry['id']}.json")
        st.success(f"Logged operation. Sidecar export: {export_path}")
        with st.expander("Log Entry JSON"):
            st.json(entry)

    except Exception as exc:
        st.error(f"Operation failed: {exc}")
