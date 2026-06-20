"""Page 1 — Encryption Lab.

Operation-first workflow for local cryptography experiments:
1. Select operation
2. Configure keys/algorithm/signature for encryption workflows
3. Provide plaintext/file input or encrypted package input
4. Run once and inspect hashes, signature, entropy, RAM, and timing
"""

from __future__ import annotations

import json
import math
import mimetypes
from pathlib import Path

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from PIL import Image

from analysis.avalanche import bit_difference_map
from analysis.entropy import byte_frequency, entropy_label, shannon_entropy
from crypto.key_generator import (
    generate_ecdsa_keypair,
    generate_rsa_keypair,
    generate_symmetric_key,
)
from lab_core import (
    ALGORITHM_DISPLAY,
    EncryptionConfig,
    build_and_log_row,
    hex_preview,
    run_operation,
    sha256_hex,
)

st.set_page_config(page_title="Encryption Lab — CryptoLab", layout="wide")
st.title("🔬 Encryption Lab")
st.caption(
    "Choose the operation first, then encrypt or decrypt with one controlled run."
)

PACKAGE_MAGIC = b"CLABPKG1"
TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".xml", ".md"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}


def _init_keys(
    sym_bits: int = 256, rsa_size: int = 2048, ecdsa_curve: str = "P-256"
) -> None:
    st.session_state.lab_aes_key = generate_symmetric_key(sym_bits)
    st.session_state.lab_chacha_key = generate_symmetric_key(256)
    st.session_state.lab_rsa_priv, st.session_state.lab_rsa_pub = generate_rsa_keypair(
        rsa_size
    )
    st.session_state.lab_ecdsa_priv, st.session_state.lab_ecdsa_pub = (
        generate_ecdsa_keypair(ecdsa_curve)
    )
    st.session_state.lab_key_sym_bits = sym_bits
    st.session_state.lab_key_rsa_size = rsa_size
    st.session_state.lab_key_ecdsa_curve = ecdsa_curve


def _is_text_file(file_name: str) -> bool:
    return Path(file_name).suffix.lower() in TEXT_EXTENSIONS


def _is_image_file(file_name: str) -> bool:
    return Path(file_name).suffix.lower() in IMAGE_EXTENSIONS


def _encrypted_image_preview(ciphertext: bytes) -> Image.Image:
    width = 256
    height = max(1, math.ceil(len(ciphertext) / width))
    padded = ciphertext.ljust(width * height, b"\x00")
    return Image.frombytes("L", (width, height), padded)


def _build_package(
    *,
    ciphertext: bytes,
    signature: bytes,
    config: EncryptionConfig,
    input_name: str,
    input_bytes: bytes,
    result_plaintext_hash: str,
    result_ciphertext_hash: str,
) -> bytes:
    header = {
        "version": 1,
        "algorithm": config.algorithm,
        "sym_key_size_bits": config.sym_key_size_bits,
        "sig_algorithm": config.sig_algorithm or "",
        "sig_key_param": config.sig_key_param if config.sig_algorithm else "",
        "original_filename": input_name,
        "original_extension": Path(input_name).suffix.lower(),
        "original_mime": mimetypes.guess_type(input_name)[0]
        or "application/octet-stream",
        "original_size_bytes": len(input_bytes),
        "plaintext_sha256": result_plaintext_hash,
        "ciphertext_sha256": result_ciphertext_hash,
        "ciphertext_len": len(ciphertext),
        "signature_len": len(signature),
    }
    header_bytes = json.dumps(header).encode("utf-8")
    return (
        PACKAGE_MAGIC
        + len(header_bytes).to_bytes(4, "big")
        + header_bytes
        + ciphertext
        + signature
    )


def _parse_package(package_bytes: bytes) -> tuple[dict[str, object], bytes, bytes]:
    if len(package_bytes) < len(PACKAGE_MAGIC) + 4 or not package_bytes.startswith(
        PACKAGE_MAGIC
    ):
        raise ValueError("This file is not a valid CryptoLab encrypted package")
    header_len_offset = len(PACKAGE_MAGIC)
    header_len = int.from_bytes(
        package_bytes[header_len_offset : header_len_offset + 4], "big"
    )
    header_start = header_len_offset + 4
    header_end = header_start + header_len
    header = json.loads(package_bytes[header_start:header_end].decode("utf-8"))
    ciphertext_len = int(header.get("ciphertext_len", 0))
    signature_len = int(header.get("signature_len", 0))
    ciphertext_start = header_end
    ciphertext_end = ciphertext_start + ciphertext_len
    signature_end = ciphertext_end + signature_len
    ciphertext = package_bytes[ciphertext_start:ciphertext_end]
    signature = package_bytes[ciphertext_end:signature_end]
    return header, ciphertext, signature


def _show_keys(sym_bits: int, rsa_bits: int, ecdsa_curve: str) -> None:
    with st.expander("🔑 View and download keys used in this lab", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            st.caption(f"AES-GCM key ({sym_bits} bits)")
            st.code(st.session_state.lab_aes_key.hex(), language="")
            st.download_button(
                "⬇️ Download AES key",
                data=st.session_state.lab_aes_key,
                file_name=f"aes_{sym_bits}bit.key",
                mime="application/octet-stream",
            )
            st.caption("ChaCha20-Poly1305 key (256 bits)")
            st.code(st.session_state.lab_chacha_key.hex(), language="")
            st.download_button(
                "⬇️ Download ChaCha key",
                data=st.session_state.lab_chacha_key,
                file_name="chacha20_poly1305_256bit.key",
                mime="application/octet-stream",
            )
        with c2:
            st.caption(f"RSA private/public ({rsa_bits} bits)")
            st.text_area(
                "RSA private key (PEM)",
                st.session_state.lab_rsa_priv.decode("utf-8"),
                height=120,
            )
            st.text_area(
                "RSA public key (PEM)",
                st.session_state.lab_rsa_pub.decode("utf-8"),
                height=120,
            )
            st.download_button(
                "⬇️ Download RSA private PEM",
                data=st.session_state.lab_rsa_priv,
                file_name=f"rsa_{rsa_bits}_private.pem",
                mime="application/x-pem-file",
            )
            st.download_button(
                "⬇️ Download RSA public PEM",
                data=st.session_state.lab_rsa_pub,
                file_name=f"rsa_{rsa_bits}_public.pem",
                mime="application/x-pem-file",
            )
            st.caption(f"ECDSA private/public ({ecdsa_curve})")
            st.text_area(
                "ECDSA private key (PEM)",
                st.session_state.lab_ecdsa_priv.decode("utf-8"),
                height=120,
            )
            st.text_area(
                "ECDSA public key (PEM)",
                st.session_state.lab_ecdsa_pub.decode("utf-8"),
                height=120,
            )
            st.download_button(
                "⬇️ Download ECDSA private PEM",
                data=st.session_state.lab_ecdsa_priv,
                file_name=f"ecdsa_{ecdsa_curve}_private.pem",
                mime="application/x-pem-file",
            )
            st.download_button(
                "⬇️ Download ECDSA public PEM",
                data=st.session_state.lab_ecdsa_pub,
                file_name=f"ecdsa_{ecdsa_curve}_public.pem",
                mime="application/x-pem-file",
            )


if "lab_aes_key" not in st.session_state:
    _init_keys()

st.header("Step 1 — Operation", divider="blue")
operation = st.radio(
    "Choose operation",
    ["encrypt", "decrypt", "both"],
    index=0,
    format_func=lambda value: {
        "encrypt": "Encrypt only",
        "decrypt": "Decrypt only",
        "both": "Encrypt and then decrypt",
    }[value],
    horizontal=True,
)

if operation in {"encrypt", "both"}:
    st.header("Step 2 — Key sizes", divider="blue")
    k1, k2, k3 = st.columns(3)
    with k1:
        sym_key_bits = st.radio(
            "AES-GCM key size", [128, 192, 256], index=2, horizontal=True
        )
    with k2:
        rsa_key_size = st.radio(
            "RSA key size", [2048, 3072, 4096], index=0, horizontal=True
        )
    with k3:
        ecdsa_curve = st.radio(
            "ECDSA curve", ["P-256", "P-384", "P-521"], index=0, horizontal=True
        )

    if (
        st.session_state.get("lab_key_sym_bits") != sym_key_bits
        or st.session_state.get("lab_key_rsa_size") != rsa_key_size
        or st.session_state.get("lab_key_ecdsa_curve") != ecdsa_curve
    ):
        _init_keys(sym_key_bits, rsa_key_size, ecdsa_curve)

    if st.button("🔄 Regenerate all keys"):
        _init_keys(sym_key_bits, rsa_key_size, ecdsa_curve)
        st.success("New runtime keys generated.")

    _show_keys(sym_key_bits, rsa_key_size, ecdsa_curve)

    st.header("Step 3 — Algorithm and signature", divider="blue")
    algorithm = st.radio(
        "Encryption algorithm",
        ["aes_gcm", "chacha20_poly1305", "hybrid"],
        format_func=lambda value: ALGORITHM_DISPLAY[value],
        horizontal=True,
    )
    sig_choice = st.radio(
        "Digital signature",
        ["None", "RSA", "ECDSA"],
        horizontal=True,
        help="The signature is included inside the single downloadable encrypted package.",
    )
    sig_algorithm = None if sig_choice == "None" else sig_choice
    sig_key_param = str(rsa_key_size) if sig_algorithm == "RSA" else ecdsa_curve

    st.header("Step 4 — Input", divider="blue")
    input_mode = st.radio("Input type", ["Text Input", "File Upload"], horizontal=True)
    input_name = "inline.txt"
    input_data = b""

    if input_mode == "Text Input":
        text_value = st.text_area("Plaintext", height=180)
        input_data = text_value.encode("utf-8")
        input_name = "inline.txt"
        if input_data:
            st.caption(f"Text size: {len(input_data)} bytes")
    else:
        uploaded = st.file_uploader("Upload any file")
        if uploaded:
            input_data = uploaded.read()
            input_name = uploaded.name
            st.caption(f"{uploaded.name} • {len(input_data):,} bytes")
            if _is_text_file(input_name):
                st.text_area(
                    "Original text preview",
                    input_data.decode("utf-8", errors="replace"),
                    height=180,
                )
            elif _is_image_file(input_name):
                st.image(input_data, caption="Original image", use_column_width=True)

    run_clicked = st.button("▶ Run encryption", type="primary", disabled=not input_data)

    if run_clicked and input_data:
        config = EncryptionConfig(
            algorithm=algorithm,
            sym_key_size_bits=sym_key_bits,
            sig_algorithm=sig_algorithm,
            sig_key_param=sig_key_param,
            operation=operation,
            iterations=1,
        )

        aes_key = st.session_state.lab_aes_key
        chacha_key = st.session_state.lab_chacha_key
        private_pem = (
            st.session_state.lab_rsa_priv
            if sig_algorithm == "RSA"
            else st.session_state.lab_ecdsa_priv
            if sig_algorithm == "ECDSA"
            else None
        )
        public_pem = (
            st.session_state.lab_rsa_pub
            if sig_algorithm == "RSA"
            else st.session_state.lab_ecdsa_pub
            if sig_algorithm == "ECDSA"
            else None
        )

        with st.spinner("Running encryption workflow..."):
            result = run_operation(
                config, input_data, aes_key, chacha_key, private_pem, public_pem
            )

        if result.error:
            st.error(f"Operation failed: {result.error}")
            st.stop()

        package_signature = result.sig_bytes if algorithm != "hybrid" else b""
        package_name = f"{input_name}.clab"
        package_bytes = _build_package(
            ciphertext=result.ciphertext,
            signature=package_signature,
            config=config,
            input_name=input_name,
            input_bytes=input_data,
            result_plaintext_hash=result.plaintext_sha256,
            result_ciphertext_hash=result.ciphertext_sha256,
        )

        row = build_and_log_row(config, input_name, input_data, package_name, result)
        st.success(
            "✅ Encryption workflow complete — logged to `logs/operations.jsonl`"
        )

        if operation == "both":
            if result.hash_match:
                st.success(
                    "Round-trip success: the same key restored the original content after decryption."
                )
            else:
                st.error(
                    "Round-trip failure: decrypted content did not match the original plaintext hash."
                )

        tabs = st.tabs(
            [
                "⚡ Performance",
                "🔐 Entropy",
                "💥 Avalanche",
                "✍️ Signature",
                "🧾 Hashes",
                "👁 Output Preview",
                "⬇️ Download",
            ]
        )

        with tabs[0]:
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Enc Time (ms)", f"{result.enc_time_ms:.3f}")
            c2.metric("Dec Time (ms)", f"{result.dec_time_ms:.3f}")
            c3.metric("Total (ms)", f"{result.enc_time_ms + result.dec_time_ms:.3f}")
            c4.metric("Enc RAM (KB)", f"{result.enc_ram_kb:.1f}")
            c5.metric("Throughput", f"{result.enc_throughput_kbps:.1f} KB/s")
            if operation == "both":
                perf_fig = go.Figure(
                    data=[
                        go.Bar(
                            name="Encrypt",
                            x=["Time", "RAM"],
                            y=[result.enc_time_ms, result.enc_ram_kb],
                        ),
                        go.Bar(
                            name="Decrypt",
                            x=["Time", "RAM"],
                            y=[result.dec_time_ms, result.dec_ram_kb],
                        ),
                    ]
                )
                perf_fig.update_layout(barmode="group", title="Encrypt vs decrypt")
                st.plotly_chart(perf_fig, use_container_width=True)

        with tabs[1]:
            stages = [
                ("Plaintext", result.entropy_plaintext),
                ("AES half", result.entropy_aes_half),
                ("ChaCha half", result.entropy_chacha_half),
                ("Ciphertext", result.entropy_final),
            ]
            ecols = st.columns(4)
            for col, (label, value) in zip(ecols, stages):
                col.metric(label, f"{value:.4f}", entropy_label(value))
            byte_fig = px.bar(
                x=list(range(256)),
                y=byte_frequency(result.ciphertext),
                title="Ciphertext byte frequency",
            )
            st.plotly_chart(byte_fig, use_container_width=True)

        with tabs[2]:
            if result.avalanche:
                a1, a2, a3 = st.columns(3)
                a1.metric("Changed bits", f"{result.avalanche.bit_change_pct:.2f}%")
                a2.metric(
                    "Deviation from ideal",
                    f"{result.avalanche.deviation_from_ideal:.2f}%",
                )
                a3.metric("Quality", result.avalanche.label())
                if len(input_data) >= 2:
                    from analysis.avalanche import flip_one_bit
                    from crypto import aes_gcm_engine

                    sample = input_data[: min(512, len(input_data))]
                    c_orig = aes_gcm_engine.encrypt(
                        sample, st.session_state.lab_aes_key
                    )
                    c_flip = aes_gcm_engine.encrypt(
                        flip_one_bit(sample, 0), st.session_state.lab_aes_key
                    )
                    hm_fig = px.imshow(
                        [bit_difference_map(c_orig, c_flip)],
                        aspect="auto",
                        title="Bit-difference heatmap",
                    )
                    st.plotly_chart(hm_fig, use_container_width=True)
            else:
                st.info(
                    "Avalanche analysis is only available for encryption workflows with plaintext input."
                )

        with tabs[3]:
            if sig_algorithm:
                s1, s2, s3 = st.columns(3)
                s1.metric("Signature algorithm", sig_algorithm)
                s2.metric("Signature key", sig_key_param)
                s3.metric("Signature size", f"{result.sig_size_bits} bits")
                st.write(
                    "The signature is embedded in the single downloadable encrypted package."
                )
                if package_signature:
                    st.text_area("Signature HEX", package_signature.hex(), height=140)
                elif algorithm == "hybrid":
                    st.info(
                        "Hybrid payload contains the signature internally inside the ciphertext package."
                    )
            else:
                st.info("No digital signature selected.")

        with tabs[4]:
            h1, h2, h3 = st.columns(3)
            h1.metric(
                "Plaintext hash", "Available" if result.plaintext_sha256 else "N/A"
            )
            h2.metric(
                "Ciphertext hash", "Available" if result.ciphertext_sha256 else "N/A"
            )
            h3.metric(
                "Decrypted hash match",
                "Yes"
                if result.hash_match
                else ("No" if result.hash_match is False else "N/A"),
            )
            if result.plaintext_sha256:
                st.text_input("Plaintext SHA-256", result.plaintext_sha256)
            if result.ciphertext_sha256:
                st.text_input("Ciphertext SHA-256", result.ciphertext_sha256)
            if result.decrypted_sha256:
                st.text_input("Decrypted SHA-256", result.decrypted_sha256)

        with tabs[5]:
            if input_mode == "Text Input":
                st.subheader("Ciphertext shown on page")
                st.code(result.ciphertext.hex())
                if operation == "both":
                    p1, p2 = st.columns(2)
                    p1.text_area(
                        "Original plaintext",
                        input_data.decode("utf-8", errors="replace"),
                        height=180,
                    )
                    p2.text_area(
                        "Decrypted plaintext",
                        result.decrypted.decode("utf-8", errors="replace"),
                        height=180,
                    )
            elif _is_image_file(input_name):
                st.subheader("Encrypted image preview")
                st.image(
                    _encrypted_image_preview(result.ciphertext),
                    caption="Encrypted image visualization",
                    use_column_width=True,
                )
                st.code(hex_preview(result.ciphertext, 256), language="")
                if operation == "both":
                    p1, p2, p3 = st.columns(3)
                    p1.image(
                        input_data, caption="Original image", use_column_width=True
                    )
                    p2.image(
                        _encrypted_image_preview(result.ciphertext),
                        caption="Encrypted image visualization",
                        use_column_width=True,
                    )
                    p3.image(
                        result.decrypted,
                        caption="Decrypted image",
                        use_column_width=True,
                    )
            else:
                st.subheader("Ciphertext HEX preview")
                st.code(hex_preview(result.ciphertext, 512), language="")
                st.write(
                    "For non-text and non-image files, use the single package download below."
                )

        with tabs[6]:
            st.download_button(
                "⬇️ Download encrypted package",
                data=package_bytes,
                file_name=package_name,
                mime="application/octet-stream",
            )
            if operation == "both" and not (
                _is_text_file(input_name) or _is_image_file(input_name)
            ):
                st.download_button(
                    "⬇️ Download decrypted file",
                    data=result.decrypted,
                    file_name=input_name,
                    mime="application/octet-stream",
                )
            st.download_button(
                "⬇️ Download log row (JSON)",
                data=json.dumps(row, indent=2, default=str).encode("utf-8"),
                file_name=f"{row['id']}.json",
                mime="application/json",
            )

else:
    st.header("Step 2 — Current runtime keys", divider="blue")
    sym_key_bits = st.session_state.get("lab_key_sym_bits", 256)
    rsa_key_size = st.session_state.get("lab_key_rsa_size", 2048)
    ecdsa_curve = st.session_state.get("lab_key_ecdsa_curve", "P-256")
    _show_keys(sym_key_bits, rsa_key_size, ecdsa_curve)
    st.info(
        "Decrypt mode accepts only one uploaded CryptoLab encrypted package file. "
        "It will decrypt it using the current runtime keys in this session."
    )

    st.header("Step 3 — Upload encrypted package", divider="blue")
    uploaded_package = st.file_uploader(
        "Upload one encrypted package file", type=["clab", "bin", "enc"]
    )

    if uploaded_package:
        package_bytes = uploaded_package.read()
        try:
            package_header, ciphertext_bytes, signature_bytes = _parse_package(
                package_bytes
            )
        except Exception as exc:
            st.error(f"Invalid package: {exc}")
            st.stop()

        st.subheader("Package metadata")
        st.json(package_header)

        if st.button("▶ Decrypt package", type="primary"):
            algorithm = str(package_header.get("algorithm", "aes_gcm"))
            sig_algorithm = str(package_header.get("sig_algorithm", "") or "") or None
            sig_key_param = str(package_header.get("sig_key_param", "") or "")
            config = EncryptionConfig(
                algorithm=algorithm,
                sym_key_size_bits=int(
                    package_header.get("sym_key_size_bits", 256) or 256
                ),
                sig_algorithm=sig_algorithm,
                sig_key_param=sig_key_param,
                operation="decrypt",
                iterations=1,
            )

            public_pem = (
                st.session_state.lab_rsa_pub
                if sig_algorithm == "RSA"
                else st.session_state.lab_ecdsa_pub
                if sig_algorithm == "ECDSA"
                else None
            )

            with st.spinner("Decrypting package..."):
                result = run_operation(
                    config,
                    ciphertext_bytes,
                    st.session_state.lab_aes_key,
                    st.session_state.lab_chacha_key,
                    None,
                    public_pem,
                    detached_signature=signature_bytes,
                )

            if result.error:
                st.error(f"Decryption failed: {result.error}")
                st.stop()

            result.plaintext_sha256 = str(
                package_header.get("plaintext_sha256", "") or ""
            )
            result.ciphertext_sha256 = str(
                package_header.get("ciphertext_sha256", "")
                or sha256_hex(ciphertext_bytes)
            )
            result.hash_match = (
                bool(result.plaintext_sha256)
                and result.plaintext_sha256 == result.decrypted_sha256
            )

            original_name = str(
                package_header.get("original_filename", "decrypted_output.bin")
            )
            row = build_and_log_row(
                config, uploaded_package.name, package_bytes, original_name, result
            )
            st.success("✅ Decryption complete — logged to `logs/operations.jsonl`")

            h1, h2, h3 = st.columns(3)
            h1.metric("Signature valid", "Yes" if result.sig_valid else "No")
            h2.metric(
                "Decrypted hash available", "Yes" if result.decrypted_sha256 else "No"
            )
            h3.metric("Hash matches original", "Yes" if result.hash_match else "No")

            if result.plaintext_sha256:
                st.text_input(
                    "Original plaintext SHA-256 (from package)", result.plaintext_sha256
                )
            st.text_input("Ciphertext SHA-256", result.ciphertext_sha256)
            st.text_input("Decrypted SHA-256", result.decrypted_sha256)

            if _is_text_file(original_name):
                st.subheader("Recovered text")
                st.text_area(
                    "Plaintext",
                    result.decrypted.decode("utf-8", errors="replace"),
                    height=220,
                )
            elif _is_image_file(original_name):
                st.subheader("Recovered image")
                st.image(result.decrypted, caption=original_name, use_column_width=True)
            else:
                st.info("Recovered file is ready to download below.")

            st.download_button(
                "⬇️ Download decrypted original file",
                data=result.decrypted,
                file_name=original_name,
                mime="application/octet-stream",
            )
            st.download_button(
                "⬇️ Download log row (JSON)",
                data=json.dumps(row, indent=2, default=str).encode("utf-8"),
                file_name=f"{row['id']}.json",
                mime="application/json",
            )
