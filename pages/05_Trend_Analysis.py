"""Page 5 — Trend Analysis

Research dashboard loaded from logs/operations.jsonl.
Provides heatmaps, distributions, algorithm recommendations, and CSV export.
"""

from __future__ import annotations

from datetime import date

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from storage.log_store import clear_log, export_csv, load_all

st.set_page_config(page_title="Trend Analysis — CryptoLab", layout="wide")
st.title("📊 Trend Analysis")
st.caption(
    "Research dashboard — analyze all logged operations from the JSONL log to discover which algorithms, key sizes, and signatures perform best."
)

# ─────────────────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────────────────
df_raw = load_all()

if df_raw.empty:
    st.info(
        "No logged operations yet. Run some encryptions in the **Encryption Lab**, **Algorithm Comparator**, or **Batch Runner** to populate this dashboard."
    )
    st.stop()

# ─────────────────────────────────────────────────────────
# SIDEBAR FILTERS
# ─────────────────────────────────────────────────────────
with st.sidebar:
    st.header("🔍 Filters")

    all_algos = sorted(df_raw["algorithm"].dropna().unique())
    sel_algos = st.multiselect(
        "Algorithm", all_algos, default=all_algos, key="trend_algos"
    )

    all_key_sizes = sorted(df_raw["sym_key_size_bits"].dropna().unique())
    sel_key_sizes = st.multiselect(
        "Key Size (bits)", all_key_sizes, default=all_key_sizes, key="trend_ks"
    )

    all_sigs = sorted(df_raw["sig_algorithm"].fillna("None").unique())
    sel_sigs = st.multiselect("Signature", all_sigs, default=all_sigs, key="trend_sig")

    all_cats = sorted(df_raw["input_file_category"].dropna().unique())
    sel_cats = st.multiselect(
        "File Category", all_cats, default=all_cats, key="trend_cat"
    )

    all_ops = ["encrypt", "decrypt", "both"]
    sel_ops = st.multiselect("Operation", all_ops, default=all_ops, key="trend_op")

    min_ts = df_raw["timestamp"].min()
    max_ts = df_raw["timestamp"].max()
    if pd.notna(min_ts) and pd.notna(max_ts):
        date_range = st.date_input(
            "Date Range",
            value=(min_ts.date(), max_ts.date()),
            key="trend_date",
        )
    else:
        date_range = None

    size_min = (
        float(df_raw["input_size_kb"].min())
        if df_raw["input_size_kb"].notna().any()
        else 0.0
    )
    size_max = (
        float(df_raw["input_size_kb"].max())
        if df_raw["input_size_kb"].notna().any()
        else 1.0
    )
    size_max = max(size_max, size_min + 0.1)
    size_range = st.slider(
        "Input Size (KB)", size_min, size_max, (size_min, size_max), key="trend_size"
    )

# ─────────────────────────────────────────────────────────
# APPLY FILTERS
# ─────────────────────────────────────────────────────────
df = df_raw.copy()

if sel_algos:
    df = df[df["algorithm"].isin(sel_algos)]
if sel_key_sizes:
    df = df[df["sym_key_size_bits"].isin(sel_key_sizes)]
if sel_cats:
    df = df[df["input_file_category"].isin(sel_cats)]
if sel_ops:
    df = df[df["operation"].isin(sel_ops)]
if sel_sigs:
    df["sig_col"] = df["sig_algorithm"].fillna("None")
    df = df[df["sig_col"].isin(sel_sigs)]
if date_range and isinstance(date_range, (list, tuple)) and len(date_range) == 2:
    start_ts = pd.Timestamp(date_range[0])
    end_ts = pd.Timestamp(date_range[1]) + pd.Timedelta(days=1)
    df = df[(df["timestamp"] >= start_ts) & (df["timestamp"] < end_ts)]
if "input_size_kb" in df.columns:
    df = df[
        (df["input_size_kb"] >= size_range[0]) & (df["input_size_kb"] <= size_range[1])
    ]

if df.empty:
    st.warning("No data matches the selected filters. Adjust the sidebar filters.")
    st.stop()

# ─────────────────────────────────────────────────────────
# OVERVIEW METRICS
# ─────────────────────────────────────────────────────────
st.header("Overview", divider="blue")
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Operations", len(df))
c2.metric("Unique Algorithms", df["algorithm"].nunique())
c3.metric("File Categories", df["input_file_category"].nunique())
c4.metric(
    "Avg Enc Time (ms)",
    f"{df['enc_time_ms'].mean():.3f}" if "enc_time_ms" in df else "—",
)
c5.metric(
    "Avg Throughput (KB/s)",
    f"{df['enc_throughput_kbps'].mean():.0f}" if "enc_throughput_kbps" in df else "—",
)

# ─────────────────────────────────────────────────────────
# ALGORITHM DISPLAY LABELS
# ─────────────────────────────────────────────────────────
ALGO_LABELS = {
    "aes_gcm": "AES-GCM",
    "chacha20_poly1305": "ChaCha20-Poly1305",
    "hybrid": "Hybrid",
}
if "algorithm" in df.columns:
    df["algo_label"] = df["algorithm"].map(ALGO_LABELS).fillna(df["algorithm"])

df["key_size_label"] = df["sym_key_size_bits"].apply(
    lambda x: f"{int(x)}-bit" if pd.notna(x) else "?"
)

# ─────────────────────────────────────────────────────────
# SUMMARY STATISTICS TABLE
# ─────────────────────────────────────────────────────────
st.header("📋 Summary Statistics by Algorithm", divider="blue")

agg_cols = {
    "enc_time_ms": ["mean", "std"],
    "dec_time_ms": ["mean"],
    "enc_throughput_kbps": ["mean", "std"],
    "enc_ram_kb": ["mean"],
    "avalanche_pct": ["mean"],
    "entropy_final": ["mean"],
    "ciphertext_expansion_pct": ["mean"],
    "byte_freq_std_dev": ["mean"],
}
valid_agg = {k: v for k, v in agg_cols.items() if k in df.columns}

if valid_agg:
    group_cols = ["algo_label", "key_size_label"]
    group_cols = [c for c in group_cols if c in df.columns]
    summary = df.groupby(group_cols).agg(valid_agg).round(3)
    summary.columns = ["_".join(c).strip("_") for c in summary.columns]
    summary["Count"] = df.groupby(group_cols).size()
    summary = summary.reset_index()
    summary.columns = [
        c.replace("_mean", " (avg)").replace("_std", " (std)") for c in summary.columns
    ]
    st.dataframe(summary, use_container_width=True)

# ─────────────────────────────────────────────────────────
# CHARTS
# ─────────────────────────────────────────────────────────
st.header("📈 Charts", divider="blue")

chart_tabs = st.tabs(
    [
        "⚡ Performance",
        "💾 Throughput",
        "🔐 Entropy",
        "💥 Avalanche",
        "🗂 By File Type",
        "📅 Over Time",
        "🔥 Heatmaps",
    ]
)

# ── Performance ─────────────────────────────────────────
with chart_tabs[0]:
    if "enc_time_ms" in df.columns:
        fig = px.box(
            df,
            x="algo_label",
            y="enc_time_ms",
            color="key_size_label",
            title="Encryption Time Distribution per Algorithm",
            labels={
                "algo_label": "Algorithm",
                "enc_time_ms": "Enc Time (ms)",
                "key_size_label": "Key Size",
            },
        )
        fig.update_layout(
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
        )
        st.plotly_chart(fig, use_container_width=True)

        if "input_size_kb" in df.columns:
            fig_s = px.scatter(
                df,
                x="input_size_kb",
                y="enc_time_ms",
                color="algo_label",
                title="File Size vs Encryption Time",
                labels={
                    "input_size_kb": "Input Size (KB)",
                    "enc_time_ms": "Enc Time (ms)",
                },
            )
            fig_s.update_layout(
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
            )
            st.plotly_chart(fig_s, use_container_width=True)

# ── Throughput ───────────────────────────────────────────
with chart_tabs[1]:
    if "enc_throughput_kbps" in df.columns:
        fig_tp = px.box(
            df,
            x="algo_label",
            y="enc_throughput_kbps",
            color="key_size_label",
            title="Throughput Distribution (KB/s)",
            labels={
                "algo_label": "Algorithm",
                "enc_throughput_kbps": "Throughput (KB/s)",
            },
        )
        fig_tp.update_layout(
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
        )
        st.plotly_chart(fig_tp, use_container_width=True)

        if "input_size_kb" in df.columns:
            fig_scale = px.scatter(
                df,
                x="input_size_kb",
                y="enc_throughput_kbps",
                color="algo_label",
                title="File Size vs Throughput (Scaling Curve)",
                labels={
                    "input_size_kb": "Input Size (KB)",
                    "enc_throughput_kbps": "Throughput (KB/s)",
                },
            )
            fig_scale.update_layout(
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
            )
            st.plotly_chart(fig_scale, use_container_width=True)

# ── Entropy ──────────────────────────────────────────────
with chart_tabs[2]:
    if "entropy_final" in df.columns:
        fig_ent = px.box(
            df,
            x="algo_label",
            y="entropy_final",
            color="key_size_label",
            title="Final Ciphertext Entropy Distribution (bits/byte)",
            range_y=[6, 8.2],
            labels={"algo_label": "Algorithm", "entropy_final": "Entropy (bits/byte)"},
        )
        fig_ent.add_hline(
            y=8.0, line_dash="dash", line_color="green", annotation_text="Max (8.0)"
        )
        fig_ent.add_hline(
            y=7.5, line_dash="dot", line_color="orange", annotation_text="Good (7.5)"
        )
        fig_ent.update_layout(
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
        )
        st.plotly_chart(fig_ent, use_container_width=True)

    if "byte_freq_std_dev" in df.columns:
        fig_bfsd = px.box(
            df,
            x="algo_label",
            y="byte_freq_std_dev",
            color="key_size_label",
            title="Byte Frequency Std Dev (lower = more uniform ciphertext)",
            labels={"algo_label": "Algorithm", "byte_freq_std_dev": "Byte Freq σ"},
        )
        fig_bfsd.update_layout(
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
        )
        st.plotly_chart(fig_bfsd, use_container_width=True)

# ── Avalanche ────────────────────────────────────────────
with chart_tabs[3]:
    if "avalanche_pct" in df.columns:
        ava_df = df.dropna(subset=["avalanche_pct"])
        if not ava_df.empty:
            fig_av = px.box(
                ava_df,
                x="algo_label",
                y="avalanche_pct",
                color="key_size_label",
                title="Avalanche Effect Distribution (ideal = 50%)",
                labels={"algo_label": "Algorithm", "avalanche_pct": "Avalanche (%)"},
            )
            fig_av.add_hline(
                y=50,
                line_dash="dash",
                line_color="green",
                annotation_text="Ideal (50%)",
            )
            fig_av.add_hrect(
                y0=40,
                y1=60,
                fillcolor="green",
                opacity=0.1,
                annotation_text="Good range",
            )
            fig_av.update_layout(
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
            )
            st.plotly_chart(fig_av, use_container_width=True)

        if "ciphertext_expansion_pct" in df.columns:
            fig_exp = px.box(
                df,
                x="algo_label",
                y="ciphertext_expansion_pct",
                color="key_size_label",
                title="Ciphertext Expansion % (overhead per algorithm)",
                labels={
                    "algo_label": "Algorithm",
                    "ciphertext_expansion_pct": "Expansion (%)",
                },
            )
            fig_exp.update_layout(
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
            )
            st.plotly_chart(fig_exp, use_container_width=True)

# ── By File Type ─────────────────────────────────────────
with chart_tabs[4]:
    if "input_file_category" in df.columns and "enc_time_ms" in df.columns:
        cat_time = (
            df.groupby(["input_file_category", "algo_label"])["enc_time_ms"]
            .mean()
            .reset_index()
        )
        fig_cat = px.bar(
            cat_time,
            x="input_file_category",
            y="enc_time_ms",
            color="algo_label",
            barmode="group",
            title="Average Enc Time by File Category",
            labels={
                "input_file_category": "File Category",
                "enc_time_ms": "Avg Enc Time (ms)",
            },
        )
        fig_cat.update_layout(
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
        )
        st.plotly_chart(fig_cat, use_container_width=True)

    if "enc_throughput_kbps" in df.columns:
        cat_tp = (
            df.groupby(["input_file_category", "algo_label"])["enc_throughput_kbps"]
            .mean()
            .reset_index()
        )
        fig_cat_tp = px.bar(
            cat_tp,
            x="input_file_category",
            y="enc_throughput_kbps",
            color="algo_label",
            barmode="group",
            title="Average Throughput by File Category",
            labels={
                "input_file_category": "File Category",
                "enc_throughput_kbps": "Throughput (KB/s)",
            },
        )
        fig_cat_tp.update_layout(
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
        )
        st.plotly_chart(fig_cat_tp, use_container_width=True)

# ── Over Time ────────────────────────────────────────────
with chart_tabs[5]:
    if "timestamp" in df.columns and "enc_time_ms" in df.columns:
        df["day"] = df["timestamp"].dt.date
        time_df = df.groupby(["day", "algo_label"])["enc_time_ms"].mean().reset_index()
        fig_tl = px.line(
            time_df,
            x="day",
            y="enc_time_ms",
            color="algo_label",
            title="Average Enc Time Over Time",
            labels={"day": "Date", "enc_time_ms": "Avg Enc Time (ms)"},
        )
        fig_tl.update_layout(
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
        )
        st.plotly_chart(fig_tl, use_container_width=True)

    if "enc_throughput_kbps" in df.columns:
        tp_df = (
            df.groupby(["day", "algo_label"])["enc_throughput_kbps"]
            .mean()
            .reset_index()
        )
        fig_tl2 = px.line(
            tp_df,
            x="day",
            y="enc_throughput_kbps",
            color="algo_label",
            title="Average Throughput Over Time",
            labels={"day": "Date", "enc_throughput_kbps": "Avg Throughput (KB/s)"},
        )
        fig_tl2.update_layout(
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
        )
        st.plotly_chart(fig_tl2, use_container_width=True)

# ── Heatmaps ─────────────────────────────────────────────
with chart_tabs[6]:
    if "input_file_category" in df.columns and "algo_label" in df.columns:
        if "enc_throughput_kbps" in df.columns:
            pivot_tp = (
                df.groupby(["algo_label", "input_file_category"])["enc_throughput_kbps"]
                .mean()
                .unstack(fill_value=0)
            )
            fig_hm1 = px.imshow(
                pivot_tp,
                title="Throughput (KB/s) — Algorithm × File Category",
                color_continuous_scale="Blues",
                text_auto=".0f",
                labels={"x": "File Category", "y": "Algorithm", "color": "KB/s"},
            )
            fig_hm1.update_layout(
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
            )
            st.plotly_chart(fig_hm1, use_container_width=True)

        if "enc_time_ms" in df.columns and "sym_key_size_bits" in df.columns:
            pivot_time = (
                df.groupby(["algo_label", "key_size_label"])["enc_time_ms"]
                .mean()
                .unstack(fill_value=0)
            )
            fig_hm2 = px.imshow(
                pivot_time,
                title="Avg Enc Time (ms) — Algorithm × Key Size",
                color_continuous_scale="Reds",
                text_auto=".2f",
                labels={"x": "Key Size", "y": "Algorithm", "color": "ms"},
            )
            fig_hm2.update_layout(
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
            )
            st.plotly_chart(fig_hm2, use_container_width=True)

        if "entropy_final" in df.columns:
            pivot_ent = (
                df.groupby(["algo_label", "input_file_category"])["entropy_final"]
                .mean()
                .unstack(fill_value=0)
            )
            fig_hm3 = px.imshow(
                pivot_ent,
                title="Avg Final Entropy — Algorithm × File Category",
                color_continuous_scale="Greens",
                text_auto=".3f",
                labels={"x": "File Category", "y": "Algorithm", "color": "Entropy"},
            )
            fig_hm3.update_layout(
                plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="white"
            )
            st.plotly_chart(fig_hm3, use_container_width=True)

# ─────────────────────────────────────────────────────────
# ALGORITHM RECOMMENDATION
# ─────────────────────────────────────────────────────────
st.header("🏆 Algorithm Recommendations", divider="green")
st.caption(
    "Based on logged data — identifies the best-performing algorithm per file category and metric."
)

if "input_file_category" in df.columns and not df.empty:
    cats = df["input_file_category"].dropna().unique()
    recs: list[dict] = []

    for cat in sorted(cats):
        cat_df = df[df["input_file_category"] == cat]
        if cat_df.empty:
            continue

        rec: dict = {"File Category": cat}

        if "enc_throughput_kbps" in cat_df.columns:
            best_tp = (
                cat_df.groupby("algo_label")["enc_throughput_kbps"].mean().idxmax()
            )
            rec["Fastest Throughput"] = str(best_tp)

        if "enc_time_ms" in cat_df.columns:
            best_time = cat_df.groupby("algo_label")["enc_time_ms"].mean().idxmin()
            rec["Lowest Enc Time"] = str(best_time)

        if "enc_ram_kb" in cat_df.columns:
            best_ram = cat_df.groupby("algo_label")["enc_ram_kb"].mean().idxmin()
            rec["Lowest RAM"] = str(best_ram)

        if "avalanche_pct" in cat_df.columns:
            ava_sub = cat_df.dropna(subset=["avalanche_pct"])
            if not ava_sub.empty:
                # Best avalanche = closest to 50%
                best_ava = (
                    ava_sub.groupby("algo_label")["avalanche_pct"]
                    .apply(lambda s: (s - 50).abs().mean())
                    .idxmin()
                )
                rec["Best Avalanche"] = str(best_ava)

        if "entropy_final" in cat_df.columns:
            best_ent = cat_df.groupby("algo_label")["entropy_final"].mean().idxmax()
            rec["Highest Entropy"] = str(best_ent)

        recs.append(rec)

    if recs:
        rec_df = pd.DataFrame(recs).set_index("File Category")
        st.dataframe(rec_df, use_container_width=True)
        st.caption(
            "These recommendations are based on average performance across all logged operations matching the current filters."
        )

# ─────────────────────────────────────────────────────────
# RAW DATA TABLE
# ─────────────────────────────────────────────────────────
st.header("🗃 Raw Data", divider="blue")

display_cols = [
    "timestamp",
    "algo_label",
    "key_size_label",
    "sig_algorithm",
    "input_file_category",
    "input_size_kb",
    "enc_time_ms",
    "dec_time_ms",
    "enc_throughput_kbps",
    "enc_ram_kb",
    "entropy_final",
    "avalanche_pct",
    "ciphertext_expansion_pct",
    "sig_valid",
    "hash_match",
    "memory_backend",
]
display_cols = [c for c in display_cols if c in df.columns]
st.dataframe(
    df[display_cols].sort_values("timestamp", ascending=False), use_container_width=True
)

# ─────────────────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────────────────
st.header("⬇️ Export", divider="blue")

col_exp1, col_exp2 = st.columns(2)
with col_exp1:
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download Filtered Data (CSV)",
        csv_bytes,
        file_name="trend_export.csv",
        mime="text/csv",
    )

with col_exp2:
    json_bytes = df.to_json(orient="records", date_format="iso", indent=2).encode(
        "utf-8"
    )
    st.download_button(
        "⬇️ Download Filtered Data (JSON)",
        json_bytes,
        file_name="trend_export.json",
        mime="application/json",
    )

st.divider()
if st.button("🗑️ Clear All Log Data (irreversible)", type="secondary"):
    confirm = st.checkbox("I confirm I want to delete all log data")
    if confirm:
        clear_log()
        st.success("Log cleared. Refresh the page.")
