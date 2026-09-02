from __future__ import annotations

import json
from datetime import date

import pandas as pd
import plotly.express as px
import streamlit as st

from lab_core import classify_extension
from storage.log_store import clear_log, load_all

st.title("Trend Dashboard")

rows = load_all()
if not rows:
    st.info("No logged operations yet.")
    st.stop()

raw_df = pd.json_normalize(rows)
# Logged timestamps carry a Z suffix and parse as tz-aware; the date filter
# below builds naive Timestamps, so drop the tz to keep comparisons valid.
raw_df["timestamp"] = pd.to_datetime(raw_df["timestamp"], errors="coerce", utc=True).dt.tz_localize(None)
raw_df["file_type"] = raw_df["input.extension"].fillna("").apply(classify_extension)

algos = sorted(raw_df["algorithm"].dropna().unique().tolist())
sel_algos = st.sidebar.multiselect("Algorithm", algos, default=algos)

min_date = raw_df["timestamp"].min().date() if not raw_df["timestamp"].isna().all() else date.today()
max_date = raw_df["timestamp"].max().date() if not raw_df["timestamp"].isna().all() else date.today()
date_range = st.sidebar.date_input("Date range", value=(min_date, max_date))

file_types = sorted(raw_df["file_type"].dropna().unique().tolist())
sel_types = st.sidebar.multiselect("File type", file_types, default=file_types)

op_type = st.sidebar.selectbox("Operation", ["Both", "encrypt", "decrypt"])

mask = raw_df["algorithm"].isin(sel_algos) & raw_df["file_type"].isin(sel_types)
if isinstance(date_range, tuple) and len(date_range) == 2:
    start_ts = pd.Timestamp(date_range[0])
    end_ts = pd.Timestamp(date_range[1]) + pd.Timedelta(days=1)
    mask &= (raw_df["timestamp"] >= start_ts) & (raw_df["timestamp"] < end_ts)
if op_type != "Both":
    mask &= raw_df["operation"] == op_type

df = raw_df[mask].copy()
if df.empty:
    st.warning("No data after filters.")
    st.stop()

df["day"] = df["timestamp"].dt.date

fig1 = px.line(
    df.groupby(["day", "algorithm"], as_index=False)["performance.enc_time_ms"].mean(),
    x="day",
    y="performance.enc_time_ms",
    color="algorithm",
    title="Average Encryption Time Over Time",
)
fig2 = px.line(
    df.groupby(["day", "algorithm"], as_index=False)["performance.enc_ram_kb"].mean(),
    x="day",
    y="performance.enc_ram_kb",
    color="algorithm",
    title="Average RAM Usage Over Time",
)
fig3 = px.scatter(
    df,
    x="input.size_kb",
    y="performance.enc_time_ms",
    color="algorithm",
    title="File Size vs Encryption Time",
)
fig4 = px.bar(
    df.groupby("algorithm", as_index=False).size(),
    x="algorithm",
    y="size",
    title="Operations by Algorithm",
)
fig5 = px.box(df, x="algorithm", y="security.entropy_stages.final_combined_ciphertext", title="Entropy Distribution")
fig6 = px.bar(
    df.groupby("file_type", as_index=False)["performance.enc_time_ms"].mean(),
    x="file_type",
    y="performance.enc_time_ms",
    title="Average Encryption Time by File Type",
)

for fig in [fig1, fig2, fig3, fig4, fig5, fig6]:
    st.plotly_chart(fig, use_container_width=True)

view_cols = [
    "timestamp",
    "algorithm",
    "file_type",
    "input.size_kb",
    "performance.enc_time_ms",
    "performance.dec_time_ms",
    "performance.enc_ram_kb",
    "security.entropy_stages.final_combined_ciphertext",
    "security.signature_valid",
]
st.dataframe(df[view_cols], use_container_width=True)

csv_bytes = df.to_csv(index=False).encode("utf-8")
json_bytes = df.to_json(orient="records", date_format="iso", indent=2).encode("utf-8")

st.download_button("Download filtered CSV", csv_bytes, file_name="filtered_trends.csv")
st.download_button("Download filtered JSON", json_bytes, file_name="filtered_trends.json")

if st.button("Clear log (irreversible)"):
    clear_log()
    st.success("Log cleared.")
