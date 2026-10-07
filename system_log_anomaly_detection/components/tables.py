"""SOC event table: search, filters, sorting, pagination and row selection."""

from typing import Literal

import pandas as pd
import streamlit as st

from utils.helpers import SEV_COLORS, fmt_ts_series

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_TINT = {"CRITICAL": "rgba(239,68,68,.17)", "HIGH": "rgba(249,115,22,.12)", "MEDIUM": "rgba(234,179,8,.07)"}
SORTS = {
    "Newest first": ("timestamp", False), "Oldest first": ("timestamp", True),
    "Highest risk": ("risk_score", False), "Lowest risk": ("risk_score", True),
}


def filter_events(df: pd.DataFrame, key: str, anomaly_default: bool = False) -> pd.DataFrame:
    """Render the filter bar and return the filtered + sorted frame."""
    c1, c2, c3, c4 = st.columns([2.2, 1.4, 1.3, 1.4])
    q = c1.text_input("Search", key=f"{key}_q", placeholder="message, service, host, user or event id")
    services = c2.multiselect("Service", sorted(df["service"].unique()), key=f"{key}_svc")
    sev = c3.multiselect("Severity", SEV_ORDER, key=f"{key}_sev")
    cls = c4.multiselect("Event", sorted(df["event_class"].unique()), key=f"{key}_cls")
    c5, c6 = st.columns([2.2, 1.4])
    status = c5.radio("Status", ["All", "Anomalies only", "Normal only"], index=1 if anomaly_default else 0,
                      horizontal=True, key=f"{key}_status")
    sort = c6.selectbox("Sort", list(SORTS), key=f"{key}_sort")

    f = df
    if q:
        ql = q.strip()
        hit = (f["message"].str.contains(ql, case=False, regex=False)
               | f["service"].str.contains(ql, case=False, regex=False)
               | f["event_id"].str.contains(ql, case=False, regex=False)
               | f["src_host"].fillna("").str.contains(ql, case=False, regex=False)
               | f["target_user"].fillna("").str.contains(ql, case=False, regex=False))
        f = f[hit]
    if services:
        f = f[f["service"].isin(services)]
    if sev:
        f = f[f["severity"].isin(sev)]
    if cls:
        f = f[f["event_class"].isin(cls)]
    if status == "Anomalies only":
        f = f[f["status"] == "ANOMALY"]
    elif status == "Normal only":
        f = f[f["status"] == "NORMAL"]
    col, asc = SORTS[sort]
    return f.sort_values(col, ascending=asc, kind="stable")


def _display_frame(page: pd.DataFrame, has_year: bool) -> pd.DataFrame:
    columns = {
        "ID": page["event_id"].values,
        "Timestamp": fmt_ts_series(page["timestamp"], has_year).values,
        "Severity": page["severity"].values,
        "Service": page["service"].values,
        "Event": page["event_class"].values,
        "Status": page["status"].values,
        "Risk Score": page["risk_score"].values,
        "Message": page["message"].str.slice(0, 140).values,
    }
    return pd.DataFrame(columns)


def _style(frame: pd.DataFrame):
    def row(r):
        return [f"background-color:{_TINT.get(r['Severity'], '')}"] * len(r)

    def sev(v):
        return f"color:{SEV_COLORS.get(v, '#c3cfdf')};font-weight:600"

    def status(v):
        return "color:#fca5a5;font-weight:600" if v == "ANOMALY" else "color:#86efac"

    return frame.style.apply(row, axis=1).map(sev, subset=["Severity"]).map(status, subset=["Status"])


def render_event_table(df: pd.DataFrame, key: str, has_year: bool = True, selectable: bool = False,
                       default_page_size: int = 25,
                       selection_mode: Literal["single-row", "single-cell"] = "single-row"):
    """Paginated table. Returns the selected event_id (or None) when `selectable`."""
    total = len(df)
    c1, c2, c3 = st.columns([1.2, 1.2, 4])
    sizes = [25, 50, 100, 200]
    page_size = c1.selectbox("Rows per page", sizes, index=sizes.index(default_page_size), key=f"{key}_ps")
    pages = max(1, -(-total // page_size))
    page_no = c2.number_input("Page", min_value=1, max_value=pages, value=1, step=1, key=f"{key}_pg")
    c3.markdown(f"<div style='padding-top:1.9rem;color:#8190a6;font-size:.82rem'>{total:,} matching events · page {page_no} of {pages}</div>",
                unsafe_allow_html=True)
    if total == 0:
        st.info("No events match the current filters.")
        return None

    start = (int(page_no) - 1) * page_size
    page = df.iloc[start:start + page_size]
    frame = _display_frame(page, has_year)
    cfg = {"Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0.0, max_value=1.0, format="%.2f"),
           "Message": st.column_config.TextColumn("Message", width="large")}
    try:
        shown = _style(frame)
    except Exception:
        shown = frame
    kwargs = dict(use_container_width=True, hide_index=True, column_config=cfg,
                  height=min(36 * (len(frame) + 1) + 3, 640), key=f"{key}_tbl")
    if selectable:
        ev = st.dataframe(shown, on_select="rerun", selection_mode=selection_mode, **kwargs)
        if ev is None:
            rows = []
        elif selection_mode == "single-cell":
            rows = [row for row, _ in ev.selection.cells]
        else:
            rows = ev.selection.rows
        return page.iloc[rows[0]]["event_id"] if rows else None
    st.dataframe(shown, **kwargs)
    return None
