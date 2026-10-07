"""Log Explorer: browse and search every parsed Linux log event."""

import streamlit as st

from components.tables import filter_events, render_event_table
from components.ui import dataset_chips, page_header
from services.analysis_service import AnalysisService
from utils.helpers import fmt_ts_series, goto


def render() -> None:
    res = AnalysisService.ensure_loaded()
    page_header("Log Explorer", "Search, filter and sort all parsed Linux log events")
    dataset_chips(res.dataset_info)
    f = filter_events(res.events, "lx", anomaly_default=False)
    sel = render_event_table(
        f, "lx", res.dataset_info.has_year, selectable=True, selection_mode="single-cell"
    )
    c1, c2, _ = st.columns([1.3, 1.6, 4])
    if sel and c1.button(f"🔍 Investigate {sel}", type="primary", key="lx_inv"):
        goto("Investigation", selected_event=sel)
    export = f[["event_id", "timestamp", "hostname", "service", "event_class", "severity", "status",
                "risk_score", "message"]].copy()
    export["timestamp"] = fmt_ts_series(export["timestamp"], res.dataset_info.has_year)
    c2.download_button("⬇ Export filtered events (CSV)", export.to_csv(index=False).encode("utf-8"),
                       "linux_log_events_filtered.csv", "text/csv", key="lx_dl")
