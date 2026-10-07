"""Anomaly queue: every flagged event, filterable, with one-click investigation."""

import streamlit as st

from components.tables import filter_events, render_event_table
from components.ui import callout, kpi_card, page_header
from services.analysis_service import AnalysisService
from services.ml_pipeline import explain_event
from utils.helpers import goto


def render() -> None:
    res = AnalysisService.ensure_loaded()
    ev = res.events
    a = ev[ev["status"] == "ANOMALY"]
    page_header("Anomalies", "Events flagged as anomalous, ranked for analyst triage")

    c = st.columns(2)
    with c[0]: kpi_card("Anomalies", f"{len(a):,}", f"{res.anomaly_rate():.2f}% of all events", "red")
    with c[1]: kpi_card("Critical + High", f"{res.high_risk_events:,}", "triage first", "orange")
    st.markdown("<div style='height:.8rem'></div>", unsafe_allow_html=True)

    if a.empty:
        st.success("No anomalies were detected with the current detection parameters.")
        return

    callout("Select a cell for a quick explanation, then open it in Investigation.")
    f = filter_events(ev, "an", anomaly_default=True)
    sel = render_event_table(
        f, "an", res.dataset_info.has_year, selectable=True, selection_mode="single-cell",
    )

    if sel:
        x = explain_event(res, sel)
        row = x["row"]
        st.markdown(f"**{sel}** · {row['service']} · {row['event_class']} · risk {row['risk_score']:.2f}")
        st.write(x["headline"])
        if st.button("Open full investigation", type="primary", key="an_open"):
            goto("Investigation", selected_event=sel)
