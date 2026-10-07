"""SOC Overview: KPIs, trend, risk distribution, top suspicious services/events, recent events."""

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import charts
from components.tables import filter_events, render_event_table
from components.ui import dataset_chips, kpi_card, page_header, stage_card
from services.analysis_service import AnalysisService
from services.anomaly_alerts import find_anomaly_burst
from utils.helpers import TIME_RANGES, filter_time_range

_CFG = {"displayModeBar": False}


def render() -> None:
    res = AnalysisService.ensure_loaded()
    info = res.dataset_info
    page_header("Linux SOC Monitor", "Linux System Log Anomaly Detection & Security Analytics", status=True)
    dataset_chips(info)

    alert_threshold = int(st.session_state.get("anomaly_alert_threshold", 10))
    alert_window = int(st.session_state.get("anomaly_alert_window_minutes", 5))
    burst = find_anomaly_burst(res.events, alert_threshold, alert_window)
    if burst:
        count, start, end = burst
        st.error(
            f"High anomaly volume detected: {count} anomalies occurred within "
            f"{alert_window} minutes ({start:%Y-%m-%d %H:%M:%S} to {end:%Y-%m-%d %H:%M:%S}). "
            "Review the events immediately. If you suspect active compromise, follow your incident "
            "response plan to isolate or safely shut down the affected host."
        )

    rng = st.radio("Time range", TIME_RANGES, index=len(TIME_RANGES) - 1, horizontal=True, key="ov_range")
    df = filter_time_range(res.events, rng)
    if df.empty:
        st.info("No Linux log events fall inside this time range. Choose a wider range.")
        return

    anomalies = df[df["status"] == "ANOMALY"]
    n, a = len(df), len(anomalies)
    high = int(anomalies["severity"].isin(["HIGH", "CRITICAL"]).sum())

    cols = st.columns(6)
    with cols[0]: kpi_card("Total Linux logs", f"{n:,}", f"{rng.lower()}")
    with cols[1]: kpi_card("Normal events", f"{n - a:,}", f"{(n - a) / n * 100:.1f}% of events", "green")
    with cols[2]: kpi_card("Anomalies detected", f"{a:,}", "detected in scope", "red")
    with cols[3]: kpi_card("Anomaly rate", f"{a / n * 100:.2f}%", "anomalous ÷ total", "amber")
    with cols[4]: kpi_card("High-risk events", f"{high:,}", "HIGH + CRITICAL anomalies", "orange")
    with cols[5]: kpi_card("Services monitored", f"{df['service'].nunique():,}", "distinct Linux services")

    st.markdown("<div style='height:.9rem'></div>", unsafe_allow_html=True)
    left, right = st.columns([1.2, 1.2])
    with left:
        st.markdown("### Event relationship — normal vs anomalous")
        pie_normal = go.Figure(go.Pie(labels=["Normal", "Anomalous"], values=[n - a, a], hole=0.5,
                                     marker=dict(colors=["#22c55e", "#ef4444"]), sort=False,
                                     textinfo="label+percent", textfont=dict(color="white")))
        pie_normal.update_layout(margin=dict(l=10, r=10, t=10, b=10), showlegend=False)
        st.plotly_chart(pie_normal, use_container_width=True, config=_CFG)
    with right:
        st.markdown("### Severity mix — anomalous events")
        sev_counts = anomalies["severity"].value_counts().reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0)
        pie_sev = go.Figure(go.Pie(labels=[s for s in sev_counts.index if sev_counts.get(s, 0) > 0],
                                  values=[sev_counts.get(s, 0) for s in sev_counts.index if sev_counts.get(s, 0) > 0],
                                  hole=0.5,
                                  marker=dict(colors=["#ef4444", "#f97316", "#eab308", "#38bdf8"]), sort=False,
                                  textinfo="label+percent", textfont=dict(color="white")))
        pie_sev.update_layout(margin=dict(l=10, r=10, t=10, b=10), showlegend=False)
        st.plotly_chart(pie_sev, use_container_width=True, config=_CFG)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("### Top suspicious services")
        st.plotly_chart(charts.top_bar(anomalies["service"].value_counts(), "#38bdf8"), use_container_width=True, config=_CFG)
    with c2:
        st.markdown("### Top suspicious events")
        st.plotly_chart(charts.top_bar(anomalies["event_class"].value_counts(), "#f97316"), use_container_width=True, config=_CFG)
    with c3:
        st.markdown("### Top source hosts (auth failures)")
        src = anomalies[anomalies["event_class"] == "AUTH_FAIL"]["src_host"].dropna().value_counts()
        if src.empty:
            st.caption("No anomalous authentication failures with a source host in this range.")
        else:
            st.plotly_chart(charts.top_bar(src, "#ef4444"), use_container_width=True, config=_CFG)

    st.markdown("### Recent security events")
    f = filter_events(df, "ov", anomaly_default=True)
    render_event_table(f, "ov", info.has_year, selectable=False, default_page_size=25)
