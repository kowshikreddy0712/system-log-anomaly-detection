"""Settings for the unsupervised Linux anomaly pipeline."""

import streamlit as st

from components.sidebar import CLEAR_ON_LOGOUT
from components.ui import page_header
from services.analysis_service import AnalysisService
from services.ml_pipeline import SEV_THRESHOLDS


def render() -> None:
    AnalysisService.ensure_loaded()
    page_header("Settings", "Manage alerts and account settings")

    st.markdown("### High anomaly volume alert")
    st.caption(
        "Alert when the analyzed event timestamps contain this many anomalies within the selected window. "
        "This checks the active dataset; it does not continuously collect new logs or shut down a host."
    )
    with st.form("anomaly_alert_settings"):
        alert_cols = st.columns(2)
        alert_threshold = alert_cols[0].number_input(
            "Anomaly count threshold",
            min_value=2,
            max_value=10000,
            value=int(st.session_state.get("anomaly_alert_threshold", 10)),
            step=1,
        )
        alert_window = alert_cols[1].number_input(
            "Time window (minutes)",
            min_value=1,
            max_value=1440,
            value=int(st.session_state.get("anomaly_alert_window_minutes", 5)),
            step=1,
        )
        save_alert_settings = st.form_submit_button("Save alert settings")
    if save_alert_settings:
        st.session_state.anomaly_alert_threshold = int(alert_threshold)
        st.session_state.anomaly_alert_window_minutes = int(alert_window)
        st.success("Anomaly alert settings saved.")

    st.markdown("### Severity bands")
    st.write(f"CRITICAL ≥ {SEV_THRESHOLDS['CRITICAL']:.2f} · HIGH ≥ {SEV_THRESHOLDS['HIGH']:.2f} · MEDIUM ≥ {SEV_THRESHOLDS['MEDIUM']:.2f}")

    st.markdown("### Account")
    st.write(f"Signed in as **{st.session_state.get('username', 'guest')}**")
    if st.button("Log out", key="st_logout"):
        for k in CLEAR_ON_LOGOUT:
            st.session_state.pop(k, None)
        st.rerun()
