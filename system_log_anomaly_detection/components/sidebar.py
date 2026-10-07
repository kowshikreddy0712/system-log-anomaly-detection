"""SOC navigation sidebar."""

import html

import streamlit as st

from utils.helpers import PAGES

GROUPS = [
    ("Monitoring", ["Overview", "Anomalies", "Log Explorer", "Investigation"]),
    ("Data & admin", ["Upload Linux Logs", "Reports", "Settings"]),
]
_ICON = dict((label, icon) for icon, label in PAGES)

CLEAR_ON_LOGOUT = [
    "logged_in", "username", "user_id", "analysis_result", "source", "selected_event", "dispositions",
    "ai_incident_report", "ai_incident_report_remote",
    "anomaly_alert_threshold", "anomaly_alert_window_minutes",
]


def render_sidebar() -> str:
    if st.session_state.current_page not in _ICON:
        st.session_state.current_page = "Overview"

    with st.sidebar:
        st.markdown(
            '<div class="brand"><div class="brand-mark">🛡</div><div><div class="brand-name">LINUX SOC MONITOR</div>'
            '<div class="brand-sub">Log anomaly detection</div></div></div>',
            unsafe_allow_html=True,
        )
        theme = st.session_state.get("theme", "dark")
        if st.button("☀️ Switch to light mode" if theme == "dark" else "🌙 Switch to dark mode",
                     use_container_width=True, key="theme_toggle"):
            st.session_state["theme"] = "light" if theme == "dark" else "dark"
            st.rerun()

        for group, items in GROUPS:
            st.markdown(f'<div class="nav-group">{group}</div>', unsafe_allow_html=True)
            for label in items:
                active = st.session_state.current_page == label
                if st.button(f"{_ICON[label]}  {label}", key=f"nav_{label}", use_container_width=True,
                             type="primary" if active else "secondary"):
                    st.session_state.current_page = label
                    st.rerun()

        res = st.session_state.get("analysis_result")
        if res is not None:
            info = res.dataset_info
            st.markdown(
                f'<div class="side-card"><b>Active dataset</b><br>{html.escape(info.filename)}<br>'
                f'{res.total_logs:,} events · {res.anomalies:,} anomalies</div>',
                unsafe_allow_html=True,
            )
        st.markdown(
            f'<div class="side-card"><span class="dot"></span><b>Engine online</b><br>'
            f'Signed in as {html.escape(str(st.session_state.get("username", "guest")))}</div>',
            unsafe_allow_html=True,
        )
        if st.button("Log out", use_container_width=True, key="nav_logout"):
            for key in list(st.session_state):
                if key.startswith(("ai_summary_", "ai_triage_")):
                    st.session_state.pop(key, None)
            for k in CLEAR_ON_LOGOUT:
                st.session_state.pop(k, None)
            st.rerun()
    return st.session_state.current_page
