"""
Linux SOC Monitor — Linux System Log Anomaly Detection & Security Analytics.

Run with:
    streamlit run app.py
"""

import streamlit as st
from components.sidebar import render_sidebar
from database.db import init_db
from utils.helpers import init_session_state, load_css
from views import anomalies, auth, investigation, log_explorer, overview, reports, settings, upload

st.set_page_config(page_title="Linux SOC Monitor", page_icon="🛡", layout="wide", initial_sidebar_state="expanded")

PAGE_RENDERERS = {
    "Overview": overview.render,
    "Anomalies": anomalies.render,
    "Log Explorer": log_explorer.render,
    "Investigation": investigation.render,
    "Upload Linux Logs": upload.render,
    "Reports": reports.render,
    "Settings": settings.render,
}


def main() -> None:
    init_db()
    init_session_state()
    load_css("assets/styles.css")

    if not st.session_state.get("logged_in"):
        auth.render()
        return

    page = render_sidebar()
    PAGE_RENDERERS.get(page, overview.render)()


if __name__ == "__main__":
    main()
