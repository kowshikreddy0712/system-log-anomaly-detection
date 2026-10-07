"""Upload Linux Logs: intake, parse report, preview, and run the analysis pipeline."""

import streamlit as st

from components.ui import callout, kpi_card, page_header
from services.analysis_service import AnalysisService
from services.log_parser import parse_bytes
from utils.helpers import fmt_ts, goto


def render() -> None:
    page_header("Upload Linux Logs", "Analyse your own Linux system logs (authentication, SSH, sudo, kernel, service events)")
    callout("<b>Supported input.</b> CSV with at least a <code>timestamp</code> and a <code>message</code> column "
            "(optional: <code>hostname</code>, <code>service</code>, <code>event_type</code>), or raw syslog text "
            "(<code>Jun  9 06:06:20 host sshd(pam_unix)[123]: message</code>). Only Linux system logs are in scope.")

    up = st.file_uploader("Drop a Linux log file here", type=["csv", "log", "txt"], key="up_file")
    c1, c2 = st.columns([1, 3])
    if c1.button("Use bundled demo dataset", key="up_demo"):
        with st.spinner("Running the pipeline on the bundled Linux log dataset…"):
            AnalysisService.load_demo()
        goto("Overview")

    if up is None:
        c2.caption("Or load the bundled 25,549-event Linux syslog dataset to explore the platform.")
        return

    raw = up.getvalue()
    try:
        df, info = parse_bytes(up.name, raw)
    except Exception as exc:
        st.error(f"Could not parse this file: {exc}")
        return

    st.markdown("### Parse report")
    c = st.columns(5)
    with c[0]: kpi_card("Detected format", info.detected_format, info.file_type.upper())
    with c[1]: kpi_card("Lines / rows read", f"{info.total_lines:,}", f"{info.size_kb:,} KB")
    with c[2]: kpi_card("Parsed events", f"{info.parsed_rows:,}", f"{info.parsed_rows / max(info.total_lines, 1) * 100:.1f}% parse rate", "green")
    with c[3]: kpi_card("Skipped", f"{info.dropped_rows:,}", "unparseable / no timestamp", "amber" if info.dropped_rows else "")
    with c[4]: kpi_card("Services", f"{df['service'].nunique():,}", "distinct")
    st.caption(f"Time span: {fmt_ts(info.time_start, info.has_year)} → {fmt_ts(info.time_end, info.has_year)}"
               + ("" if info.has_year else "  ·  no year in source timestamps"))
    if info.parsed_rows < 200:
        st.warning("Fewer than 200 events: findings may be less stable on very small datasets.")

    st.markdown("### Preview")
    st.dataframe(df.head(25), hide_index=True, use_container_width=True)

    if st.button("🔍 Run Linux log analysis", type="primary", key="up_run", use_container_width=True):
        with st.spinner("Analyzing Linux logs…"):
            try:
                AnalysisService.run(raw, up.name, is_demo=False)
            except Exception as exc:
                st.error(f"Analysis failed: {exc}")
                return
        goto("Overview")
