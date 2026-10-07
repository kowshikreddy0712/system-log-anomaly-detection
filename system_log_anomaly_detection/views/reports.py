"""Reports: executive summary and CSV/JSON exports, all generated from the active analysis."""

import pandas as pd
import streamlit as st

from components.ui import page_header
from services.ai_assistant import AIServiceError, ai_available, ai_provider_name, generate_incident_report
from services.analysis_service import AnalysisService
from utils.helpers import fmt_ts, fmt_ts_series


def build_summary(res) -> str:
    info, e, m = res.dataset_info, res.events, res.metrics
    a = e[e["status"] == "ANOMALY"]
    yr = info.has_year
    lines = [
        "# Linux Log Anomaly Detection — Summary Report", "",
        f"**Dataset:** {info.filename} · {res.total_logs:,} Linux log events · "
        f"{fmt_ts(info.time_start, yr)} → {fmt_ts(info.time_end, yr)}", "",
        "## Key figures",
        f"- Anomalies detected: **{res.anomalies:,}** ({res.anomaly_rate():.2f}% of events)",
        f"- High-risk (HIGH + CRITICAL) anomalies: **{res.high_risk_events:,}**",
        f"- Services monitored: {res.services_monitored}",
        "",
    ]
    if not a.empty:
        lines += ["## Top suspicious services"] + [f"- {k}: {v:,} anomalies" for k, v in a["service"].value_counts().head(5).items()]
        lines += ["", "## Top suspicious event types"] + [f"- {k}: {v:,}" for k, v in a["event_class"].value_counts().head(5).items()]
        src = a[a["event_class"] == "AUTH_FAIL"]["src_host"].dropna().value_counts().head(5)
        if len(src):
            lines += ["", "## Top source hosts (anomalous authentication failures)"] + [f"- {k}: {v:,}" for k, v in src.items()]
        top = a.sort_values("risk_score", ascending=False).head(5)
        lines += ["", "## Highest-risk events"] + [
            f"- {r.event_id} · {fmt_ts(r.timestamp, yr)} · {r.service} · {r.event_class} · risk {r.risk_score:.2f}" for r in top.itertuples()]
    if m.get("ground_truth"):
        g = m["ground_truth"]
        lines += ["", "## Post-hoc evaluation against supplied ground truth",
                  f"- Accuracy: {g['accuracy'] * 100:.1f}%, precision: {g['precision'] * 100:.1f}%, "
                  f"recall: {g['recall'] * 100:.1f}%, F1: {g['f1']:.3f}",
                  "- Ground-truth labels were not used during anomaly detection."]
    lines += ["", "## Recommended next steps",
              "1. Triage CRITICAL and HIGH anomalies in the Investigation page, starting with the highest risk score.",
              "2. For authentication-failure bursts, identify the source host, check for any later successful login from it, and block or rate-limit it.",
              "3. Review privilege (su/sudo) and service-error anomalies against change windows.",
              "4. Record benign findings and false positives to improve future review.", "",
              "_Anomalous does not mean malicious: findings are risk indicators that require analyst review._"]
    return "\n".join(lines)


def render() -> None:
    res = AnalysisService.ensure_loaded()
    e, yr = res.events, res.dataset_info.has_year
    page_header("Reports", "Executive summary and exports for the active Linux log analysis")

    summary = build_summary(res)
    st.markdown("### Executive summary")
    st.markdown(summary)
    st.download_button("⬇ Download summary (Markdown)", summary.encode("utf-8"), "linux_soc_summary.md", "text/markdown", type="primary", key="rp_md")

    st.markdown("### AI incident review")
    if ai_available():
        st.warning(f"The report uses aggregate analysis findings and is sent to the configured {ai_provider_name()} service.")
    else:
        st.caption("Without a Gemini or OpenAI API key, this creates a local report template from the analysis facts.")
    ai_report_key = "ai_incident_report"
    if st.button("Generate incident review", key="rp_ai_report"):
        events = res.events
        anomalies = events[events["status"] == "ANOMALY"]
        severity = anomalies["severity"].value_counts().to_dict()
        services = anomalies["service"].value_counts().head(10).to_dict()
        classes = anomalies["event_class"].value_counts().head(10).to_dict()
        top_events = [
            {
                "event_class": row.event_class,
                "service": row.service,
                "severity": row.severity,
                "risk_score": round(float(row.risk_score), 2),
            }
            for row in anomalies.nlargest(10, "risk_score").itertuples()
        ]
        context = (
            f"Dataset: {res.dataset_info.filename}\nEvents: {res.total_logs:,}\n"
            f"Anomalies: {res.anomalies:,} ({res.anomaly_rate():.2f}%)\n"
            f"High-risk anomalies: {res.high_risk_events:,}\n"
            f"Severity counts: {severity}\nTop anomalous services: {services}\n"
            f"Top event classes: {classes}\nHighest-risk event summaries: {top_events}\n"
            "Anomalies are not confirmed attacks. If ground-truth labels are supplied, they are used only for post-hoc evaluation."
        )
        try:
            report, used_ai = generate_incident_report(context)
            st.session_state[ai_report_key] = report
            st.session_state[ai_report_key + "_remote"] = used_ai
        except AIServiceError as exc:
            st.error(str(exc))
    ai_report = st.session_state.get(ai_report_key)
    if ai_report:
        st.markdown(ai_report)
        if not st.session_state.get(ai_report_key + "_remote"):
            st.caption("This is a local report template, not AI-generated analysis.")
        st.download_button(
            "⬇ Download incident review (Markdown)",
            ai_report.encode("utf-8"),
            "linux_soc_incident_review.md",
            "text/markdown",
            key="rp_ai_report_download",
        )

    st.markdown("### Data exports")

    def frame(df):
        out = df[["event_id", "timestamp", "hostname", "service", "event_class", "severity", "status",
                  "risk_score", "src_host", "target_user", "message"]].copy()
        out["timestamp"] = fmt_ts_series(out["timestamp"], yr)
        return out

    c1, c2 = st.columns(2)
    c1.download_button("⬇ Anomalies (CSV)", frame(e[e["status"] == "ANOMALY"]).to_csv(index=False).encode("utf-8"),
                       "linux_anomalies.csv", "text/csv", key="rp_an")
    c2.download_button("⬇ All scored events (CSV)", frame(e).to_csv(index=False).encode("utf-8"),
                       "linux_scored_events.csv", "text/csv", key="rp_all")
    disp = st.session_state.get("dispositions", {})
    st.markdown("### Analyst dispositions (this session)")
    if disp:
        d = pd.DataFrame([{"event_id": k, **v} for k, v in disp.items()])
        st.dataframe(d, hide_index=True, use_container_width=True)
        st.download_button("⬇ Dispositions (CSV)", d.to_csv(index=False).encode("utf-8"), "analyst_dispositions.csv", "text/csv", key="rp_disp")
    else:
        st.caption("No dispositions saved yet. Use the Investigation page to mark events as escalated, benign or false positive.")
