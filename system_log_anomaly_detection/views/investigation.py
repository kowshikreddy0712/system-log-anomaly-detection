"""Anomaly Investigation: why was it flagged, how risky is it, what should the analyst do."""

import html
import re

import streamlit as st

from components.ui import badge, key_values, message_box, page_header
from services.ai_assistant import AIServiceError, ai_provider_name, generate_event_summary, triage_event
from services.analysis_service import AnalysisService
from services.ml_pipeline import event_context, explain_event
from utils.helpers import fmt_ts, fmt_ts_series

_DISPOSITIONS = ["Unreviewed", "Escalate to incident response", "Benign / expected", "False positive", "Needs more data"]


def _ensure_event_summary(event_id, row, explanation, cache):
    key = "ai_summary_v3_" + str(event_id)
    if cache.get(key + "_attempted"):
        return

    cache[key + "_attempted"] = True
    try:
        cache[key], cache[key + "_remote"] = generate_event_summary(row, explanation)
    except AIServiceError as exc:
        cache[key + "_error"] = str(exc)


def _mini_table(df, has_year):
    t = df[["event_id", "timestamp", "service", "event_class", "status", "severity", "risk_score", "message"]].copy()
    t["timestamp"] = fmt_ts_series(t["timestamp"], has_year)
    t["message"] = t["message"].str.slice(0, 120)
    t.columns = ["ID", "Timestamp", "Service", "Event", "Status", "Severity", "Risk", "Message"]
    st.dataframe(t, use_container_width=True, hide_index=True,
                 column_config={"Risk": st.column_config.ProgressColumn("Risk", min_value=0.0, max_value=1.0, format="%.2f")})


def render() -> None:
    res = AnalysisService.ensure_loaded()
    ev, has_year = res.events, res.dataset_info.has_year
    page_header("Investigation", "Event context, AI summary and recommended actions")

    queue = ev[ev["status"] == "ANOMALY"].sort_values("risk_score", ascending=False)
    if queue.empty:
        st.success("No anomalies to investigate.")
        return
    options = queue["event_id"].head(300).tolist()
    chosen = st.session_state.get("selected_event")
    if chosen and chosen not in options and (ev["event_id"] == chosen).any():
        options = [chosen] + options
    if not chosen or chosen not in options:
        chosen = options[0]

    c1, c2 = st.columns([3, 1.4])
    lookup = dict(zip(ev["event_id"], ev["service"] + " · " + ev["event_class"] + " · risk " + ev["risk_score"].map("{:.2f}".format)))
    eid = c1.selectbox("Anomaly (highest risk first)", options, index=options.index(chosen),
                       format_func=lambda i: f"{i}  —  {lookup[i]}", key="inv_select")
    typed = c2.text_input("Jump to event ID", placeholder="EVT-000123", key="inv_jump").strip().upper()
    if typed and (ev["event_id"] == typed).any():
        eid = typed
    elif typed:
        c2.caption("No event with that ID.")
    st.session_state.selected_event = eid

    x = explain_event(res, eid)
    row = x["row"]
    is_anom = row["status"] == "ANOMALY"

    st.markdown("### Anomaly summary")
    key_values([
        ("Anomaly ID", f'<span class="mono">{eid}</span>'),
        ("Timestamp", f'<span class="mono">{fmt_ts(row["timestamp"], has_year)}</span>'),
        ("Host", html.escape(str(row["hostname"]))), ("Service", f'<span class="mono">{html.escape(str(row["service"]))}</span>'),
        ("Event", html.escape(str(row["event_class"]))), ("Severity", badge(row["severity"])),
        ("Status", badge(row["status"])),
        ("Risk score", f'{row["risk_score"]:.2f} / 1.00'),
    ])
    message_box(row["message"])

    st.markdown("### AI investigation assistant")
    ai_key = "ai_summary_v3_" + str(eid)
    if not st.session_state.get(ai_key + "_attempted"):
        with st.spinner(f"Generating alert summary with {ai_provider_name() or 'local guidance'}..."):
            _ensure_event_summary(eid, row.to_dict(), x, st.session_state)
    if st.session_state.get(ai_key + "_error"):
        st.error(st.session_state[ai_key + "_error"])
    summary = st.session_state.get(ai_key)
    if summary:
        summary = re.sub(r"<br\s*/?>", "\n", summary, flags=re.IGNORECASE)
        summary = re.sub(r"</p>\s*<p[^>]*>", "\n\n", summary, flags=re.IGNORECASE)
        summary = re.sub(r"</?(?:p|strong|b|em|i)\b[^>]*>", "", summary, flags=re.IGNORECASE)
        summary = html.unescape(summary)
        with st.container(border=True):
            st.markdown("**SOC analyst summary**")
            st.markdown(summary)
        if not st.session_state.get(ai_key + "_remote"):
            st.caption("Showing rule-based SOC triage guidance; configure GEMINI_API_KEY or OPENAI_API_KEY for an AI-generated note.")
    else:
        if st.button("Retry alert summary", key=f"retry_ai_{eid}"):
            st.session_state.pop(ai_key + "_attempted", None)
            st.session_state.pop(ai_key + "_error", None)
            st.rerun()

    triage_key = "ai_triage_" + str(eid)
    if st.button("Generate triage suggestions", key=f"triage_{eid}"):
        try:
            st.session_state[triage_key], st.session_state[triage_key + "_remote"] = triage_event(row.to_dict(), x)
        except AIServiceError as exc:
            st.error(str(exc))
    triage = st.session_state.get(triage_key)
    if triage:
        st.markdown("#### AI triage")
        st.markdown(triage)
        if not st.session_state.get(triage_key + "_remote"):
            st.caption("Showing rule-based local triage guidance.")

    st.markdown("### Recommended analyst actions")
    for i, act in enumerate(x["actions"], 1):
        st.markdown(f"{i}. {act}")

    st.markdown("### Related activity")
    t1, t2, t3 = st.tabs(["Surrounding events", "Same source host", "Same message pattern"])
    with t1:
        _mini_table(event_context(res, eid), has_year)
    with t2:
        if isinstance(row["src_host"], str) and row["src_host"]:
            same = ev[ev["src_host"] == row["src_host"]].sort_values("timestamp")
            st.caption(f"{len(same):,} events reference source host {row['src_host']}.")
            _mini_table(same.head(100), has_year)
        else:
            st.caption("This event has no source host recorded.")
    with t3:
        same = ev[ev["template"] == row["template"]]
        st.caption(f"{len(same):,} event(s) share this message pattern; {int((same['status'] == 'ANOMALY').sum()):,} are anomalous.")
        _mini_table(same.sort_values("timestamp").head(100), has_year)

    st.markdown("### Analyst disposition")
    disp = st.session_state.setdefault("dispositions", {})
    prev = disp.get(eid, {"status": "Unreviewed", "note": ""})
    d1, d2 = st.columns([1.3, 3])
    status = d1.selectbox("Disposition", _DISPOSITIONS, index=_DISPOSITIONS.index(prev["status"]), key=f"disp_{eid}")
    note = d2.text_input("Analyst note", value=prev["note"], key=f"note_{eid}")
    if st.button("Save disposition", key=f"save_{eid}"):
        disp[eid] = {"status": status, "note": note}
        st.success("Saved for this session. Dispositions are included in exported reports.")
    if not is_anom:
        st.caption("This event was not flagged as anomalous.")
