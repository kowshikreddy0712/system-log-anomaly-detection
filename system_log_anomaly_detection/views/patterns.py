"""Event Patterns: Apriori co-occurrence rules plus repeated-activity views."""

import pandas as pd
import streamlit as st

from components import charts
from components.ui import callout, kpi_card, page_header
from services.analysis_service import AnalysisService
from utils.helpers import fmt_ts_series

_CFG = {"displayModeBar": False}


def render() -> None:
    res = AnalysisService.ensure_loaded()
    ev, p, has_year = res.events, res.pipeline, res.dataset_info.has_year
    page_header("Event Patterns", "Frequent co-occurring Linux events and repeated activity (Apriori)")
    callout("<b>How to read this.</b> Logs are grouped into five-minute windows. Each window is a <i>transaction</i> of the services and event "
            "classes seen in it. Apriori finds item combinations that appear together often (<b>support</b>); a rule "
            "<i>if A then B</i> has <b>confidence</b> = how often B appears when A does, and <b>lift</b> &gt; 1 means the association is "
            "stronger than chance. Items named <code>ANOMALY_IN_WINDOW</code> link a pattern to detected anomalies.")

    c = st.columns(4)
    with c[0]: kpi_card("Time windows", f"{p['apriori_windows']:,}", f"{res.params['window']} each")
    with c[1]: kpi_card("Frequent itemsets", f"{p['itemsets']:,}", f"min support {res.params['min_support']:.0%}")
    with c[2]: kpi_card("Association rules", f"{p['rules']:,}", f"min confidence {res.params['min_confidence']:.0%}", "amber")
    with c[3]: kpi_card("Repeated auth failures", f"{int((ev['event_class'] == 'AUTH_FAIL').sum()):,}", "AUTH_FAIL events", "red")
    st.markdown("<div style='height:.8rem'></div>", unsafe_allow_html=True)

    t1, t2, t3 = st.tabs(["Frequent itemsets & rules", "Repeated activity by source host", "Repeated message patterns"])

    with t1:
        left, right = st.columns([1, 1.15])
        with left:
            st.markdown("### Most frequent patterns")
            st.plotly_chart(charts.support_bars(res.itemsets), use_container_width=True, config=_CFG)
            st.caption("Red bars include anomalous windows.")
        with right:
            st.markdown("### Association rules")
            if res.rules.empty:
                st.info("No rules meet the current support/confidence thresholds. Lower them in Settings.")
            else:
                only_anom = st.checkbox("Only rules involving anomalous windows", value=False, key="pat_anom")
                r = res.rules
                if only_anom:
                    r = r[r["if"].str.contains("ANOMALY") | r["then"].str.contains("ANOMALY")]
                show = r.head(200).copy()
                show["support"], show["confidence"] = show["support"] * 100, show["confidence"] * 100
                st.dataframe(show[["if", "then", "support", "confidence", "lift", "windows"]], hide_index=True, use_container_width=True, height=420,
                             column_config={"if": "If (antecedent)", "then": "Then (consequent)",
                                            "support": st.column_config.NumberColumn("Support %", format="%.1f"),
                                            "confidence": st.column_config.NumberColumn("Confidence %", format="%.1f"),
                                            "lift": st.column_config.NumberColumn("Lift", format="%.2f"),
                                            "windows": "Windows"})
        top = res.rules.head(1)
        if not top.empty:
            t = top.iloc[0]
            callout(f"<b>Strongest association:</b> when a window contains <code>{t['if']}</code>, it also contains <code>{t['then']}</code> "
                    f"in {t['confidence'] * 100:.0f}% of cases (lift {t['lift']:.1f}).")

    with t2:
        a = ev[(ev["event_class"] == "AUTH_FAIL") & ev["src_host"].notna()]
        if a.empty:
            st.info("No authentication failures with an extractable source host in this dataset.")
        else:
            g = (a.groupby("src_host")
                 .agg(failures=("event_id", "size"), target_accounts=("target_user", "nunique"),
                      flagged=("status", lambda s: int((s == "ANOMALY").sum())), peak_burst=("burst", "max"),
                      first_seen=("timestamp", "min"), last_seen=("timestamp", "max"))
                 .sort_values("failures", ascending=False).head(25).reset_index())
            g["first_seen"], g["last_seen"] = fmt_ts_series(g["first_seen"], has_year), fmt_ts_series(g["last_seen"], has_year)
            st.markdown("### Sources with the most authentication failures")
            st.dataframe(g, hide_index=True, use_container_width=True,
                         column_config={"src_host": "Source host", "failures": "Failures", "target_accounts": "Accounts targeted",
                                        "flagged": "Flagged anomalous", "peak_burst": "Peak burst / window",
                                        "first_seen": "First seen", "last_seen": "Last seen"})
            st.caption("A source touching several accounts, or failing repeatedly in short windows, is a typical password-guessing indicator.")

    with t3:
        g = (ev.groupby("template")
             .agg(events=("event_id", "size"), services=("service", "nunique"), anomalous=("status", lambda s: int((s == "ANOMALY").sum())),
                  example=("message", "first"))
             .sort_values("events", ascending=False).head(25).reset_index())
        g["example"] = g["example"].str.slice(0, 120)
        st.markdown("### Most repeated message patterns")
        st.dataframe(g[["events", "anomalous", "services", "example"]], hide_index=True, use_container_width=True,
                     column_config={"events": "Events", "anomalous": "Anomalous", "services": "Services", "example": "Example message"})
