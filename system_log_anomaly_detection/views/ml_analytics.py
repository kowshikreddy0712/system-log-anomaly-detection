"""ML Analytics for the fully unsupervised Linux anomaly pipeline."""

import pandas as pd
import streamlit as st

from components import charts
from components.ui import callout, kpi_card, page_header, stage_card
from services.analysis_service import AnalysisService
from services.ml_pipeline import SEV_THRESHOLDS

_CFG = {"displayModeBar": False}

_FEATURES = pd.DataFrame([
    ("hour (sin/cos)", "Time of day encoded cyclically", "DBSCAN + Isolation Forest"),
    ("message length", "Log-message size", "DBSCAN + Isolation Forest"),
    ("message-pattern rarity", "Frequency of normalized message template", "DBSCAN + Isolation Forest"),
    ("service rarity", "Frequency of the Linux service", "DBSCAN + Isolation Forest"),
    ("burst size", "Repeated events in a time window", "DBSCAN + Isolation Forest"),
    ("event class", "Security-oriented event category", "DBSCAN + Isolation Forest"),
    ("token count / digit ratio", "Message structure", "Isolation Forest"),
], columns=["Feature", "Meaning", "Used by"])


def render() -> None:
    res = AnalysisService.ensure_loaded()
    p, prm, m = res.pipeline, res.params, res.metrics
    page_header("ML Analytics", "Unsupervised Linux anomaly detection with DBSCAN + Isolation Forest + Apriori")

    st.markdown("### Pipeline on the active dataset")
    s = st.columns(5)
    with s[0]: stage_card(f"{p['input_rows']:,}", "Linux log events", "parsed from the uploaded file")
    with s[1]: stage_card(p["model_features"], "Model features", "engineered per event")
    with s[2]: stage_card(f"{p['dbscan_noise']:,}", "DBSCAN noise", f"{p['dbscan_clusters']} clusters")
    with s[3]: stage_card(f"{p['isolation_forest_anomalies']:,}", "Isolation Forest", "unsupervised outliers")
    with s[4]: stage_card(f"{p['seconds']}s", "Pipeline run time", "single pass, cached")

    callout(
        "<b>No labels are used for detection.</b> DBSCAN finds density-based outliers, while "
        "Isolation Forest finds events that are easy to isolate in the engineered feature space. "
        "The final anomaly decision is the union of those two independent unsupervised detectors. "
        "Apriori is used separately to discover recurring event/service patterns."
    )

    if p["detection_source"] == "reference":
        callout("Reference DBSCAN mode is intended only for reproducing the old bundled Colab result. "
                "Use live mode for real uploaded files.", "warn")

    t1, t2, t3, t4 = st.tabs(["DBSCAN", "Isolation Forest", "Risk scoring", "Features & limits"])

    with t1:
        c = st.columns(4)
        with c[0]: kpi_card("eps used", f"{prm['eps_used']}", "neighbourhood radius")
        with c[1]: kpi_card("min_samples used", f"{prm['min_samples_used']}", "core-point requirement")
        with c[2]: kpi_card("Clusters", f"{p['dbscan_clusters']}", "dense groups")
        with c[3]: kpi_card("Noise events", f"{p['dbscan_noise']:,}", "DBSCAN outliers", "red")
        if p.get("auto_params"):
            callout("For a small file, DBSCAN eps/min_samples were derived automatically from k-distance.")
        left, right = st.columns([1.3, 1])
        with left:
            st.markdown("### 2-D projection of DBSCAN feature space")
            if len(res.projection):
                st.plotly_chart(charts.projection_scatter(res.projection), use_container_width=True, config=_CFG)
            else:
                st.info("Not enough points for a projection.")
        with right:
            st.markdown("### Cluster sizes")
            st.plotly_chart(charts.cluster_sizes(res.clusters), use_container_width=True, config=_CFG)
        st.dataframe(
            res.clusters[["cluster", "size", "share_pct", "top_service", "top_event", "avg_length"]],
            hide_index=True, use_container_width=True,
            column_config={"cluster": "Cluster", "size": "Events",
                           "share_pct": st.column_config.NumberColumn("Share %", format="%.2f"),
                           "top_service": "Top service", "top_event": "Top event",
                           "avg_length": st.column_config.NumberColumn("Avg msg length", format="%.0f")}
        )

    with t2:
        st.markdown("### Isolation Forest")
        st.markdown(
            "Isolation Forest is the primary portable unsupervised model. It does not receive "
            "`actual_label`, `label`, or any attack ground truth. A higher anomaly score means the "
            "event is easier to isolate from the rest of the dataset."
        )
        left, right = st.columns([1, 1])
        with left:
            st.markdown("**Model configuration**")
            st.write("- 300 trees")
            st.write(f"- Contamination assumption: `{prm.get('if_contamination', 'auto')}`")
            st.write("- No supervised training labels")
            st.write("- Anomaly prediction: Isolation Forest + DBSCAN ensemble")
        with right:
            st.markdown("**Top descriptive anomaly features**")
            if len(res.importance):
                st.plotly_chart(charts.importance_bar(res.importance.head(12)), use_container_width=True, config=_CFG)
            else:
                st.info("No anomaly features available.")

        gt = m.get("ground_truth")
        if gt:
            st.success(
                f"Post-hoc evaluation only: accuracy {gt['accuracy']:.3f}, "
                f"precision {gt['precision']:.3f}, recall {gt['recall']:.3f}, F1 {gt['f1']:.3f}. "
                "These labels were NOT used by the detector."
            )

    with t3:
        st.markdown("### Risk score (0 – 1)")
        st.markdown("A transparent triage score, not a probability of attack.")
        st.dataframe(pd.DataFrame([
            ("Event type", 0.30, "Security relevance of the event class"),
            ("Service sensitivity", 0.15, "Higher for access-control services"),
            ("Repetition / burst size", 0.15, "Repeated activity in a time window"),
            ("Message-pattern rarity", 0.10, "Rare normalized message patterns"),
            ("DBSCAN noise", 0.15, "Density-based anomaly signal"),
            ("Isolation Forest score", 0.15, "Unsupervised isolation signal"),
        ], columns=["Component", "Weight", "Meaning"]), hide_index=True, use_container_width=True)
        st.markdown(
            f"**Severity:** CRITICAL ≥ {SEV_THRESHOLDS['CRITICAL']:.2f} · "
            f"HIGH ≥ {SEV_THRESHOLDS['HIGH']:.2f} · MEDIUM ≥ {SEV_THRESHOLDS['MEDIUM']:.2f}."
        )

    with t4:
        st.dataframe(_FEATURES, hide_index=True, use_container_width=True)
        callout(
            "<b>Important limitation.</b> Unsupervised learning has no knowledge of the true attack "
            "label. It finds unusual behaviour, not every malicious event. A rare legitimate maintenance "
            "operation can be flagged, while a common attack pattern can look normal. If a labeled test "
            "set is supplied, labels are used only for post-hoc evaluation."
        )
