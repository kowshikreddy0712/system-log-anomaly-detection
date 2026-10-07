"""Model Testing for the unsupervised anomaly detector."""

import os
import pandas as pd
import streamlit as st
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from components import charts
from components.ui import callout, kpi_card, page_header
from services.analysis_service import AnalysisService, DATA_DIR

_CFG = {"displayModeBar": False}


def _pct(x):
    return f"{x * 100:.1f}%"


def render() -> None:
    res = AnalysisService.ensure_loaded()
    m = res.metrics
    page_header("Model Testing", "Evaluate the unsupervised detector without using labels during detection.")

    callout(
        "<b>Important:</b> DBSCAN and Isolation Forest make the anomaly decision without "
        "using ground-truth labels. If an uploaded CSV contains <code>actual_label</code> / "
        "<code>label</code>, those labels are used only after detection to measure performance."
    )

    gt = m.get("ground_truth")
    if gt:
        st.markdown("### Post-hoc evaluation against supplied ground truth")
        c = st.columns(5)
        with c[0]: kpi_card("Accuracy", _pct(gt["accuracy"]), "correct ÷ all", "green")
        with c[1]: kpi_card("Precision", _pct(gt["precision"]), "flagged that were anomalous")
        with c[2]: kpi_card("Recall", _pct(gt["recall"]), "anomalies caught")
        with c[3]: kpi_card("F1", f"{gt['f1']:.3f}", "precision/recall balance")
        with c[4]: kpi_card("Actual anomalies", f"{gt['positives']:,}", "ground truth only")
        l, r = st.columns(2)
        with l:
            st.markdown("### Confusion matrix")
            st.plotly_chart(charts.confusion_heatmap(gt["confusion"]), use_container_width=True, config=_CFG)
        with r:
            tn, fp = gt["confusion"][0]
            fn, tp = gt["confusion"][1]
            st.markdown("### Detection summary")
            st.write(f"**True positives:** {tp:,}")
            st.write(f"**Missed anomalies:** {fn:,}")
            st.write(f"**False alarms:** {fp:,}")
            st.write(f"**Correct normal events:** {tn:,}")
        st.caption("This is a post-hoc evaluation. The labels were never supplied to DBSCAN or Isolation Forest.")

    else:
        st.info(
            "The active dataset has no ground-truth labels. This is expected for real Linux logs. "
            "The dashboard reports anomaly counts and scores, but not supervised accuracy."
        )

    st.markdown("### Score a new, unseen Linux log file")
    st.caption("The trained Isolation Forest is applied to a new file; DBSCAN is also recomputed for that file.")
    up = st.file_uploader("Linux log file (.csv, .log, .txt)", type=["csv", "log", "txt"], key="mt_up")
    if up is None:
        return

    try:
        sc = AnalysisService.score_file(res, up.getvalue(), up.name)
    except Exception as exc:
        st.error(f"Could not score this file: {exc}")
        return

    c = st.columns(3)
    with c[0]: kpi_card("Events scored", f"{len(sc):,}", up.name)
    with c[1]: kpi_card("Predicted anomalous", f"{int(sc['model_pred'].sum()):,}", f"{sc['model_pred'].mean() * 100:.2f}%", "red")
    with c[2]: kpi_card("Predicted normal", f"{int((sc['model_pred'] == 0).sum()):,}", "", "green")

    if "label" in sc and sc["label"].notna().any():
        v = sc.dropna(subset=["label"])
        st.success(
            f"Against supplied labels ({len(v):,} rows): accuracy {_pct(accuracy_score(v.label, v.model_pred))}, "
            f"precision {_pct(precision_score(v.label, v.model_pred, zero_division=0))}, "
            f"recall {_pct(recall_score(v.label, v.model_pred, zero_division=0))}, "
            f"F1 {f1_score(v.label, v.model_pred, zero_division=0):.3f}"
        )
    else:
        st.caption("No ground-truth label found; only unsupervised predictions are shown.")

    st.dataframe(sc.sort_values("model_prob", ascending=False).head(200), hide_index=True, use_container_width=True)
