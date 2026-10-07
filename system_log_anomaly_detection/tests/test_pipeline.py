"""Tests for the unsupervised Linux anomaly pipeline."""
import os
import sys
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.log_parser import parse_bytes
from services.ml_pipeline import explain_event, risk_breakdown, run_pipeline, score_unseen

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "processed_linux_logs_with_dbscan.csv")

@pytest.fixture(scope="module")
def result():
    with open(DEMO, "rb") as fh:
        df, info = parse_bytes("demo.csv", fh.read())
    return run_pipeline(df, info)

def test_kpis_are_consistent(result):
    assert result.total_logs > 0
    assert result.normal_events + result.anomalies == result.total_logs
    assert 0 <= result.anomaly_rate() <= 100
    assert result.high_risk_events <= result.anomalies

def test_unsupervised_model_is_used(result):
    assert result.model is not None
    assert result.pipeline["detection_mode"] == "unsupervised"
    assert "isolation_forest_anomalies" in result.pipeline
    assert set(np.unique(result.events.model_pred)) <= {0, 1}

def test_no_label_needed_for_detection(result):
    assert "label" not in result.events.columns or result.events["label"].isna().all()

def test_risk_scores_bounded(result):
    assert result.events.risk_score.between(0, 1).all()

def test_explanations_have_evidence_and_actions(result):
    eid = result.events[result.events.status == "ANOMALY"].event_id.iloc[0]
    x = explain_event(result, eid)
    assert x["headline"] and x["evidence"] and x["actions"]

def test_unseen_scoring_shape(result):
    with open(DEMO, "rb") as fh:
        df, _ = parse_bytes("demo.csv", fh.read())
    sc = score_unseen(result, df.head(500))
    assert len(sc) == 500 and set(np.unique(sc.model_pred)) <= {0, 1}
