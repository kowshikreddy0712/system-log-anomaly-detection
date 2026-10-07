"""
Single access point the UI uses to run / fetch the analysis.

  upload bytes -> log_parser.parse_bytes -> ml_pipeline.run_pipeline -> AnalysisResult

Results are cached by (file digest, parameters) so changing a page never re-runs
the ML pipeline; changing a detection parameter in Settings does.
"""

import hashlib
import json
import os

import pandas as pd
import streamlit as st

from models.analysis_result import AnalysisResult
from services.log_parser import parse_bytes
from services.ml_pipeline import DEFAULT_PARAMS, run_pipeline, score_unseen

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DEMO_FILE = os.path.join(DATA_DIR, "processed_linux_logs_with_dbscan.csv")
DEMO_NAME = "linux_syslog_demo.csv"


@st.cache_data(show_spinner=False, max_entries=6)
def _cached_run(digest: str, filename: str, params_json: str, is_demo: bool, _raw: bytes) -> AnalysisResult:
    df, info = parse_bytes(filename, _raw)
    info.is_demo = is_demo
    return run_pipeline(df, info, json.loads(params_json))


def current_params() -> dict:
    return {**DEFAULT_PARAMS, **st.session_state.get("detection_params", {})}


class AnalysisService:
    @staticmethod
    def run(raw: bytes, filename: str, is_demo: bool = False) -> AnalysisResult:
        params = current_params()
        digest = hashlib.sha1(raw).hexdigest()
        res = _cached_run(digest, filename, json.dumps(params, sort_keys=True), is_demo, raw)
        st.session_state.analysis_result = res
        st.session_state.source = {"raw": raw, "filename": filename, "is_demo": is_demo}
        return res

    @staticmethod
    def load_demo() -> AnalysisResult:
        with open(DEMO_FILE, "rb") as fh:
            return AnalysisService.run(fh.read(), DEMO_NAME, is_demo=True)

    @staticmethod
    def rerun_with_current_params() -> AnalysisResult:
        src = st.session_state.get("source")
        if not src:
            return AnalysisService.load_demo()
        return AnalysisService.run(src["raw"], src["filename"], src["is_demo"])

    @staticmethod
    def get_result():
        return st.session_state.get("analysis_result")

    @staticmethod
    def has_result() -> bool:
        return st.session_state.get("analysis_result") is not None

    @staticmethod
    def ensure_loaded() -> AnalysisResult:
        """Auto-load the bundled Linux log dataset so every page is populated on first visit."""
        res = AnalysisService.get_result()
        if res is None:
            with st.spinner("Analyzing the bundled Linux log dataset…"):
                res = AnalysisService.load_demo()
        return res

    @staticmethod
    def score_file(res: AnalysisResult, raw: bytes, filename: str) -> pd.DataFrame:
        df, _ = parse_bytes(filename, raw)
        return score_unseen(res, df)
