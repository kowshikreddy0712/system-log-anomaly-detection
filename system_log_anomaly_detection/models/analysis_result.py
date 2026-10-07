"""
Data contracts shared by the ML pipeline and the UI.

The UI never runs ML code. It only reads an `AnalysisResult`, which is produced
by `services.ml_pipeline.run_pipeline` (via `services.analysis_service`).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import pandas as pd


@dataclass
class DatasetInfo:
    """Metadata about the uploaded / loaded Linux log file."""
    filename: str = "unknown"
    size_kb: float = 0.0
    file_type: str = "csv"
    num_records: int = 0
    columns: list = field(default_factory=list)
    # parse report
    detected_format: str = "csv"
    total_lines: int = 0
    parsed_rows: int = 0
    dropped_rows: int = 0
    has_year: bool = True          # False when the source has no year (classic syslog)
    time_start: Optional[pd.Timestamp] = None
    time_end: Optional[pd.Timestamp] = None
    is_demo: bool = False


@dataclass
class AnalysisResult:
    """Everything the SOC UI needs, produced by one pipeline run."""
    events: pd.DataFrame = field(default_factory=pd.DataFrame)       # one row per Linux log event, fully scored
    itemsets: pd.DataFrame = field(default_factory=pd.DataFrame)     # Apriori frequent itemsets
    rules: pd.DataFrame = field(default_factory=pd.DataFrame)        # Apriori association rules
    clusters: pd.DataFrame = field(default_factory=pd.DataFrame)     # DBSCAN cluster summary
    projection: pd.DataFrame = field(default_factory=pd.DataFrame)   # 2-D PCA projection for plotting
    importance: pd.DataFrame = field(default_factory=pd.DataFrame)   # descriptive anomaly-feature scores
    metrics: Dict[str, Any] = field(default_factory=dict)            # optional post-hoc ground-truth metrics
    params: Dict[str, Any] = field(default_factory=dict)
    pipeline: Dict[str, Any] = field(default_factory=dict)           # counts per stage, timings
    model: Any = None                                                # fitted sklearn tree (for unseen scoring)
    feature_names: list = field(default_factory=list)
    tree_text: str = ""
    dataset_info: DatasetInfo = field(default_factory=DatasetInfo)

    # ---- convenience KPIs (all derived, never hardcoded) -------------------
    @property
    def total_logs(self) -> int:
        return int(len(self.events))

    @property
    def anomalies(self) -> int:
        return int((self.events["status"] == "ANOMALY").sum()) if len(self.events) else 0

    @property
    def normal_events(self) -> int:
        return self.total_logs - self.anomalies

    @property
    def high_risk_events(self) -> int:
        if not len(self.events):
            return 0
        e = self.events
        return int(((e["status"] == "ANOMALY") & e["severity"].isin(["HIGH", "CRITICAL"])).sum())

    @property
    def services_monitored(self) -> int:
        return int(self.events["service"].nunique()) if len(self.events) else 0

    def anomaly_rate(self) -> float:
        return round(self.anomalies / self.total_logs * 100, 2) if self.total_logs else 0.0
