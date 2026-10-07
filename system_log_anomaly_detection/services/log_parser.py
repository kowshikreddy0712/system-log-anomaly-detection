"""
Linux log parsing.

Accepts:
  * CSV exports (columns are matched by common aliases: timestamp/time, host,
    service/program/process, message/msg/content, optional event_type/level)
  * Raw syslog text (`Jun  9 06:06:20 host sshd(pam_unix)[123]: message`)
  * ISO-timestamp text (`2026-09-10 00:07:00 host sshd[123]: message`)

Lines that cannot be parsed are counted and reported, never silently kept as
fake events.
"""

import re
from io import StringIO
from typing import Tuple

import pandas as pd

from models.analysis_result import DatasetInfo

_SYSLOG = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+"
    r"(?P<service>[\w./-]+(?:\([\w./-]+\))?(?:\s\d[\d.]*)?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_ISO = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+"
    r"(?P<service>[\w./()-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "@timestamp", "ts"],
    "hostname": ["hostname", "host", "node", "machine"],
    "service": ["service", "program", "process", "app", "component", "daemon", "ident"],
    "message": ["message", "msg", "content", "log", "text", "description", "details"],
    "raw_event_type": ["event_type", "eventtype", "level", "type", "category"],
    "dbscan_cluster": ["dbscan_cluster"],
    "label": ["label", "actual_label", "is_anomaly", "anomaly", "ground_truth"],
}


def _first_alias(columns_lower: dict, names: list):
    for n in names:
        if n in columns_lower:
            return columns_lower[n]
    return None


def _parse_text(text: str) -> Tuple[pd.DataFrame, int]:
    rows, total = [], 0
    for line in text.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        total += 1
        m = _SYSLOG.match(line) or _ISO.match(line)
        if m:
            rows.append(m.groupdict())
    return pd.DataFrame(rows), total


def _canonicalise_csv(df: pd.DataFrame) -> pd.DataFrame:
    lower = {str(c).strip().lower(): c for c in df.columns}
    out = pd.DataFrame(index=df.index)
    for target, names in _ALIASES.items():
        src = _first_alias(lower, names)
        if src is not None:
            out[target] = df[src]
    missing = [c for c in ("timestamp", "message") if c not in out.columns]
    if missing:
        raise ValueError(
            "CSV is missing required column(s): " + ", ".join(missing)
            + ". Expected at least a timestamp and a message column "
            "(e.g. timestamp, hostname, service, message)."
        )
    if "hostname" not in out.columns:
        out["hostname"] = "unknown"
    if "service" not in out.columns:
        out["service"] = "unknown"
    return out


def parse_bytes(filename: str, data: bytes) -> Tuple[pd.DataFrame, DatasetInfo]:
    """Parse raw file bytes into the canonical Linux-log frame + a parse report."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt"
    text = data.decode("utf-8", errors="ignore")

    if ext == "csv":
        raw = pd.read_csv(StringIO(text))
        total = len(raw)
        df = _canonicalise_csv(raw)
        fmt = "CSV"
    else:
        df, total = _parse_text(text)
        fmt = "Syslog text"
        if df.empty:
            raise ValueError(
                "No lines matched a Linux syslog format. Expected e.g. "
                "'Jun  9 06:06:20 host sshd(pam_unix)[123]: authentication failure ...'."
            )

    # timestamps: syslog has no year -> pandas assigns 1900; remember that
    norm = df["timestamp"].astype(str).str.replace(r"\s+", " ", regex=True)
    ts = pd.to_datetime(norm, errors="coerce", format="%b %d %H:%M:%S")   # classic syslog, no year -> 1900
    if ts.isna().mean() > 0.5:
        ts = pd.to_datetime(norm, errors="coerce", format="mixed")
    df = df.assign(timestamp=ts)
    before = len(df)
    df = df.dropna(subset=["timestamp"]).copy()
    df["message"] = df["message"].fillna("").astype(str)
    df["service"] = df["service"].fillna("unknown").astype(str)
    df["hostname"] = df["hostname"].fillna("unknown").astype(str)
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    dropped = (total - len(df)) if total >= len(df) else (before - len(df))

    has_year = bool(len(df)) and int(df["timestamp"].dt.year.min()) > 1970
    info = DatasetInfo(
        filename=filename,
        size_kb=round(len(data) / 1024, 2),
        file_type=ext,
        num_records=len(df),
        columns=[c for c in df.columns],
        detected_format=fmt,
        total_lines=int(total),
        parsed_rows=int(len(df)),
        dropped_rows=int(max(dropped, 0)),
        has_year=has_year,
        time_start=df["timestamp"].min() if len(df) else None,
        time_end=df["timestamp"].max() if len(df) else None,
    )
    if df.empty:
        raise ValueError("No rows with a valid timestamp were found in this file.")
    return df, info


def parse_uploaded_file(uploaded_file) -> Tuple[pd.DataFrame, DatasetInfo]:
    """Streamlit UploadedFile wrapper (kept for backward compatibility)."""
    return parse_bytes(uploaded_file.name, uploaded_file.getvalue())
