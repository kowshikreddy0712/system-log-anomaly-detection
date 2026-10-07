"""Small shared helpers used across the app."""

from pathlib import Path

import pandas as pd
import streamlit as st

TIME_RANGES = ["Last 1 hour", "Last 24 hours", "Last 7 days", "All data"]
_RANGE_DELTAS = {"Last 1 hour": pd.Timedelta(hours=1), "Last 24 hours": pd.Timedelta(hours=24),
                 "Last 7 days": pd.Timedelta(days=7)}

SEV_COLORS = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#38bdf8"}
STATUS_COLORS = {"ANOMALY": "#ef4444", "NORMAL": "#22c55e"}

PAGES = [
    ("📊", "Overview"), ("🚨", "Anomalies"), ("📜", "Log Explorer"), ("🔍", "Investigation"),
    ("📁", "Upload Linux Logs"), ("📈", "Reports"), ("⚙️", "Settings"),
]


def load_css(path: str) -> None:
    css_path = Path(path)
    if not css_path.exists():
        return

    theme = st.session_state.get("theme", "dark")
    palette = {
        "dark": {
            "bg": "#0b1020",
            "panel": "#101a2b",
            "panel_2": "#152235",
            "sidebar": "#0d1424",
            "sidebar_hover": "#16253d",
            "sidebar_active": "#17324f",
            "border": "#233754",
            "border_2": "#2e456a",
            "text": "#edf5ff",
            "muted": "#9aaec3",
            "accent": "#38bdf8",
            "brand_bg": "#102a43",
            "brand_border": "#25598b",
            "subtle_bg": "#0d1624",
            "input_bg": "#0d1624",
            "card_bg": "#101a2b",
            "shadow": "rgba(8, 15, 25, 0.45)",
        },
        "light": {
            "bg": "#f4f8fc",
            "panel": "#ffffff",
            "panel_2": "#edf4ff",
            "sidebar": "#edf4fb",
            "sidebar_hover": "#e1ecfb",
            "sidebar_active": "#dfeffc",
            "border": "#d5e0ee",
            "border_2": "#bfd1ea",
            "text": "#152033",
            "muted": "#56677f",
            "accent": "#0d6ecf",
            "brand_bg": "#eaf5ff",
            "brand_border": "#bfd9f7",
            "subtle_bg": "#f8fbff",
            "input_bg": "#f9fbff",
            "card_bg": "#ffffff",
            "shadow": "rgba(148, 163, 184, 0.28)",
        },
    }[theme]

    css = css_path.read_text(encoding='utf-8')
    st.markdown(
        f"""
        <style>
        .stApp {{
            --bg: {palette['bg']};
            --panel: {palette['panel']};
            --panel-2: {palette['panel_2']};
            --sidebar: {palette['sidebar']};
            --sidebar-hover: {palette['sidebar_hover']};
            --sidebar-active: {palette['sidebar_active']};
            --border: {palette['border']};
            --border-2: {palette['border_2']};
            --text: {palette['text']};
            --muted: {palette['muted']};
            --accent: {palette['accent']};
            --brand-bg: {palette['brand_bg']};
            --brand-border: {palette['brand_border']};
            --subtle-bg: {palette['subtle_bg']};
            --input-bg: {palette['input_bg']};
            --card-bg: {palette['card_bg']};
            --shadow: {palette['shadow']};
        }}
        {css}
        </style>
        """,
        unsafe_allow_html=True,
    )


def init_session_state() -> None:
    defaults = {
        "logged_in": False, "username": None, "user_id": None, "current_page": "Overview",
        "analysis_result": None, "source": None, "selected_event": None, "detection_params": {},
        "theme": "dark",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def goto(page: str, **state) -> None:
    for k, v in state.items():
        st.session_state[k] = v
    st.session_state.current_page = page
    st.rerun()


def format_number(n) -> str:
    return f"{int(n):,}"


def fmt_ts(ts, has_year: bool = True) -> str:
    """Syslog has no year, so never display a fake one."""
    if pd.isna(ts):
        return "—"
    return ts.strftime("%Y-%m-%d %H:%M:%S") if has_year else ts.strftime("%b %d %H:%M:%S")


def fmt_ts_series(s: pd.Series, has_year: bool = True) -> pd.Series:
    return s.dt.strftime("%Y-%m-%d %H:%M:%S" if has_year else "%b %d %H:%M:%S")


def filter_time_range(df: pd.DataFrame, choice: str) -> pd.DataFrame:
    """Time ranges are relative to the newest event in the dataset, not the wall clock."""
    if choice == "All data" or df.empty:
        return df
    end = df["timestamp"].max()
    return df[df["timestamp"] > end - _RANGE_DELTAS[choice]]


def auto_freq(df: pd.DataFrame, target_bins: int = 48) -> str:
    if df.empty:
        return "1h"
    span = (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
    step = max(span / target_bins, 60)
    for sec, f in [(60, "1min"), (300, "5min"), (900, "15min"), (1800, "30min"), (3600, "1h"), (10800, "3h"),
                   (21600, "6h"), (43200, "12h"), (86400, "1D"), (7 * 86400, "7D")]:
        if step <= sec:
            return f
    return "7D"
