"""Small HTML building blocks shared by every page (KPI cards, badges, callouts, headers)."""

import html

import streamlit as st

from utils.helpers import SEV_COLORS


def page_header(title: str, subtitle: str, status: bool = False) -> None:
    pill = '<span class="status-pill"><span class="dot"></span>Monitoring · Linux log analysis engine online</span>' if status else ""
    st.markdown(
        f'<div class="page-head"><div><h1>{html.escape(title)}</h1><div class="sub">{html.escape(subtitle)}</div></div>{pill}</div>',
        unsafe_allow_html=True,
    )


def kpi_card(label: str, value: str, sub: str = "", tone: str = "") -> None:
    st.markdown(
        f'<div class="kpi {tone}"><div class="kpi-label">{html.escape(label)}</div>'
        f'<div class="kpi-value">{html.escape(str(value))}</div><div class="kpi-sub">{html.escape(sub)}</div></div>',
        unsafe_allow_html=True,
    )


def badge(text: str, kind: str = "") -> str:
    kind = kind or text
    return f'<span class="badge b-{html.escape(str(kind))}">{html.escape(str(text))}</span>'


def callout(text: str, kind: str = "info") -> None:
    """`text` may contain simple <b> tags; callers must only pass trusted strings."""
    st.markdown(f'<div class="callout {kind}">{text}</div>', unsafe_allow_html=True)


def key_values(pairs: list) -> None:
    cells = "".join(
        f'<div><div class="k">{html.escape(k)}</div><div class="v">{v}</div></div>' for k, v in pairs
    )
    st.markdown(f'<div class="panel"><div class="kv">{cells}</div></div>', unsafe_allow_html=True)


def message_box(text: str) -> None:
    st.markdown(f'<div class="msg">{html.escape(str(text))}</div>', unsafe_allow_html=True)


def stage_card(n, title: str, desc: str) -> None:
    st.markdown(
        f'<div class="stage"><div class="n">{html.escape(str(n))}</div><div class="t">{html.escape(title)}</div>'
        f'<div class="d">{html.escape(desc)}</div></div>',
        unsafe_allow_html=True,
    )


def dataset_chips(info) -> None:
    from utils.helpers import fmt_ts
    chips = [info.filename, f"{info.num_records:,} events", f"{fmt_ts(info.time_start, info.has_year)} → {fmt_ts(info.time_end, info.has_year)}"]
    if info.is_demo:
        chips.append("bundled demo dataset")
    st.markdown("".join(f'<span class="chip">{html.escape(c)}</span>' for c in chips), unsafe_allow_html=True)
    if not info.has_year:
        st.caption("Source timestamps carry no year (classic syslog), so dates are shown as month/day. Time ranges are relative to the newest event in the data.")
