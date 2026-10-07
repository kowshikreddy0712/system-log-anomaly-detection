"""Plotly chart builders. They take plain DataFrames and return figures; no ML here."""

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from utils.helpers import SEV_COLORS, auto_freq

_FONT = dict(family="IBM Plex Sans, system-ui, sans-serif", color="#c3cfdf", size=12)
_GRID = "#1a2535"
CYAN, RED, GREEN, GREY = "#38bdf8", "#ef4444", "#22c55e", "#64748b"


def _base(fig: go.Figure, height: int = 300, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=8, r=8, t=10, b=8), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=_FONT, showlegend=legend, legend=dict(orientation="h", y=1.12, x=0, bgcolor="rgba(0,0,0,0)"),
        hoverlabel=dict(bgcolor="#151e2c", font_size=12),
    )
    fig.update_xaxes(gridcolor=_GRID, zeroline=False, linecolor=_GRID)
    fig.update_yaxes(gridcolor=_GRID, zeroline=False, linecolor=_GRID)
    return fig


def _empty(msg: str = "No data in this selection", height: int = 260) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=msg, showarrow=False, font=dict(color="#8190a6", size=13))
    fig.update_xaxes(visible=False); fig.update_yaxes(visible=False)
    return _base(fig, height, legend=False)


def anomaly_trend(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return _empty()
    freq = auto_freq(df)
    g = df.assign(bin=df["timestamp"].dt.floor(freq)).groupby(["bin", "status"]).size().unstack(fill_value=0)
    fig = go.Figure()
    fig.add_bar(x=g.index, y=g.get("NORMAL", pd.Series(0, index=g.index)), name="Normal", marker_color="#1f6b45")
    fig.add_bar(x=g.index, y=g.get("ANOMALY", pd.Series(0, index=g.index)), name="Anomalous", marker_color=RED)
    fig.update_layout(barmode="stack", bargap=0.15)
    fig.update_yaxes(title="events per bin")
    return _base(fig, 300)


def severity_bars(df: pd.DataFrame) -> go.Figure:
    a = df[df["status"] == "ANOMALY"]
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    counts = a["severity"].value_counts().reindex(order, fill_value=0)
    if counts.sum() == 0:
        return _empty("No anomalous events")
    fig = go.Figure(go.Bar(x=counts.values, y=counts.index, orientation="h", marker_color=[SEV_COLORS[s] for s in counts.index],
                           text=[f"{v:,}" for v in counts.values], textposition="outside", cliponaxis=False))
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(range=[0, counts.max() * 1.2])
    return _base(fig, 300, legend=False)


def top_bar(series: pd.Series, color: str = CYAN, height: int = 280) -> go.Figure:
    s = series.sort_values(ascending=True).tail(8)
    if s.empty:
        return _empty()
    fig = go.Figure(go.Bar(x=s.values, y=s.index.astype(str), orientation="h", marker_color=color,
                           text=[f"{v:,}" for v in s.values], textposition="outside", cliponaxis=False))
    fig.update_xaxes(range=[0, s.max() * 1.22])
    return _base(fig, height, legend=False)


def projection_scatter(proj: pd.DataFrame) -> go.Figure:
    if proj.empty:
        return _empty("Not enough data for a projection")
    fig = go.Figure()
    normal = proj[~proj["is_noise"]]
    noise = proj[proj["is_noise"]]
    fig.add_scattergl(x=normal["x"], y=normal["y"], mode="markers", name="Clustered (normal)",
                      marker=dict(size=5, color="#3b6ea5", opacity=.45), text=normal["cluster"] + " · " + normal["service"],
                      hovertemplate="%{text}<extra></extra>")
    fig.add_scattergl(x=noise["x"], y=noise["y"], mode="markers", name="DBSCAN noise (anomalous)",
                      marker=dict(size=6, color=RED, opacity=.85), text=noise["service"] + " · " + noise["event_class"],
                      hovertemplate="%{text}<extra></extra>")
    fig.update_xaxes(title="PC 1"); fig.update_yaxes(title="PC 2")
    return _base(fig, 380)


def importance_bar(imp: pd.DataFrame) -> go.Figure:
    if imp.empty:
        return _empty("No trained model")
    d = imp.head(12).iloc[::-1]
    fig = go.Figure(go.Bar(x=d["importance"], y=d["feature"], orientation="h", marker_color=CYAN))
    return _base(fig, 360, legend=False)


def confusion_heatmap(cm: list) -> go.Figure:
    z = np.array(cm)
    labels = ["Normal", "Anomalous"]
    fig = go.Figure(go.Heatmap(z=z, x=[f"Predicted {l}" for l in labels], y=[f"Actual {l}" for l in labels], colorscale=[[0, "#0f1a2a"], [1, "#1b7fb0"]],
                               showscale=False, text=[[f"{v:,}" for v in r] for r in z], texttemplate="%{text}", textfont=dict(size=16, color="white")))
    fig.update_yaxes(autorange="reversed")
    return _base(fig, 300, legend=False)


def roc_curve_fig(roc: dict, auc: float) -> go.Figure:
    fig = go.Figure()
    fig.add_scatter(x=[0, 1], y=[0, 1], mode="lines", line=dict(dash="dot", color=GREY), name="Chance")
    fig.add_scatter(x=roc["fpr"], y=roc["tpr"], mode="lines", line=dict(color=CYAN, width=2.5), name=f"Decision Tree (AUC {auc:.3f})")
    fig.update_xaxes(title="False positive rate"); fig.update_yaxes(title="True positive rate")
    return _base(fig, 300)


def cluster_sizes(clusters: pd.DataFrame) -> go.Figure:
    d = clusters.head(12).iloc[::-1]
    colors = [RED if "Noise" in c else "#3b6ea5" for c in d["cluster"]]
    fig = go.Figure(go.Bar(x=d["size"], y=d["cluster"], orientation="h", marker_color=colors,
                           text=[f"{v:,}" for v in d["size"]], textposition="outside", cliponaxis=False))
    fig.update_xaxes(type="log", title="events (log scale)")
    return _base(fig, 340, legend=False)


def support_bars(itemsets: pd.DataFrame) -> go.Figure:
    if itemsets.empty:
        return _empty("No frequent itemsets at this support level")
    d = itemsets.sort_values("support", ascending=False).head(12).iloc[::-1]
    colors = [RED if "ANOMALY" in i else CYAN for i in d["itemset"]]
    fig = go.Figure(go.Bar(x=d["support"] * 100, y=d["itemset"], orientation="h", marker_color=colors,
                           text=[f"{v:.1f}%" for v in d["support"] * 100], textposition="outside", cliponaxis=False))
    fig.update_xaxes(title="support (% of 5-min windows)", range=[0, d["support"].max() * 100 * 1.2])
    return _base(fig, 420, legend=False)


def risk_breakdown_bar(parts: pd.DataFrame) -> go.Figure:
    d = parts.iloc[::-1]
    fig = go.Figure()
    fig.add_bar(x=d["max_weight"], y=d["component"], orientation="h", marker_color="#1a2535", name="Max possible", hoverinfo="skip")
    fig.add_bar(x=d["contribution"], y=d["component"], orientation="h", marker_color=CYAN, name="Contribution",
                text=[f"{v:.2f}" for v in d["contribution"]], textposition="inside")
    fig.update_layout(barmode="overlay")
    return _base(fig, 280)
