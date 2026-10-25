"""Plotly figures for the dashboard.

Each chart is built purely from the DataFrames it is given, so it always reflects the scope
(all data or a filtered view) of those frames. The ``*_data`` helpers expose the numbers behind
a chart so tests can check them against the filtered events.
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from .detection import RULE_CATALOG, SEVERITIES
from .metrics import top_source_ips
from .palette import GRID, MUTED_TEXT, OUTCOME_COLORS, SEVERITY_COLORS, TEXT
from .schema import LOGIN, OUTCOMES

# Candidate bar widths, smallest first. The first that gives <= MAX_BARS bars is used.
_BIN_CHOICES = ("1min", "5min", "15min", "1h", "3h", "6h", "1D")
_BIN_SECONDS = {
    "1min": 60,
    "5min": 300,
    "15min": 900,
    "1h": 3600,
    "3h": 10800,
    "6h": 21600,
    "1D": 86400,
}
_BIN_LABELS = {
    "1min": "minute",
    "5min": "5 minutes",
    "15min": "15 minutes",
    "1h": "hour",
    "3h": "3 hours",
    "6h": "6 hours",
    "1D": "day",
}
MAX_BARS = 80
TOP_ROOM = 84  # px above the plot area for the title row and a (possibly wrapped) legend row


def _style(fig: go.Figure, title: str, height: int = 340) -> go.Figure:
    fig.update_layout(
        title={
            "text": title,
            "x": 0,
            "y": 1,
            "yref": "container",
            "yanchor": "top",
            "font": {"size": 15, "color": TEXT},
        },
        height=height + TOP_ROOM - 48,
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": TEXT, "size": 12},
        # Title on its own row, legend on the row below it: stays clear of each other even
        # when the legend wraps on a narrow screen.
        margin={"l": 10, "r": 10, "t": TOP_ROOM, "b": 10},
        legend={"orientation": "h", "y": 1.0, "yanchor": "bottom", "x": 0, "xanchor": "left"},
        hoverlabel={"font_size": 12},
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID, automargin=True)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID, automargin=True)
    return fig


def empty_figure(title: str, message: str = "No data in the current scope") -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        showarrow=False,
        font={"size": 14, "color": MUTED_TEXT},
        x=0.5,
        y=0.5,
        xref="paper",
        yref="paper",
    )
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _style(fig, title, height=240)


def pick_time_bin(first: pd.Timestamp, last: pd.Timestamp) -> str:
    """Smallest bar width that keeps the chart to at most ``MAX_BARS`` bars."""
    span = max((last - first).total_seconds(), 1)
    for choice in _BIN_CHOICES:
        if span / _BIN_SECONDS[choice] <= MAX_BARS:
            return choice
    return _BIN_CHOICES[-1]


# --------------------------------------------------------------------------------------
# Events over time
# --------------------------------------------------------------------------------------


def events_over_time_data(events: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    """Event counts per (time bin, outcome) and the bin width used. Counts sum to len(events)."""
    if events.empty:
        return pd.DataFrame(columns=["bin", "outcome", "count"]), "1h"
    freq = pick_time_bin(events["timestamp"].min(), events["timestamp"].max())
    binned = events.assign(bin=events["timestamp"].dt.floor(freq))
    counts = binned.groupby(["bin", "outcome"]).size().reset_index(name="count")
    return counts, freq


def events_over_time(events: pd.DataFrame) -> go.Figure:
    title = "Security events over time"
    counts, freq = events_over_time_data(events)
    if counts.empty:
        return empty_figure(title)
    fig = go.Figure()
    for outcome in OUTCOMES:
        part = counts[counts["outcome"] == outcome]
        if part.empty:
            continue
        fig.add_bar(
            x=part["bin"],
            y=part["count"],
            name=outcome.capitalize(),
            marker_color=OUTCOME_COLORS[outcome],
            hovertemplate="%{x|%Y-%m-%d %H:%M} UTC<br>%{y} " + outcome + " events<extra></extra>",
        )
    fig.update_layout(barmode="stack", bargap=0.15)
    fig.update_xaxes(title_text=f"Time (UTC) - one bar per {_BIN_LABELS[freq]}")
    fig.update_yaxes(title_text="Events")
    return _style(fig, title)


# --------------------------------------------------------------------------------------
# Authentication outcomes
# --------------------------------------------------------------------------------------


def auth_outcomes_data(events: pd.DataFrame) -> pd.Series:
    """Login events per outcome (only outcomes that occur)."""
    logins = events[events["event_type"] == LOGIN]
    return logins["outcome"].value_counts().reindex(OUTCOMES).dropna().astype(int)


def auth_outcomes(events: pd.DataFrame) -> go.Figure:
    title = "Authentication outcomes (login events)"
    counts = auth_outcomes_data(events)
    if counts.empty:
        return empty_figure(title, "No login events in the current scope")
    fig = go.Figure(
        go.Pie(
            labels=[o.capitalize() for o in counts.index],
            values=counts.to_numpy(),
            hole=0.55,
            marker={"colors": [OUTCOME_COLORS[o] for o in counts.index]},
            sort=False,
            textinfo="label+percent",
            hovertemplate="%{label}: %{value} logins (%{percent})<extra></extra>",
        )
    )
    fig.update_layout(showlegend=False)
    fig.add_annotation(
        text=f"{int(counts.sum()):,}<br><span style='font-size:11px'>logins</span>",
        showarrow=False,
        font={"size": 20, "color": TEXT},
        x=0.5,
        y=0.5,
        xref="paper",
        yref="paper",
    )
    return _style(fig, title)


# --------------------------------------------------------------------------------------
# Most active source IPs
# --------------------------------------------------------------------------------------


def top_ips(events: pd.DataFrame, limit: int = 10) -> go.Figure:
    title = f"Most active source IPs (top {limit})"
    top = top_source_ips(events, limit)
    if top.empty:
        return empty_figure(title)
    fig = go.Figure()
    for outcome in OUTCOMES:
        fig.add_bar(
            y=top["source_ip"],
            x=top[outcome],
            name=outcome.capitalize(),
            orientation="h",
            marker_color=OUTCOME_COLORS[outcome],
            hovertemplate="%{y}<br>%{x} " + outcome + " events<extra></extra>",
        )
    fig.update_layout(barmode="stack")
    fig.update_yaxes(autorange="reversed", type="category")
    fig.update_xaxes(title_text="Events")
    return _style(fig, title, height=max(260, 28 * len(top) + 110))


# --------------------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------------------


def rule_distribution_data(alert_frame: pd.DataFrame) -> pd.DataFrame:
    """Alert counts per (rule, severity) for every rule, including rules with no alerts."""
    rows = []
    for rule_id, rule in RULE_CATALOG.items():
        subset = alert_frame[alert_frame["rule_id"] == rule_id]
        for severity in SEVERITIES:
            rows.append(
                {
                    "rule_id": rule_id,
                    "rule": f"{rule_id}  {rule.name}",
                    "severity": severity,
                    "count": int((subset["severity"] == severity).sum()),
                }
            )
    return pd.DataFrame(rows)


def rule_distribution(alert_frame: pd.DataFrame) -> go.Figure:
    title = "Alerts by detection rule"
    if alert_frame.empty:
        return empty_figure(title, "No alerts in the current scope")
    data = rule_distribution_data(alert_frame)
    fig = go.Figure()
    for severity in SEVERITIES:
        part = data[data["severity"] == severity]
        fig.add_bar(
            y=part["rule"],
            x=part["count"],
            name=severity.capitalize(),
            orientation="h",
            marker_color=SEVERITY_COLORS[severity],
            hovertemplate="%{y}<br>%{x} " + severity + " alerts<extra></extra>",
        )
    fig.update_layout(barmode="stack")
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(title_text="Alerts", dtick=1)
    return _style(fig, title, height=300)


def alert_timeline(alert_frame: pd.DataFrame) -> go.Figure:
    """One marker per alert at its first supporting event; marker size = supporting events."""
    title = "Alert activity over time"
    if alert_frame.empty:
        return empty_figure(title, "No alerts in the current scope")
    fig = go.Figure()
    biggest = max(int(alert_frame["event_count"].max()), 1)
    for severity in SEVERITIES:
        part = alert_frame[alert_frame["severity"] == severity]
        if part.empty:
            continue
        fig.add_scatter(
            x=part["timestamp"],
            y=part["rule_id"],
            mode="markers",
            name=severity.capitalize(),
            marker={
                "color": SEVERITY_COLORS[severity],
                "size": 12 + 28 * part["event_count"].to_numpy() / biggest,
                "line": {"width": 1, "color": TEXT},
                "opacity": 0.9,
            },
            customdata=part[["alert_id", "event_count"]].to_numpy(),
            hovertemplate=(
                "%{customdata[0]} - " + severity + "<br>%{x|%Y-%m-%d %H:%M:%S} UTC"
                "<br>%{customdata[1]} events<extra></extra>"
            ),
        )
    fig.update_yaxes(
        categoryorder="array",
        categoryarray=list(RULE_CATALOG)[::-1],
        type="category",
        title_text="Rule",
    )
    fig.update_xaxes(title_text="Time of first supporting event (UTC)")
    x_range = timeline_x_range(alert_frame["timestamp"].min(), alert_frame["timestamp"].max())
    if x_range:
        fig.update_xaxes(range=x_range)
    return _style(fig, title, height=300)


def timeline_x_range(first: pd.Timestamp, last: pd.Timestamp) -> list[str] | None:
    """Pad the x-axis when all alerts start within an hour of each other.

    Without this Plotly zooms in to milliseconds when every marker has the same time.
    """
    if last - first >= pd.Timedelta(hours=1):
        return None
    pad = pd.Timedelta(minutes=30)
    return [
        (first - pad).strftime("%Y-%m-%d %H:%M:%S"),
        (last + pad).strftime("%Y-%m-%d %H:%M:%S"),
    ]
