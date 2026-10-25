"""Summary numbers shown on the Overview page and in the exported report.

Everything is computed from the events and alerts passed in - nothing is hardcoded - so the
numbers always match the scope (all data, or a filtered view) they are shown for.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .detection import SEVERITIES, Alert
from .schema import FAILURE, LOGIN


@dataclass(frozen=True)
class OverviewMetrics:
    total_events: int
    failed_authentications: int
    unique_source_ips: int
    flagged_clusters: int  # number of alerts, each one a cluster of events
    flagged_events: int  # in-scope events that support at least one alert
    severity_counts: dict[str, int]
    first_event: pd.Timestamp | None
    last_event: pd.Timestamp | None


def compute_metrics(events: pd.DataFrame, alerts: list[Alert]) -> OverviewMetrics:
    failed = (events["event_type"] == LOGIN) & (events["outcome"] == FAILURE)
    severity_counts = dict.fromkeys(SEVERITIES, 0)
    flagged_ids: set[str] = set()
    for alert in alerts:
        severity_counts[alert.severity] += 1
        flagged_ids.update(alert.event_ids)
    return OverviewMetrics(
        total_events=len(events),
        failed_authentications=int(failed.sum()),
        unique_source_ips=int(events["source_ip"].nunique()),
        flagged_clusters=len(alerts),
        # Only events inside this scope: an alert's evidence can reach outside a filter.
        # (A plain membership loop: Series.isin with a data-sized set is slow on string columns.)
        flagged_events=sum(
            1 for event_id in events["event_id"].tolist() if event_id in flagged_ids
        ),
        severity_counts=severity_counts,
        first_event=events["timestamp"].min() if len(events) else None,
        last_event=events["timestamp"].max() if len(events) else None,
    )


def top_source_ips(events: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
    """Most active source IPs with their per-outcome counts (ties broken by IP for stability)."""
    columns = ["source_ip", "total", "success", "failure", "denied"]
    if events.empty:
        return pd.DataFrame(columns=columns)
    counts = events.groupby(["source_ip", "outcome"]).size().unstack(fill_value=0)
    for outcome in ("success", "failure", "denied"):
        if outcome not in counts.columns:
            counts[outcome] = 0
    counts["total"] = counts[["success", "failure", "denied"]].sum(axis=1)
    counts = counts.reset_index().sort_values(["total", "source_ip"], ascending=[False, True])
    return counts[columns].head(limit).reset_index(drop=True)
