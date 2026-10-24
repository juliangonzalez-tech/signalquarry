"""Event filtering shared by the dashboard views and the exports.

Filtering is purely a *view*: detections always run on the complete dataset (filtering first
would break correlations such as "success after failures"). An alert is considered in scope when
at least one of its supporting events passes the filter - one definition used everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .detection import Alert

SEARCH_COLUMNS = ("event_id", "source_ip", "username", "host", "message", "alert_ids")


def _utc(value: pd.Timestamp | None) -> pd.Timestamp | None:
    if value is None:
        return None
    ts = pd.Timestamp(value)
    return ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")


@dataclass(frozen=True)
class EventFilter:
    """Empty selections mean 'no restriction'. Times are UTC and both ends are inclusive."""

    start: pd.Timestamp | None = None
    end: pd.Timestamp | None = None
    source_ips: tuple[str, ...] = ()
    usernames: tuple[str, ...] = ()
    event_types: tuple[str, ...] = ()
    outcomes: tuple[str, ...] = ()
    search: str = ""

    def describe(self) -> list[str]:
        """Plain-text list of the restrictions in force (empty when nothing is filtered)."""
        parts: list[str] = []
        if self.start is not None or self.end is not None:
            start = _utc(self.start)
            end = _utc(self.end)
            left = start.strftime("%Y-%m-%d %H:%M") if start is not None else "start"
            right = end.strftime("%Y-%m-%d %H:%M") if end is not None else "end"
            parts.append(f"Time (UTC): {left} to {right}")
        for label, values in (
            ("Source IP", self.source_ips),
            ("Username", self.usernames),
            ("Event type", self.event_types),
            ("Outcome", self.outcomes),
        ):
            if values:
                extra = f" +{len(values) - 4} more" if len(values) > 4 else ""
                parts.append(f"{label}: {', '.join(values[:4])}{extra}")
        if self.search.strip():
            parts.append(f"Search: {self.search.strip()[:60]}")
        return parts

    @property
    def is_active(self) -> bool:
        return bool(self.describe())


def apply_event_filter(events: pd.DataFrame, flt: EventFilter) -> pd.DataFrame:
    """Return the events matching every active restriction (a new, re-indexed frame)."""
    mask = pd.Series(True, index=events.index)
    start, end = _utc(flt.start), _utc(flt.end)
    if start is not None:
        mask &= events["timestamp"] >= start
    if end is not None:
        mask &= events["timestamp"] <= end
    if flt.source_ips:
        mask &= events["source_ip"].isin(flt.source_ips)
    if flt.usernames:
        mask &= events["username"].isin(flt.usernames)
    if flt.event_types:
        mask &= events["event_type"].isin(flt.event_types)
    if flt.outcomes:
        mask &= events["outcome"].isin(flt.outcomes)

    needle = flt.search.strip()
    if needle:
        hit = pd.Series(False, index=events.index)
        for column in SEARCH_COLUMNS:
            if column in events.columns:
                hit |= events[column].str.contains(needle, case=False, regex=False)
        mask &= hit
    return events.loc[mask].reset_index(drop=True)


def alerts_in_scope(alerts: list[Alert], events_in_scope: pd.DataFrame) -> list[Alert]:
    """Alerts with at least one supporting event among ``events_in_scope``."""
    visible = set(events_in_scope["event_id"].tolist())
    return [a for a in alerts if not visible.isdisjoint(a.event_ids)]
