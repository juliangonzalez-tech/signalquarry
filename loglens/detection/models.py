"""Data structures shared by the detection rules, the dashboard and the exports."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
SEVERITY_RANK: dict[str, int] = {name: rank for rank, name in enumerate(SEVERITIES)}

# Every alert is a heuristic flag for an analyst to review. LogLens never labels anything a
# confirmed incident: it only sees logs, not intent.
CLASSIFICATION = "Heuristic flag"


@dataclass(frozen=True)
class RuleInfo:
    """Static description of a detection rule, used for alert metadata and the in-app guide."""

    rule_id: str
    name: str
    base_severity: str
    what: str  # one-sentence description of the pattern
    benign_causes: tuple[str, ...]  # why this can fire on harmless activity


@dataclass(frozen=True)
class Alert:
    """One flagged cluster of events.

    ``timestamp`` is the time of the first supporting event and ``end_timestamp`` the last.
    ``event_ids`` reference rows of the event table, so every alert can be traced back to
    its evidence.
    """

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    timestamp: pd.Timestamp
    end_timestamp: pd.Timestamp
    usernames: tuple[str, ...]
    source_ips: tuple[str, ...]
    event_ids: tuple[str, ...]
    summary: str  # one sentence: what was observed
    explanation: str  # summary + the rule that fired and why it may be benign
    classification: str = CLASSIFICATION

    @property
    def event_count(self) -> int:
        return len(self.event_ids)


def escalate(base_severity: str, event_count: int, threshold: int, factor: int) -> str:
    """Raise severity by one level when the cluster is at least ``factor`` x the threshold."""
    rank = SEVERITY_RANK[base_severity]
    if event_count >= factor * threshold:
        rank = min(rank + 1, len(SEVERITIES) - 1)
    return SEVERITIES[rank]


def limited_join(items: list[str] | tuple[str, ...], limit: int = 3) -> str:
    """'a, b, c +4 more' - keeps long account/IP lists readable in tables and sentences."""
    shown = ", ".join(items[:limit])
    return shown + (f" +{len(items) - limit} more" if len(items) > limit else "")


ALERT_FRAME_COLUMNS = [
    "alert_id",
    "rule_id",
    "rule_name",
    "severity",
    "classification",
    "timestamp",
    "end_timestamp",
    "account",
    "source_ip",
    "event_count",
    "summary",
    "explanation",
    "usernames",
    "source_ips",
    "event_ids",
]


def alerts_to_frame(alerts: list[Alert]) -> pd.DataFrame:
    """Alerts as a table. ``account``/``source_ip`` are display strings; the tuple columns
    (``usernames``, ``source_ips``, ``event_ids``) keep the full lists for filtering."""
    records = [
        {
            "alert_id": a.alert_id,
            "rule_id": a.rule_id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "classification": a.classification,
            "timestamp": a.timestamp,
            "end_timestamp": a.end_timestamp,
            "account": limited_join(a.usernames),
            "source_ip": limited_join(a.source_ips),
            "event_count": a.event_count,
            "summary": a.summary,
            "explanation": a.explanation,
            "usernames": a.usernames,
            "source_ips": a.source_ips,
            "event_ids": a.event_ids,
        }
        for a in alerts
    ]
    frame = pd.DataFrame(records, columns=ALERT_FRAME_COLUMNS)
    if frame.empty:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
        frame["end_timestamp"] = pd.to_datetime(frame["end_timestamp"], utc=True)
        frame["event_count"] = frame["event_count"].astype("int64")
    return frame
