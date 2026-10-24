"""Runs every registered rule and returns one ordered, uniquely identified alert list."""

from __future__ import annotations

from dataclasses import replace

import pandas as pd

from ..schema import EVENT_ID_COLUMN, REQUIRED_COLUMNS
from .config import DetectionConfig
from .models import SEVERITY_RANK, Alert
from .rules import RULES


def run_detections(events: pd.DataFrame, config: DetectionConfig | None = None) -> list[Alert]:
    """Apply all rules to ``events`` (the table produced by ``parse_csv``).

    Alerts are ordered by time, then rule, account and IP, and numbered ``ALR-0001``... in that
    order. The ordering depends only on event content, so shuffling the rows of the input file
    gives identical alerts and identical IDs.
    """
    config = config or DetectionConfig()
    missing = [c for c in (EVENT_ID_COLUMN, *REQUIRED_COLUMNS) if c not in events.columns]
    if missing:
        raise ValueError(f"events table is missing columns: {', '.join(missing)}")
    if events.empty:
        return []

    alerts = [alert for rule in RULES for alert in rule(events, config)]
    alerts.sort(key=lambda a: (a.timestamp, a.rule_id, a.usernames, a.source_ips, a.event_ids))
    return [replace(alert, alert_id=f"ALR-{i:04d}") for i, alert in enumerate(alerts, start=1)]


def severity_counts(alerts: list[Alert]) -> dict[str, int]:
    """Alerts per severity, always listing every level from lowest to highest."""
    counts = dict.fromkeys(SEVERITY_RANK, 0)
    for alert in alerts:
        counts[alert.severity] += 1
    return counts
