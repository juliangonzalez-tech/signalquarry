"""Exports and the written analysis summary.

CSV files can be opened in spreadsheet software, where a cell starting with ``=``, ``+``, ``-``
or ``@`` may be executed as a formula (CSV/formula injection). Every exported text cell is
therefore neutralised by :func:`sanitize_cell`.
"""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime

import pandas as pd

from .detection import RULE_CATALOG, SEVERITIES, Alert, DetectionConfig, limited_join
from .filters import EventFilter
from .metrics import compute_metrics, top_source_ips
from .pipeline import Dataset
from .schema import CANONICAL_COLUMNS

EVENT_EXPORT_COLUMNS = ["event_id", *CANONICAL_COLUMNS, "alert_ids"]
ALERT_EXPORT_COLUMNS = [
    "alert_id",
    "rule_id",
    "rule_name",
    "severity",
    "classification",
    "timestamp",
    "end_timestamp",
    "usernames",
    "source_ips",
    "event_count",
    "event_ids",
    "summary",
    "explanation",
]

_FORMULA_TRIGGERS = ("=", "+", "-", "@")
_LEADING_CONTROL = ("\t", "\r", "\n")
MAX_SUMMARY_ALERTS = 25


def sanitize_cell(value: object) -> object:
    """Prefix text that a spreadsheet could interpret as a formula with an apostrophe.

    The apostrophe makes Excel, LibreOffice and Google Sheets treat the cell as plain text.
    Non-string values (numbers) are returned unchanged.
    """
    if not isinstance(value, str) or not value:
        return value
    if value.startswith(_LEADING_CONTROL) or value.lstrip().startswith(_FORMULA_TRIGGERS):
        return "'" + value
    return value


def format_timestamps(series: pd.Series) -> pd.Series:
    """ISO 8601 UTC text, with fractional seconds only if any timestamp has them."""
    utc = series.dt.tz_convert("UTC")
    text = utc.dt.strftime("%Y-%m-%dT%H:%M:%S")
    if (utc.dt.microsecond != 0).any():
        text = text + utc.dt.strftime(".%f")
    return text + "Z"


def _to_csv_bytes(frame: pd.DataFrame) -> bytes:
    safe = frame.copy()
    for column in safe.columns:
        if not pd.api.types.is_numeric_dtype(safe[column]):
            safe[column] = safe[column].map(sanitize_cell)
    return safe.to_csv(index=False, lineterminator="\n").encode("utf-8")


def events_to_csv(events: pd.DataFrame) -> bytes:
    """Events as CSV in the LogLens schema (plus ``event_id`` and ``alert_ids``)."""
    frame = events.copy()
    if "alert_ids" not in frame.columns:
        frame["alert_ids"] = ""
    frame["timestamp"] = format_timestamps(frame["timestamp"])
    return _to_csv_bytes(frame[EVENT_EXPORT_COLUMNS])


def alerts_to_csv(alerts: list[Alert]) -> bytes:
    """Alerts as CSV. List-valued fields are joined with '; '."""
    rows = [
        {
            "alert_id": a.alert_id,
            "rule_id": a.rule_id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "classification": a.classification,
            "timestamp": _iso(a.timestamp),
            "end_timestamp": _iso(a.end_timestamp),
            "usernames": "; ".join(a.usernames),
            "source_ips": "; ".join(a.source_ips),
            "event_count": a.event_count,
            "event_ids": "; ".join(a.event_ids),
            "summary": a.summary,
            "explanation": a.explanation,
        }
        for a in alerts
    ]
    return _to_csv_bytes(pd.DataFrame(rows, columns=ALERT_EXPORT_COLUMNS))


def _iso(ts: pd.Timestamp) -> str:
    return ts.tz_convert("UTC").strftime("%Y-%m-%dT%H:%M:%SZ")


def _display_time(ts: pd.Timestamp | None) -> str:
    return "n/a" if ts is None or pd.isna(ts) else ts.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


def build_summary(
    dataset: Dataset,
    events: pd.DataFrame,
    alerts: list[Alert],
    flt: EventFilter,
    config: DetectionConfig,
    *,
    generated_at: datetime | None = None,
) -> str:
    """A concise plain-text analysis summary for the given scope.

    ``events``/``alerts`` are the in-scope events and alerts; ``dataset`` supplies provenance.
    Plain text on purpose: log values (usernames etc.) are untrusted and must never be
    interpreted as markup.
    """
    generated_at = generated_at or datetime.now(UTC)
    metrics = compute_metrics(events, alerts)
    parse = dataset.parse
    lines: list[str] = []

    def heading(text: str) -> None:
        lines.extend(["", text, "-" * len(text)])

    lines += ["LOGLENS SECURITY ANALYSIS SUMMARY", "=" * 33]
    lines.append(f"Generated:   {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append(f"Data source: {dataset.label}")
    if dataset.is_demo:
        lines.append(
            "*** SYNTHETIC DEMO DATA - made up for demonstration; not real security events ***"
        )

    heading("SCOPE")
    filters = flt.describe()
    scope = "; ".join(filters) if filters else "none (all events)"
    lines.append(f"Filters applied: {scope}")
    lines.append(f"Events in scope: {metrics.total_events:,} of {len(dataset.events):,} loaded")
    lines.append(
        f"Time range in scope: {_display_time(metrics.first_event)} to "
        f"{_display_time(metrics.last_event)}"
    )
    lines.append(
        f"Input quality: {parse.rows_read:,} rows read, {parse.rows_accepted:,} accepted, "
        f"{parse.rows_rejected:,} rejected, {parse.duplicate_rows:,} "
        f"duplicate{'' if parse.duplicate_rows == 1 else 's'} "
        f"{'removed' if parse.duplicates_dropped else 'kept'}"
    )

    heading("KEY NUMBERS")
    lines.append(f"Total events:              {metrics.total_events:,}")
    lines.append(f"Failed authentications:    {metrics.failed_authentications:,}")
    lines.append(f"Unique source IPs:         {metrics.unique_source_ips:,}")
    lines.append(f"Flagged clusters (alerts): {metrics.flagged_clusters:,}")
    lines.append(f"Events in alerts:          {metrics.flagged_events:,}")

    heading("ALERTS BY SEVERITY")
    for severity in reversed(SEVERITIES):
        lines.append(f"  {severity:<9}{metrics.severity_counts[severity]:>4}")

    heading("ALERTS BY RULE")
    for rule_id, rule in RULE_CATALOG.items():
        count = sum(1 for a in alerts if a.rule_id == rule_id)
        lines.append(f"  {rule_id}  {rule.name:<45}{count:>4}")

    heading(f"ALERTS (heuristic flags - {len(alerts)} in scope)")
    if not alerts:
        lines.append("No alerts in this scope.")
    ranked = sorted(alerts, key=lambda a: (-SEVERITIES.index(a.severity), a.timestamp, a.alert_id))
    for alert in ranked[:MAX_SUMMARY_ALERTS]:
        lines.append(
            f"[{alert.severity.upper()}] {alert.alert_id} | {alert.rule_id} | "
            f"{_display_time(alert.timestamp)} | {alert.event_count} events"
        )
        for label, values in (("accounts", alert.usernames), ("source IPs", alert.source_ips)):
            lines.append(
                textwrap.fill(
                    f"{label}: {limited_join(values, 5)}",
                    96,
                    initial_indent="    ",
                    subsequent_indent="      ",
                    break_long_words=False,  # never split a username or address in two
                )
            )
        lines.append(
            textwrap.fill(alert.explanation, 96, initial_indent="    ", subsequent_indent="    ")
        )
    if len(ranked) > MAX_SUMMARY_ALERTS:
        lines.append(f"... and {len(ranked) - MAX_SUMMARY_ALERTS} more; see the alerts CSV export.")

    heading("TOP SOURCE IPS (by event count)")
    top = top_source_ips(events, 5)
    if top.empty:
        lines.append("No events in this scope.")
    for row in top.itertuples():
        lines.append(
            f"  {row.source_ip:<40}{row.total:>6} events "
            f"({row.failure} failure, {row.denied} denied)"
        )

    heading("DETECTION SETTINGS USED")
    lines += [
        f"  LL-001: {config.ip_failure_threshold}+ failed logins per IP in "
        f"{config.ip_failure_window_minutes} min",
        f"  LL-002: {config.account_failure_threshold}+ failed logins per account in "
        f"{config.account_failure_window_minutes} min",
        f"  LL-003: success within {config.success_investigation_minutes} min after the last "
        "failure of an LL-002-style burst",
        f"  LL-004: {config.denial_threshold}+ denied events per account in "
        f"{config.denial_window_minutes} min",
    ]

    heading("IMPORTANT NOTES")
    notes = [
        "Alerts are heuristic flags produced by simple threshold rules. They are NOT confirmed "
        "security incidents; each needs analyst review. Benign causes (mistyped passwords, "
        "shared NAT addresses, misconfigured services) can trigger every rule.",
        "Detection always runs on the full loaded dataset. Filters change only which events and "
        "alerts are summarised here (an alert is in scope if any of its events is).",
        "Absence of alerts does not prove absence of malicious activity.",
    ]
    for note in notes:
        lines.append(textwrap.fill(note, 96, initial_indent="- ", subsequent_indent="  "))
    return "\n".join(lines) + "\n"
