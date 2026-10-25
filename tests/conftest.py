"""Shared helpers: build small, explicit logs and run them through the real parser."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

import pandas as pd

from signalquarry.parser import parse_csv
from signalquarry.schema import CANONICAL_COLUMNS

T0 = datetime(2026, 3, 2, 10, 0, 0, tzinfo=UTC)

Row = tuple[datetime, str, str, str, str]  # timestamp, ip, user, event_type, outcome


def at(minutes: float = 0, seconds: float = 0) -> datetime:
    """A time ``minutes``/``seconds`` after the fixed reference time 2026-03-02 10:00:00Z."""
    return T0 + timedelta(minutes=minutes, seconds=seconds)


def fail(when: datetime, ip: str = "203.0.113.5", user: str = "alice") -> Row:
    return (when, ip, user, "login", "failure")


def ok(when: datetime, ip: str = "203.0.113.5", user: str = "alice") -> Row:
    return (when, ip, user, "login", "success")


def deny(when: datetime, ip: str = "192.0.2.10", user: str = "alice") -> Row:
    return (when, ip, user, "access", "denied")


def access(when: datetime, ip: str = "192.0.2.10", user: str = "alice") -> Row:
    return (when, ip, user, "access", "success")


def to_csv(rows: Iterable[Row]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CANONICAL_COLUMNS)
    for when, ip, user, kind, outcome in rows:
        writer.writerow([when.strftime("%Y-%m-%dT%H:%M:%SZ"), ip, user, kind, outcome, "", ""])
    return buffer.getvalue()


def build_events(rows: Iterable[Row]) -> pd.DataFrame:
    """Rows -> validated events via the production parser (keeps duplicates, so tests that
    use identical timestamps are not silently thinned out)."""
    return parse_csv(to_csv(rows), drop_duplicates=False).events
