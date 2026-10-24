"""Glue between ingestion and analysis: load a dataset, and cross-reference events with alerts.

Everything here is held in memory for the current session only; nothing is written to disk.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pandas as pd

from .detection import Alert
from .parser import ParseResult, parse_csv
from .sample_data import SAMPLE_FILENAME, SAMPLE_PATH, generate_csv


@dataclass(frozen=True)
class Dataset:
    """A parsed log plus where it came from. ``raw`` is kept so the duplicate setting can be
    changed without asking the user to upload the file again.

    ``dataset_id`` identifies the parsed result (file content + duplicate setting);
    ``content_id`` identifies the file content alone.
    """

    dataset_id: str
    content_id: str
    label: str
    is_demo: bool
    drop_duplicates: bool
    raw: bytes
    parse: ParseResult

    @property
    def events(self) -> pd.DataFrame:
        return self.parse.events


def build_dataset(
    name: str, data: bytes, *, is_demo: bool = False, drop_duplicates: bool = False
) -> Dataset:
    """Parse ``data`` into a :class:`Dataset`. Raises ``LogValidationError`` for unusable files."""
    result = parse_csv(data, source_name=name, drop_duplicates=drop_duplicates)
    return Dataset(
        dataset_id=hashlib.sha256(data + bytes([drop_duplicates])).hexdigest()[:12],
        content_id=hashlib.sha256(data).hexdigest()[:12],
        label=name,
        is_demo=is_demo,
        drop_duplicates=drop_duplicates,
        raw=data,
        parse=result,
    )


def load_demo_dataset(*, drop_duplicates: bool = False) -> Dataset:
    """The bundled synthetic dataset, parsed through the same path as an uploaded file."""
    # Falls back to regenerating the identical content if the bundled file is missing.
    data = SAMPLE_PATH.read_bytes() if SAMPLE_PATH.exists() else generate_csv().encode("utf-8")
    return build_dataset(SAMPLE_FILENAME, data, is_demo=True, drop_duplicates=drop_duplicates)


def annotate_events(events: pd.DataFrame, alerts: list[Alert]) -> pd.DataFrame:
    """Add an ``alert_ids`` column ('ALR-0001, ALR-0003') linking each event to its alerts."""
    by_event: dict[str, list[str]] = {}
    for alert in alerts:
        for event_id in alert.event_ids:
            by_event.setdefault(event_id, []).append(alert.alert_id)
    annotated = events.copy()
    annotated["alert_ids"] = [", ".join(by_event.get(i, ())) for i in events["event_id"].tolist()]
    return annotated
