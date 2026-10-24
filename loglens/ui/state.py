"""Session state for the dashboard.

Everything lives in ``st.session_state`` (memory of the current browser session). Nothing is
written to disk, and a new browser session starts empty.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, fields

import pandas as pd
import streamlit as st

from ..detection import Alert, DetectionConfig, alerts_to_frame, run_detections
from ..filters import EventFilter, alerts_in_scope, apply_event_filter
from ..parser import LogValidationError
from ..pipeline import Dataset, annotate_events, build_dataset, load_demo_dataset

logger = logging.getLogger(__name__)

DATASET = "dataset"
LOAD_ERROR = "load_error"
LAST_UPLOAD = "last_upload_id"
UPLOADER_EPOCH = "uploader_epoch"
FILTER_EPOCH = "filter_epoch"
EVENT_FILTER = "event_filter"
ALERT_CACHE = "alert_cache"
DROP_DUPLICATES = "opt_drop_duplicates"
CONFIG_PREFIX = "cfg_"

# (DetectionConfig field, label, minimum, maximum, tooltip)
CONFIG_CONTROLS: tuple[tuple[str, str, int, int, str], ...] = (
    ("ip_failure_threshold", "LL-001: failed logins per IP", 2, 500,
     "Alert when one source IP has at least this many failed logins inside the window."),
    ("ip_failure_window_minutes", "LL-001: window (minutes)", 1, 1440,
     "Length of the rolling window. Events exactly this far apart still count together."),
    ("account_failure_threshold", "LL-002 / LL-003: failed logins per account", 2, 500,
     "Alert when one account has at least this many failed logins inside the window, from any "
     "IP. LL-003 uses the same number to decide what counts as a burst."),
    ("account_failure_window_minutes", "LL-002 / LL-003: window (minutes)", 1, 1440,
     "Rolling window for LL-002, and for the failure burst that LL-003 looks for."),
    ("success_investigation_minutes", "LL-003: investigation window (minutes)", 1, 1440,
     "A successful login is flagged if it happens within this many minutes AFTER the last "
     "failure of a qualifying burst for the same account."),
    ("denial_threshold", "LL-004: denials per account", 2, 500,
     "Alert when one account has at least this many events with outcome 'denied' (any event "
     "type) inside the window."),
    ("denial_window_minutes", "LL-004: window (minutes)", 1, 1440,
     "Length of the rolling window for LL-004. Events exactly this far apart still count "
     "together."),
)  # fmt: skip


def init_state() -> None:
    st.session_state.setdefault(DATASET, None)
    st.session_state.setdefault(LOAD_ERROR, None)
    st.session_state.setdefault(LAST_UPLOAD, None)
    st.session_state.setdefault(UPLOADER_EPOCH, 0)
    st.session_state.setdefault(FILTER_EPOCH, 0)
    st.session_state.setdefault(EVENT_FILTER, EventFilter())
    st.session_state.setdefault(ALERT_CACHE, None)
    # The settings widgets read their values from here (they are created without ``value=``), so
    # "Restore defaults" can write to these keys without Streamlit warning about two sources.
    defaults = DetectionConfig()
    for name, *_ in CONFIG_CONTROLS:
        st.session_state.setdefault(CONFIG_PREFIX + name, getattr(defaults, name))


def drop_duplicates_enabled() -> bool:
    return bool(st.session_state.get(DROP_DUPLICATES, False))


# --------------------------------------------------------------------------------------
# Loading data
# --------------------------------------------------------------------------------------


def _install(dataset: Dataset) -> None:
    st.session_state[DATASET] = dataset
    st.session_state[LOAD_ERROR] = None
    st.session_state[FILTER_EPOCH] += 1  # new data -> fresh filter widgets


def load_demo() -> None:
    """Button callback: load the bundled synthetic dataset."""
    st.session_state[UPLOADER_EPOCH] += 1  # clear the uploader so the same file can be re-sent
    st.session_state[LAST_UPLOAD] = None
    _install(load_demo_dataset(drop_duplicates=drop_duplicates_enabled()))


def ingest_upload(uploaded) -> None:
    """Parse a newly uploaded file. Invalid files leave the current dataset untouched."""
    if uploaded is None:
        if st.session_state[LAST_UPLOAD] is not None:
            # The file was removed from the uploader: its error message no longer applies.
            st.session_state[LAST_UPLOAD] = None
            st.session_state[LOAD_ERROR] = None
        return
    if uploaded.file_id == st.session_state[LAST_UPLOAD]:
        return
    st.session_state[LAST_UPLOAD] = uploaded.file_id
    try:
        dataset = build_dataset(
            uploaded.name, uploaded.getvalue(), drop_duplicates=drop_duplicates_enabled()
        )
    except LogValidationError as error:
        _refuse(f"Could not load {uploaded.name}: {error}")
        return
    except Exception as error:  # a bug must not take the page down or echo file contents
        # Only the exception TYPE is shown and logged: its message may quote uploaded data.
        logger.warning("Unexpected %s while reading an upload", type(error).__name__)
        _refuse(
            f"Could not load {uploaded.name}: an unexpected {type(error).__name__} occurred "
            "while reading it."
        )
        return
    if dataset.parse.rows_accepted == 0:
        _refuse(_no_valid_rows_message(uploaded.name, dataset))
        return
    _install(dataset)


def _refuse(message: str) -> None:
    """Record why an upload was refused, and say which data the pages are still showing."""
    current: Dataset | None = st.session_state[DATASET]
    if current is not None:
        message += f" The pages still show the previously loaded data ({current.label})."
    st.session_state[LOAD_ERROR] = message


def _no_valid_rows_message(name: str, dataset: Dataset) -> str:
    parse = dataset.parse
    top = parse.rejection_summary().head(4)
    problems = "; ".join(f"{row.rows:,} x {row.column}: {row.reason}" for row in top.itertuples())
    return (
        f"Could not load {name}: none of its {parse.rows_read:,} rows were valid. "
        f"Most common problems - {problems}."
    )


def on_duplicate_toggle() -> None:
    """Re-parse the current file with the new duplicate setting.

    Unlike loading a new file, this keeps the filters: removing exact duplicates leaves the time
    range and the distinct IPs, accounts, types and outcomes unchanged, so every filter choice is
    still valid. (The filter widgets are keyed by ``content_id``, which ignores this setting.)
    """
    current: Dataset | None = st.session_state[DATASET]
    if current is None:
        return
    st.session_state[DATASET] = build_dataset(
        current.label,
        current.raw,
        is_demo=current.is_demo,
        drop_duplicates=drop_duplicates_enabled(),
    )
    st.session_state[LOAD_ERROR] = None


def reset_filters() -> None:
    st.session_state[FILTER_EPOCH] += 1


def reset_detection_settings() -> None:
    defaults = DetectionConfig()
    for name, *_ in CONFIG_CONTROLS:
        st.session_state[CONFIG_PREFIX + name] = getattr(defaults, name)


# --------------------------------------------------------------------------------------
# Derived data
# --------------------------------------------------------------------------------------


def changed_settings(config: DetectionConfig) -> list[str]:
    """'LL-001: failed logins per IP = 4 (default 5)' for every setting that is not the default."""
    defaults = DetectionConfig()
    return [
        f"{label} = {getattr(config, name)} (default {getattr(defaults, name)})"
        for name, label, *_ in CONFIG_CONTROLS
        if getattr(config, name) != getattr(defaults, name)
    ]


def current_config() -> DetectionConfig:
    defaults = DetectionConfig()
    values = {
        f.name: st.session_state.get(CONFIG_PREFIX + f.name, getattr(defaults, f.name))
        for f in fields(DetectionConfig)
    }
    return DetectionConfig(**values)


@dataclass(frozen=True)
class Scope:
    """Everything a page needs: the full data, the detections, and the current filtered view.

    Detections always run on ``all_events``; ``events``/``alerts`` are the filtered view.
    """

    dataset: Dataset
    config: DetectionConfig
    flt: EventFilter
    all_events: pd.DataFrame
    all_alerts: list[Alert]
    events: pd.DataFrame
    alerts: list[Alert]

    @property
    def alert_frame(self) -> pd.DataFrame:
        return alerts_to_frame(self.alerts)


def _detections(dataset: Dataset, config: DetectionConfig) -> tuple[list[Alert], pd.DataFrame]:
    """Run detection once per (dataset, settings) pair and reuse it across reruns."""
    cache = st.session_state[ALERT_CACHE]
    key = (dataset.dataset_id, config)
    if cache is None or cache["key"] != key:
        alerts = run_detections(dataset.events, config)
        cache = {"key": key, "alerts": alerts, "events": annotate_events(dataset.events, alerts)}
        st.session_state[ALERT_CACHE] = cache
    return cache["alerts"], cache["events"]


def build_scope() -> Scope | None:
    dataset: Dataset | None = st.session_state[DATASET]
    if dataset is None:
        return None
    config = current_config()
    all_alerts, all_events = _detections(dataset, config)
    flt: EventFilter = st.session_state[EVENT_FILTER]
    events = apply_event_filter(all_events, flt)
    return Scope(
        dataset=dataset,
        config=config,
        flt=flt,
        all_events=all_events,
        all_alerts=all_alerts,
        events=events,
        alerts=alerts_in_scope(all_alerts, events),
    )


def load_error_message() -> str | None:
    """Raw (untrusted-text-bearing) message; render it with ``components.error_box``."""
    return st.session_state.get(LOAD_ERROR) or None
