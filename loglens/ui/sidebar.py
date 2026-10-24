"""Sidebar: data source, filters and detection settings.

The filter widgets build an :class:`EventFilter` that every page reads from session state, so
all views share one definition of "the current scope".
"""

from __future__ import annotations

import ipaddress
from datetime import timedelta

import pandas as pd
import streamlit as st

from ..filters import EventFilter
from ..schema import MAX_UPLOAD_BYTES
from . import components, state
from .safe import escape_label

MAX_FILTER_OPTIONS = 2000  # a pick-list with 100k entries would freeze the browser


def _ip_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


def _frequent_values(series: pd.Series) -> tuple[list[str], int]:
    """The most frequent values (at most ``MAX_FILTER_OPTIONS``) and the distinct total."""
    counts = series.value_counts()
    return list(counts.index[:MAX_FILTER_OPTIONS]), len(counts)


def _data_section() -> None:
    st.subheader("Data")
    st.button(
        "Load demo data",
        type="primary",
        icon=":material/science:",
        on_click=state.load_demo,
        width="stretch",
        key="sidebar_demo",
        help="Load the bundled synthetic dataset (made-up events, not real incidents).",
    )
    uploaded = st.file_uploader(
        "Upload a CSV log",
        type=["csv"],
        max_upload_size=MAX_UPLOAD_BYTES // (1024 * 1024),
        key=f"uploader_{st.session_state[state.UPLOADER_EPOCH]}",
        help="Processed locally in memory. Required columns: timestamp, source_ip, username, "
        "event_type, outcome. Optional: host, message.",
    )
    state.ingest_upload(uploaded)
    st.checkbox(
        "Remove exact duplicate rows",
        value=False,
        key=state.DROP_DUPLICATES,
        on_change=state.on_duplicate_toggle,
        help="Off by default: identical rows are kept (and counted in the data-quality panel). "
        "With second-level timestamps, scripted attempts look like duplicates, so removing them "
        "can hide an attack. Turn this on if your log repeats lines, for example because a "
        "forwarder retried; removed rows no longer count towards any detection.",
    )

    dataset = st.session_state[state.DATASET]
    if dataset is not None:
        components.dataset_caption(dataset)


def _filters_section(dataset) -> EventFilter:
    st.subheader("Filters")
    st.caption("Apply to the Overview, Alerts, Event Explorer and Reports pages.")
    events = dataset.events
    # Keyed by the file content, not the duplicate setting: re-reading the same file with
    # duplicates removed keeps the filters (see state.on_duplicate_toggle).
    suffix = f"{dataset.content_id}-{st.session_state[state.FILTER_EPOCH]}"

    lo = events["timestamp"].min().tz_localize(None).floor("min")
    hi = events["timestamp"].max().tz_localize(None).ceil("min")
    if hi <= lo:
        hi = lo + pd.Timedelta(minutes=1)
    start, end = st.slider(
        "Time range (UTC)",
        min_value=lo.to_pydatetime(),
        max_value=hi.to_pydatetime(),
        value=(lo.to_pydatetime(), hi.to_pydatetime()),
        step=timedelta(minutes=1),
        format="YYYY-MM-DD HH:mm",
        key=f"flt_time_{suffix}",
    )
    ip_options, ip_total = _frequent_values(events["source_ip"])
    ips = st.multiselect(
        "Source IP",
        options=sorted(ip_options, key=_ip_sort_key),
        key=f"flt_ip_{suffix}",
        placeholder="All source IPs",
    )
    user_options, user_total = _frequent_values(events["username"])
    users = st.multiselect(
        "Username",
        options=sorted(user_options),
        format_func=escape_label,
        key=f"flt_user_{suffix}",
        placeholder="All usernames",
    )
    if max(ip_total, user_total) > MAX_FILTER_OPTIONS:
        st.caption(
            f"Pick-lists show the {MAX_FILTER_OPTIONS:,} most frequent values; use Search below "
            "to find any other IP or username."
        )
    types = st.multiselect(
        "Event type",
        options=sorted(events["event_type"].unique()),
        format_func=lambda value: value.replace("_", " "),
        key=f"flt_type_{suffix}",
        placeholder="All event types",
    )
    outcomes = st.multiselect(
        "Outcome",
        options=sorted(events["outcome"].unique()),
        key=f"flt_outcome_{suffix}",
        placeholder="All outcomes",
    )
    search = st.text_input(
        "Search",
        key=f"flt_search_{suffix}",
        placeholder="user, IP, host, message, alert ID",
        help="Case-insensitive text match across username, IP, host, message, event ID and "
        "alert ID.",
    )

    start_ts = pd.Timestamp(start, tz="UTC")
    end_ts = pd.Timestamp(end, tz="UTC")
    flt = EventFilter(
        start=start_ts if start_ts != lo.tz_localize("UTC") else None,
        # the slider has minute precision; include the whole selected end minute
        end=end_ts + pd.Timedelta(seconds=59, microseconds=999999)
        if end_ts != hi.tz_localize("UTC")
        else None,
        source_ips=tuple(ips),
        usernames=tuple(users),
        event_types=tuple(types),
        outcomes=tuple(outcomes),
        search=search,
    )
    st.button(
        "Reset filters",
        key="sidebar_reset",
        on_click=state.reset_filters,
        width="stretch",
        disabled=not flt.is_active,
    )
    return flt


def _detection_section() -> None:
    with st.expander("Detection settings", expanded=False):
        st.caption(
            "Thresholds and rolling windows for the rules. Changing them re-runs detection on the "
            "loaded data."
        )
        # No ``value=``: the starting values are put in session state by state.init_state.
        for name, label, minimum, maximum, tooltip in state.CONFIG_CONTROLS:
            st.number_input(
                label,
                help=tooltip,
                min_value=minimum,
                max_value=maximum,
                step=1,
                key=state.CONFIG_PREFIX + name,
            )
        st.button(
            "Restore defaults",
            key="sidebar_defaults",
            on_click=state.reset_detection_settings,
            width="stretch",
        )


def render() -> None:
    with st.sidebar:
        _data_section()
        dataset = st.session_state[state.DATASET]
        if dataset is not None:
            st.session_state[state.EVENT_FILTER] = _filters_section(dataset)
        else:
            st.session_state[state.EVENT_FILTER] = EventFilter()
        _detection_section()
        st.divider()
        st.caption(
            "LogLens runs entirely on this computer. Uploaded data is held in memory for this "
            "session only."
        )
