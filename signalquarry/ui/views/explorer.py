"""Event Explorer: the raw events for the current scope, searchable and exportable."""

from __future__ import annotations

import streamlit as st

from ...reporting import events_to_csv
from .. import components, tables

MAX_DISPLAY_ROWS = 20_000


def render() -> None:
    scope = components.require_scope()
    if scope is None:
        return

    components.page_header(
        "Event explorer",
        "Browse the individual log events. Use the sidebar filters to narrow them.",
    )
    components.dataset_notice(scope)
    components.scope_bar(scope)

    only_flagged = st.toggle(
        "Only events that support an alert",
        key="explorer_only_flagged",
        help="Hide events that are not part of any alert's evidence.",
    )
    events = scope.events
    if only_flagged:
        events = events[events["alert_ids"] != ""]

    if events.empty:
        components.no_results("No events match the current filters.")
        return

    flagged = int((events["alert_ids"] != "").sum())
    failed = int(((events["event_type"] == "login") & (events["outcome"] == "failure")).sum())
    a, b, c = st.columns(3)
    a.metric("Events shown", f"{len(events):,}", border=True)
    b.metric("Failed authentications", f"{failed:,}", border=True)
    c.metric("Part of an alert", f"{flagged:,}", border=True)

    visible = events.head(MAX_DISPLAY_ROWS)
    if len(visible) < len(events):
        st.warning(
            f"Showing the first {len(visible):,} of {len(events):,} events. "
            "The CSV download contains all of them.",
            icon=":material/info:",
        )
    st.dataframe(
        tables.event_table(visible, with_alerts=True),
        hide_index=True,
        width="stretch",
        height=520,
        column_config=tables.EVENT_COLUMN_CONFIG,
    )
    st.download_button(
        f"Download these {len(events):,} events (CSV)",
        data=lambda: events_to_csv(events),  # built only when clicked
        file_name="signalquarry_events.csv",
        mime="text/csv",
        icon=":material/download:",
    )
    st.caption(
        "Time column is UTC. The Alerts column lists the alert IDs each event is evidence for. "
        "Cells that start with =, +, - or @ are prefixed with an apostrophe in the CSV so "
        "spreadsheets cannot run them as formulas."
    )
