"""Reports page: downloads that match the current scope exactly."""

from __future__ import annotations

import streamlit as st

from ...reporting import alerts_to_csv, build_summary, events_to_csv
from .. import components


def render() -> None:
    scope = components.require_scope()
    if scope is None:
        return

    components.page_header(
        "Reports", "Download what you are looking at. Every export uses the current scope."
    )
    components.dataset_notice(scope)
    components.scope_bar(scope)

    left, middle, right = st.columns(3, gap="medium")
    with left, st.container(border=True):
        st.markdown("#### Events")
        st.write(f"{len(scope.events):,} events in scope, as CSV with their alert IDs.")
        st.download_button(
            "Download events (CSV)",
            data=lambda: events_to_csv(scope.events),  # built only when clicked
            file_name="loglens_events.csv",
            mime="text/csv",
            icon=":material/download:",
            disabled=scope.events.empty,
            width="stretch",
            key="report_events",
        )
    with middle, st.container(border=True):
        st.markdown("#### Alerts")
        st.write(f"{len(scope.alerts):,} alerts in scope, with their evidence event IDs.")
        st.download_button(
            "Download alerts (CSV)",
            data=lambda: alerts_to_csv(scope.alerts),
            file_name="loglens_alerts.csv",
            mime="text/csv",
            icon=":material/download:",
            disabled=not scope.alerts,
            width="stretch",
            key="report_alerts",
        )
    summary = build_summary(scope.dataset, scope.events, scope.alerts, scope.flt, scope.config)
    with right, st.container(border=True):
        st.markdown("#### Analysis summary")
        st.write("A concise plain-text write-up of the metrics and alerts in scope.")
        st.download_button(
            "Download summary (TXT)",
            data=summary.encode("utf-8"),
            file_name="loglens_summary.txt",
            mime="text/plain",
            icon=":material/download:",
            width="stretch",
            key="report_summary",
        )

    st.markdown("##### Summary preview")
    st.code(summary, language=None, wrap_lines=True)
    st.caption(
        "Exports are written only when you click download. CSV cells that begin with =, +, - or @ "
        "are prefixed with an apostrophe so spreadsheet programs treat them as text, not formulas."
    )
