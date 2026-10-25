"""Overview page: headline numbers and charts for the current scope."""

from __future__ import annotations

import streamlit as st

from ... import charts
from ...metrics import compute_metrics
from ...parser import ParseResult
from .. import components

PLOTLY_CONFIG = {"displaylogo": False, "modeBarButtonsToRemove": ["lasso2d", "select2d"]}


def _plot(figure, key: str) -> None:
    st.plotly_chart(figure, width="stretch", config=PLOTLY_CONFIG, key=key)


def _data_quality(parse: ParseResult) -> None:
    with st.expander("Data quality: how this file was read"):
        a, b, c, d = st.columns(4)
        a.metric("Rows read", f"{parse.rows_read:,}")
        b.metric("Events accepted", f"{parse.rows_accepted:,}")
        c.metric("Rows rejected", f"{parse.rows_rejected:,}")
        d.metric(
            "Duplicates removed" if parse.duplicates_dropped else "Duplicates kept",
            f"{parse.duplicate_rows:,}",
        )
        warnings = parse.warnings()
        if not warnings:
            st.success("No problems found: every row was valid.", icon=":material/check_circle:")
        if warnings:
            components.plain_list(warnings)
        if parse.rows_rejected:
            st.markdown("**Why rows were rejected**")
            st.dataframe(parse.rejection_summary(), hide_index=True, width="stretch")
            st.markdown(
                "**First rejected rows** (row numbers match the spreadsheet row, header = 1)"
            )
            st.dataframe(parse.issues.head(200), hide_index=True, width="stretch")


def render() -> None:
    scope = components.require_scope()
    if scope is None:
        return

    components.page_header(
        "Overview", "Headline numbers, charts and alerts for the events in the current scope."
    )
    components.dataset_notice(scope)
    components.scope_bar(scope)

    metrics = compute_metrics(scope.events, scope.alerts)
    total, failed, ips, clusters = st.columns(4)
    total.metric("Total events", f"{metrics.total_events:,}", border=True)
    failed.metric(
        "Failed authentications",
        f"{metrics.failed_authentications:,}",
        border=True,
        help="Login events with outcome 'failure'.",
    )
    ips.metric("Unique source IPs", f"{metrics.unique_source_ips:,}", border=True)
    clusters.metric(
        "Flagged event clusters",
        f"{metrics.flagged_clusters:,}",
        delta=f"{metrics.flagged_events:,} events in alerts",
        delta_color="off",
        delta_arrow="off",
        border=True,
        help="Each alert is one cluster of related events that crossed a detection threshold. "
        "An alert counts here when at least one of its events is in the current scope.",
    )

    st.markdown("##### Alerts by severity")
    components.severity_cards(metrics.severity_counts)
    components.heuristic_note()

    if scope.events.empty:
        components.no_results("No events match the current filters.")
    else:
        with st.container(border=True):
            _plot(charts.events_over_time(scope.events), "chart_time")
        left, right = st.columns([2, 3])
        with left, st.container(border=True):
            _plot(charts.auth_outcomes(scope.events), "chart_outcomes")
        with right, st.container(border=True):
            _plot(charts.top_ips(scope.events), "chart_ips")

        alert_frame = scope.alert_frame
        left, right = st.columns(2)
        with left, st.container(border=True):
            _plot(charts.rule_distribution(alert_frame), "chart_rules")
        with right, st.container(border=True):
            _plot(charts.alert_timeline(alert_frame), "chart_timeline")

    _data_quality(scope.dataset.parse)
