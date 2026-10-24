"""Alerts page: a sortable, filterable table and an evidence inspector for each alert."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from ...detection import RULE_CATALOG, SEVERITIES, SEVERITY_RANK, Alert, describe_rules
from ...reporting import alerts_to_csv, events_to_csv
from ...schema import CANONICAL_COLUMNS
from .. import components, tables

SORT_OPTIONS = {
    "Severity (highest first)": (["_rank", "timestamp"], [False, True]),
    "Time (oldest first)": (["timestamp", "_rank"], [True, False]),
    "Time (newest first)": (["timestamp", "_rank"], [False, False]),
    "Supporting events (most first)": (["event_count", "_rank"], [False, False]),
    "Rule": (["rule_id", "timestamp"], [True, True]),
}


def _filter_frame(frame: pd.DataFrame) -> pd.DataFrame:
    left, middle, right = st.columns([3, 2, 2])  # wide enough to show all four severity chips
    severities = left.multiselect(
        "Severity",
        options=list(SEVERITIES)[::-1],
        default=list(SEVERITIES)[::-1],
        format_func=str.capitalize,
        key="alerts_severity",
    )
    rules = middle.multiselect(
        "Detection rule",
        options=list(RULE_CATALOG),
        format_func=lambda rule_id: f"{rule_id}  {RULE_CATALOG[rule_id].name}",
        key="alerts_rule",
        placeholder="All rules",
    )
    text = right.text_input(
        "Account or IP contains", key="alerts_text", placeholder="e.g. svc.backup or 203.0.113"
    )

    mask = frame["severity"].isin(severities)
    if rules:
        mask &= frame["rule_id"].isin(rules)
    needle = text.strip().lower()
    if needle:
        mask &= frame.apply(
            lambda row: any(
                needle in value.lower() for value in (*row["usernames"], *row["source_ips"])
            ),
            axis=1,
        )
    return frame[mask]


def _sort_frame(frame: pd.DataFrame) -> pd.DataFrame:
    left, right = st.columns([2, 4])
    choice = left.selectbox("Sort by", list(SORT_OPTIONS), key="alerts_sort")
    right.caption("Click a column header to sort by it instead.")
    by, ascending = SORT_OPTIONS[choice]
    ranked = frame.assign(_rank=frame["severity"].map(SEVERITY_RANK))
    return ranked.sort_values(by, ascending=ascending, kind="stable").drop(columns="_rank")


RULE_COLUMN_HELP = "; ".join(f"{rule_id}: {rule.name}" for rule_id, rule in RULE_CATALOG.items())


def _alerts_table(frame: pd.DataFrame) -> None:
    # "Why it was flagged" comes right after the rule ID: it already names the account and IP,
    # and on a laptop-width screen the columns after it need horizontal scrolling.
    table = pd.DataFrame(
        {
            "Time (UTC)": tables.utc_naive(frame["timestamp"]),
            "Alert": frame["alert_id"],
            "Severity": frame["severity"].map(components.severity_label),
            "Rule": frame["rule_id"],
            "Why it was flagged": frame["summary"],
            "Events": frame["event_count"],
            "Account": frame["account"],
            "Source IP": frame["source_ip"],
        }
    )
    st.dataframe(
        table,
        hide_index=True,
        width="stretch",
        height=min(38 + 35 * len(table), 440),
        column_config={
            "Time (UTC)": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
            "Alert": st.column_config.TextColumn(width="small"),
            "Events": st.column_config.NumberColumn(width="small"),
            "Rule": st.column_config.TextColumn(width="small", help=RULE_COLUMN_HELP),
            "Why it was flagged": st.column_config.TextColumn(width="large"),
        },
    )


def _inspector(scope, frame: pd.DataFrame, alerts_by_id: dict[str, Alert]) -> None:
    st.markdown("### Inspect evidence")
    # Labels are built once. Looking each one up with a frame filter inside format_func made the
    # page quadratic in the number of alerts (4,000 alerts: 4 s per click).
    labels = {
        row.alert_id: (
            f"{row.alert_id} | {row.severity.capitalize()} | {row.rule_id} | "
            f"{row.timestamp:%Y-%m-%d %H:%M} UTC"
        )
        for row in frame.itertuples()
    }
    chosen = st.selectbox(
        "Alert",
        options=list(labels),
        format_func=labels.__getitem__,
        key="inspect_alert",
        help="Choose an alert to see why it fired and the exact log rows behind it. The list "
        "follows the alert filters and sort order above.",
    )
    alert = alerts_by_id[chosen]
    rule = RULE_CATALOG[alert.rule_id]
    trigger = next(
        r["trigger"] for r in describe_rules(scope.config) if r["rule"].rule_id == alert.rule_id
    )

    with st.container(border=True):
        top = st.columns([1, 2, 1, 2])
        top[0].markdown(
            f"**Severity**<br>{components.severity_badge(alert.severity)}", unsafe_allow_html=True
        )
        top[1].markdown(f"**Rule**<br>{alert.rule_id}: {rule.name}", unsafe_allow_html=True)
        top[2].metric("Supporting events", alert.event_count)
        top[3].markdown(
            f"**Status**<br>{alert.classification} "
            "<span class='ll-dim'>(needs analyst review)</span>",
            unsafe_allow_html=True,
        )
        start = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        same_day = alert.end_timestamp.date() == alert.timestamp.date()
        end = alert.end_timestamp.strftime("%H:%M:%S" if same_day else "%Y-%m-%d %H:%M:%S")
        st.text(f"Time window (UTC): {start} to {end}")
        st.text(f"Accounts ({len(alert.usernames)}): {', '.join(alert.usernames)}")
        st.text(f"Source IPs ({len(alert.source_ips)}): {', '.join(alert.source_ips)}")

    why, benign = st.columns(2)
    with why, st.container(border=True):
        st.markdown("**Why it was flagged**")
        components.plain_text(alert.explanation)
        st.markdown("**Rule logic**")
        st.markdown(f"{rule.what} Triggered by: {trigger}")  # static text, no log content
    with benign, st.container(border=True):
        st.markdown("**Could be harmless if...**")
        st.markdown("\n".join(f"- {cause}" for cause in rule.benign_causes))
        st.caption(
            "LogLens only sees log events, not intent. Check whether the activity matches a known "
            "user, device or job before treating it as an attack."
        )

    evidence = scope.all_events[scope.all_events["event_id"].isin(alert.event_ids)]
    st.markdown(f"**Supporting events ({len(evidence)})** - the exact log rows behind this alert")
    repeated = int(evidence.duplicated(subset=list(CANONICAL_COLUMNS), keep="first").sum())
    if repeated:
        st.info(
            f"{repeated} of these rows are exact duplicates of another row in this alert "
            "(same timestamp, IP, account, event type, outcome, host and message) and are counted "
            "as separate events. If they are repeated log lines rather than repeated attempts, "
            "this alert overstates the activity; the sidebar can remove exact duplicates.",
            icon=":material/content_copy:",
        )
    st.dataframe(
        tables.event_table(evidence, with_alerts=True),
        hide_index=True,
        width="stretch",
        height=min(38 + 35 * len(evidence), 400),
        column_config=tables.EVENT_COLUMN_CONFIG,
    )
    st.download_button(
        f"Download evidence for {alert.alert_id} (CSV)",
        data=lambda: events_to_csv(evidence),
        file_name=f"{alert.alert_id}_evidence.csv",
        mime="text/csv",
        icon=":material/download:",
    )


def render() -> None:
    scope = components.require_scope()
    if scope is None:
        return

    components.page_header(
        "Security alerts",
        "Each alert is a cluster of events that crossed a detection threshold - a lead to "
        "investigate, not a verdict.",
    )
    components.dataset_notice(scope)
    components.scope_bar(
        scope, note="alerts are shown when at least one of their events is in scope"
    )
    components.heuristic_note()

    frame = scope.alert_frame
    if frame.empty:
        if scope.all_alerts:
            components.no_results("No alerts have supporting events inside the current filters.")
        else:
            st.success(
                "No detection rule fired on this data. That does not prove the activity is safe - "
                "it only means none of the four rules' thresholds were crossed.",
                icon=":material/check_circle:",
            )
        return

    with st.container(border=True):
        shown = _sort_frame(_filter_frame(frame))
        st.caption(f"Showing {len(shown):,} of {len(frame):,} alerts in scope.")
        if shown.empty:
            st.info("No alerts match these alert filters.", icon=":material/filter_alt_off:")
            return
        _alerts_table(shown)
        alerts_by_id = {a.alert_id: a for a in scope.alerts}
        displayed = [alerts_by_id[i] for i in shown["alert_id"]]
        st.download_button(
            f"Download these {len(displayed):,} alerts (CSV)",
            data=lambda: alerts_to_csv(displayed),
            file_name="loglens_alerts_shown.csv",
            mime="text/csv",
            icon=":material/download:",
        )

    _inspector(scope, shown, alerts_by_id)
