"""Filtering, metrics, charts' numbers, exports and the summary must all agree with each other."""

from __future__ import annotations

import io
from datetime import datetime

import pandas as pd
import pytest

from signalquarry import charts
from signalquarry.detection import DetectionConfig, alerts_to_frame, run_detections
from signalquarry.filters import EventFilter, alerts_in_scope, apply_event_filter
from signalquarry.metrics import compute_metrics, top_source_ips
from signalquarry.parser import parse_csv
from signalquarry.pipeline import annotate_events, load_demo_dataset
from signalquarry.reporting import (
    ALERT_EXPORT_COLUMNS,
    EVENT_EXPORT_COLUMNS,
    alerts_to_csv,
    build_summary,
    events_to_csv,
    sanitize_cell,
)


@pytest.fixture(scope="module")
def demo():
    return load_demo_dataset()


@pytest.fixture(scope="module")
def alerts(demo):
    return run_detections(demo.events)


@pytest.fixture(scope="module")
def events(demo, alerts):
    return annotate_events(demo.events, alerts)


def read_csv_text(data: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)


# --------------------------------------------------------------------------------------
# Filters
# --------------------------------------------------------------------------------------


def test_empty_filter_returns_everything(events):
    assert len(apply_event_filter(events, EventFilter())) == len(events)
    assert not EventFilter().is_active


def test_each_filter_restricts_as_documented(events):
    by_user = apply_event_filter(events, EventFilter(usernames=("svc.backup",)))
    assert set(by_user["username"]) == {"svc.backup"}

    by_ip = apply_event_filter(events, EventFilter(source_ips=("203.0.113.45", "203.0.113.99")))
    assert set(by_ip["source_ip"]) == {"203.0.113.45", "203.0.113.99"}

    by_type = apply_event_filter(events, EventFilter(event_types=("logout",)))
    assert set(by_type["event_type"]) == {"logout"}

    by_outcome = apply_event_filter(events, EventFilter(outcomes=("denied",)))
    assert set(by_outcome["outcome"]) == {"denied"}


def test_filters_combine_with_and_semantics(events):
    combined = apply_event_filter(
        events,
        EventFilter(
            usernames=("svc.reporting",), outcomes=("failure",), source_ips=("203.0.113.88",)
        ),
    )
    assert len(combined) == 16
    assert (combined["outcome"] == "failure").all()


def test_time_range_is_inclusive_at_both_ends(events):
    start = pd.Timestamp("2026-03-02T03:12:00Z")
    end = pd.Timestamp("2026-03-02T03:17:52Z")
    window = apply_event_filter(
        events, EventFilter(start=start, end=end, usernames=("svc.backup",))
    )
    assert len(window) == 16
    assert window["timestamp"].min() == start
    assert window["timestamp"].max() == end
    assert (
        len(apply_event_filter(events, EventFilter(start=end, end=end, usernames=("svc.backup",))))
        == 1
    )


def test_naive_filter_times_are_treated_as_utc(events):
    naive = apply_event_filter(
        events, EventFilter(start=datetime(2026, 3, 4, 13, 0), end=datetime(2026, 3, 4, 14, 0))
    )
    aware = apply_event_filter(
        events,
        EventFilter(start=pd.Timestamp("2026-03-04T13:00Z"), end=pd.Timestamp("2026-03-04T14:00Z")),
    )
    pd.testing.assert_frame_equal(naive, aware)
    assert len(naive) > 0


def test_search_is_case_insensitive_literal_substring_across_text_columns(events):
    assert (
        len(apply_event_filter(events, EventFilter(search="SVC.BACKUP")))
        == (events["username"] == "svc.backup").sum()
    )
    by_message = apply_event_filter(events, EventFilter(search="invalid username"))
    assert len(by_message) == (events["message"].str.contains("Invalid username", case=False)).sum()
    by_alert = apply_event_filter(events, EventFilter(search="ALR-0010"))
    assert len(by_alert) == 6 and set(by_alert["username"]) == {"priya.raman"}
    # '.' is a literal here, not a regex wildcard
    assert (
        len(apply_event_filter(events, EventFilter(search="203.0.113.4")))
        == (events["source_ip"] == "203.0.113.45").sum()
    )
    assert apply_event_filter(events, EventFilter(search="203x0x113")).empty


def test_filtering_never_changes_the_original(events):
    snapshot = events.copy()
    apply_event_filter(events, EventFilter(usernames=("svc.etl",)))
    pd.testing.assert_frame_equal(events, snapshot)


def test_filter_description_lists_active_restrictions():
    flt = EventFilter(usernames=("a", "b"), outcomes=("failure",), search="  abc ")
    text = " | ".join(flt.describe())
    assert "Username: a, b" in text and "Outcome: failure" in text and "Search: abc" in text
    assert flt.is_active


# --------------------------------------------------------------------------------------
# Counts and charts reflect the filter scope
# --------------------------------------------------------------------------------------


def test_metrics_are_computed_from_the_scope_they_describe(events, alerts):
    everything = compute_metrics(events, alerts)
    assert everything.total_events == len(events)
    assert (
        everything.failed_authentications
        == ((events["event_type"] == "login") & (events["outcome"] == "failure")).sum()
    )
    assert everything.unique_source_ips == events["source_ip"].nunique()
    assert everything.flagged_clusters == len(alerts) == sum(everything.severity_counts.values())

    scope = apply_event_filter(events, EventFilter(usernames=("marcus.lee",)))
    scoped_alerts = alerts_in_scope(alerts, scope)
    scoped = compute_metrics(scope, scoped_alerts)
    assert scoped.total_events == len(scope) < everything.total_events
    assert scoped.flagged_clusters == 2  # the LL-002 and LL-003 alerts for marcus.lee
    assert scoped.severity_counts == {"low": 0, "medium": 1, "high": 1, "critical": 0}


def test_events_in_alerts_never_exceeds_the_events_in_scope(events, alerts):
    # Regression: the metric used to count every event of every in-scope alert, so a filter that
    # left ONE event (of a 17-event alert) displayed "1 total events, 17 events in alerts".
    one_event = apply_event_filter(events, EventFilter(search="EVT-000515"))
    metrics = compute_metrics(one_event, alerts_in_scope(alerts, one_event))
    assert metrics.total_events == 1
    assert metrics.flagged_clusters == 3  # it is evidence for three alerts
    assert metrics.flagged_events == 1

    for flt in (
        EventFilter(),
        EventFilter(outcomes=("failure",)),
        EventFilter(usernames=("svc.reporting",), outcomes=("success",)),
        EventFilter(start=pd.Timestamp("2026-03-04T01:50Z"), end=pd.Timestamp("2026-03-04T01:55Z")),
    ):
        scope = apply_event_filter(events, flt)
        scoped = compute_metrics(scope, alerts_in_scope(alerts, scope))
        assert scoped.flagged_events <= scoped.total_events
        assert scoped.flagged_events == int((scope["alert_ids"] != "").sum())


def test_alert_scope_follows_the_supporting_events(events, alerts):
    # Only failures kept: LL-004 (denials) drops out; every login-failure based alert stays.
    failures_only = apply_event_filter(events, EventFilter(outcomes=("failure",)))
    assert {a.rule_id for a in alerts_in_scope(alerts, failures_only)} == {
        "LL-001",
        "LL-002",
        "LL-003",
    }

    day_two = apply_event_filter(
        events,
        EventFilter(
            start=pd.Timestamp("2026-03-03T00:00Z"), end=pd.Timestamp("2026-03-03T23:59:59Z")
        ),
    )
    assert {a.alert_id for a in alerts_in_scope(alerts, day_two)} == {
        "ALR-0004",
        "ALR-0005",
        "ALR-0006",
    }

    assert alerts_in_scope(alerts, events.iloc[0:0]) == []


def test_chart_numbers_add_up_to_the_filtered_events(events, alerts):
    for flt in (
        EventFilter(),
        EventFilter(usernames=("svc.reporting", "svc.backup")),
        EventFilter(outcomes=("failure", "denied")),
        EventFilter(start=pd.Timestamp("2026-03-03T08:00Z"), end=pd.Timestamp("2026-03-03T12:00Z")),
    ):
        scope = apply_event_filter(events, flt)
        counts, _ = charts.events_over_time_data(scope)
        assert counts["count"].sum() == len(scope)
        logins = scope[scope["event_type"] == "login"]
        assert charts.auth_outcomes_data(scope).sum() == len(logins)
        top = top_source_ips(scope, 5)
        assert top["total"].is_monotonic_decreasing
        assert (top["total"] == top[["success", "failure", "denied"]].sum(axis=1)).all()
        frame = alerts_to_frame(alerts_in_scope(alerts, scope))
        assert charts.rule_distribution_data(frame)["count"].sum() == len(frame)


def test_all_figures_build_for_full_filtered_and_empty_scopes(events, alerts):
    empty_events = events.iloc[0:0]
    for scope_events, scope_alerts in (
        (events, alerts),
        (events.iloc[:5], alerts[:1]),
        (empty_events, []),
    ):
        frame = alerts_to_frame(scope_alerts)
        figures = [
            charts.events_over_time(scope_events),
            charts.auth_outcomes(scope_events),
            charts.top_ips(scope_events),
            charts.rule_distribution(frame),
            charts.alert_timeline(frame),
        ]
        assert all(fig.layout.title.text for fig in figures)
    assert len(charts.events_over_time(empty_events).data) == 0  # empty state, not a broken chart
    assert len(charts.events_over_time(events).data) >= 2


def test_alert_timeline_axis_is_padded_when_alerts_share_a_time(alerts):
    same_time = alerts_to_frame([a for a in alerts if a.timestamp == alerts[-3].timestamp])
    assert same_time["timestamp"].nunique() == 1
    fig = charts.alert_timeline(same_time)
    low, high = fig.layout.xaxis.range
    assert pd.Timestamp(high) - pd.Timestamp(low) == pd.Timedelta(hours=1)  # +-30 minutes
    assert pd.Timestamp(low) < same_time["timestamp"].iloc[0].tz_localize(None) < pd.Timestamp(high)
    # widely spread alerts keep Plotly's automatic range
    assert charts.alert_timeline(alerts_to_frame(alerts)).layout.xaxis.range is None


def test_time_bin_scales_with_the_span():
    t0 = pd.Timestamp("2026-03-02T00:00Z")
    assert charts.pick_time_bin(t0, t0 + pd.Timedelta(minutes=30)) == "1min"
    assert charts.pick_time_bin(t0, t0 + pd.Timedelta(hours=72)) == "1h"
    assert charts.pick_time_bin(t0, t0 + pd.Timedelta(days=400)) == "1D"
    assert charts.pick_time_bin(t0, t0) == "1min"


# --------------------------------------------------------------------------------------
# Exports match what is on screen
# --------------------------------------------------------------------------------------


def test_events_export_matches_the_filtered_view(events):
    scope = apply_event_filter(
        events, EventFilter(usernames=("svc.reporting",), outcomes=("failure",))
    )
    exported = read_csv_text(events_to_csv(scope))
    assert list(exported.columns) == EVENT_EXPORT_COLUMNS
    assert len(exported) == len(scope) == 16
    assert list(exported["event_id"]) == list(scope["event_id"])
    assert set(exported["username"]) == {"svc.reporting"}
    assert exported["timestamp"].iloc[0] == "2026-03-04T01:47:00Z"
    assert exported["alert_ids"].iloc[0] == "ALR-0007, ALR-0008, ALR-0009"


def test_full_events_export_round_trips_through_the_parser(events):
    result = parse_csv(events_to_csv(events))
    assert result.rows_rejected == 0
    assert any("alert_ids" in warning for warning in result.warnings())  # extra column ignored
    original = events.drop(columns=["source_row", "alert_ids"]).reset_index(drop=True)
    again = result.events.drop(columns=["source_row"]).reset_index(drop=True)
    pd.testing.assert_frame_equal(original, again)


def test_alerts_export_matches_alert_objects(alerts):
    exported = read_csv_text(alerts_to_csv(alerts))
    assert list(exported.columns) == ALERT_EXPORT_COLUMNS
    assert len(exported) == len(alerts)
    for row, alert in zip(exported.itertuples(), alerts, strict=True):
        assert row.alert_id == alert.alert_id
        assert row.rule_id == alert.rule_id
        assert row.severity == alert.severity
        assert row.classification == "Heuristic flag"
        assert int(row.event_count) == alert.event_count == len(row.event_ids.split("; "))
        assert row.event_ids.split("; ") == list(alert.event_ids)
        assert row.explanation == alert.explanation
    assert alerts_to_csv([]).decode().strip().split(",")[0] == "alert_id"


def test_exported_evidence_ids_exist_in_the_events_export(events, alerts):
    event_ids = set(read_csv_text(events_to_csv(events))["event_id"])
    for alert in alerts:
        assert set(alert.event_ids) <= event_ids


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=SUM(A1:A9)", "'=SUM(A1:A9)"),
        ("+1+1", "'+1+1"),
        ("-2+3", "'-2+3"),
        ("@cmd", "'@cmd"),
        ("\tcmd", "'\tcmd"),
        ("\rcmd", "'\rcmd"),
        ('  =HYPERLINK("x")', '\'  =HYPERLINK("x")'),
        ("alice", "alice"),
        ("Invalid username or password", "Invalid username or password"),
        ("a=b", "a=b"),
        ("", ""),
        (42, 42),
    ],
)
def test_sanitize_cell(value, expected):
    assert sanitize_cell(value) == expected


def test_csv_exports_neutralise_formula_injection():
    hostile = (
        "timestamp,source_ip,username,event_type,outcome,host,message\n"
        "2026-03-02T10:00:00Z,192.0.2.1,=cmd|' /C calc'!A0,login,failure,@evil,=1+1\n"
        "2026-03-02T10:00:01Z,192.0.2.1,=cmd|' /C calc'!A0,login,failure,-host,+SUM(1)\n"
        "2026-03-02T10:00:02Z,192.0.2.1,=cmd|' /C calc'!A0,login,failure,h,\t=1\n"
    )
    events = parse_csv(hostile).events
    exported = read_csv_text(events_to_csv(events))
    for column in ("username", "host", "message"):
        for cell in exported[column]:
            assert not cell or cell[0] not in "=+-@\t\r", (column, cell)
    assert exported["username"].iloc[0] == "'=cmd|' /c calc'!a0"  # usernames are lower-cased

    config = DetectionConfig(ip_failure_threshold=3, account_failure_threshold=3)
    flagged = run_detections(events, config)
    assert flagged
    alert_csv = read_csv_text(alerts_to_csv(flagged))
    for cell in alert_csv["usernames"]:
        assert cell.startswith("'=")


# --------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------


def test_summary_reports_the_numbers_for_its_scope(demo, events, alerts):
    when = datetime(2026, 3, 5, 12, 0)
    config = DetectionConfig()
    everything = build_summary(demo, events, alerts, EventFilter(), config, generated_at=when)
    assert "SYNTHETIC DEMO DATA" in everything
    assert f"Total events:              {len(events):,}" in everything
    assert "Flagged clusters (alerts): 10" in everything
    assert "Filters applied: none (all events)" in everything
    assert "NOT confirmed" in everything
    assert "Generated:   2026-03-05 12:00:00 UTC" in everything
    for alert in alerts:
        assert alert.alert_id in everything

    flt = EventFilter(usernames=("priya.raman",))
    scope = apply_event_filter(events, flt)
    scoped = build_summary(
        demo, scope, alerts_in_scope(alerts, scope), flt, config, generated_at=when
    )
    assert f"Events in scope: {len(scope):,} of {len(events):,} loaded" in scoped
    assert "Flagged clusters (alerts): 1" in scoped
    assert "Username: priya.raman" in scoped
    assert "ALR-0010" in scoped and "ALR-0001" not in scoped


def test_summary_handles_an_empty_scope(demo, events):
    flt = EventFilter(search="no-such-thing")
    scope = apply_event_filter(events, flt)
    text = build_summary(demo, scope, [], flt, DetectionConfig())
    assert "Events in scope: 0 of" in text
    assert "No alerts in this scope." in text
    assert "No events in this scope." in text


def test_summary_of_uploaded_data_is_not_labelled_synthetic(demo, events, alerts):
    from dataclasses import replace

    user_dataset = replace(demo, is_demo=False, label="my-logs.csv")
    text = build_summary(user_dataset, events, alerts, EventFilter(), DetectionConfig())
    assert "SYNTHETIC" not in text
    assert "my-logs.csv" in text
