"""UI behaviours that mutation testing showed were unchecked.

Purely visual settings (borders, column ratios, table heights) are deliberately not pinned: a test
for those would just restate the code. What is pinned here changes what a user sees or gets.
"""

from __future__ import annotations

import dataclasses
import re

import pytest
from test_app import APP, TIMEOUT, fresh_app, load_demo, metric_values, view_app
from test_edge_cases import BENIGN, HEADER, page

from loglens.detection import (
    RULE_CATALOG,
    SEVERITIES,
    DetectionConfig,
    describe_rules,
    run_detections,
)
from loglens.parser import parse_csv
from loglens.pipeline import build_dataset, load_demo_dataset
from loglens.ui import state, tables
from loglens.ui.components import SEVERITY_EMOJI, severity_label

RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@pytest.fixture(scope="module")
def demo_alerts():
    return {a.alert_id: a for a in run_detections(load_demo_dataset().events)}


def table_order(app) -> list[str]:
    return list(app.dataframe[0].value["Alert"])


# --------------------------------------------------------------------------------------
# Alerts page
# --------------------------------------------------------------------------------------


def test_every_sort_option_orders_the_alert_table_as_its_label_says(demo_alerts):
    alerts = list(demo_alerts.values())
    # Expected orders are written with plain Python sorting, independent of the page's pandas
    # sort. Ties are broken the way the page documents: by the secondary key, then input order.
    expected = {
        "Severity (highest first)": sorted(alerts, key=lambda a: (-RANK[a.severity], a.timestamp)),
        "Time (oldest first)": sorted(alerts, key=lambda a: (a.timestamp, -RANK[a.severity])),
        "Time (newest first)": sorted(
            alerts, key=lambda a: (a.timestamp, RANK[a.severity]), reverse=True
        ),
        "Supporting events (most first)": sorted(
            alerts, key=lambda a: (a.event_count, RANK[a.severity]), reverse=True
        ),
        "Rule": sorted(alerts, key=lambda a: (a.rule_id, a.timestamp)),
    }
    for option, ordered in expected.items():
        app = view_app("alerts")
        next(s for s in app.selectbox if s.key == "alerts_sort").select(option).run()
        assert not app.exception
        assert table_order(app) == [a.alert_id for a in ordered], option


@pytest.mark.parametrize("alert_id", ["ALR-0001", "ALR-0002", "ALR-0009", "ALR-0010"])
def test_inspector_shows_the_rule_that_actually_fired(alert_id, demo_alerts):
    alert = demo_alerts[alert_id]
    app = view_app("alerts")
    next(s for s in app.selectbox if s.key == "inspect_alert").select(alert_id).run()
    assert not app.exception
    text = " ".join(m.value for m in app.markdown)
    triggers = {r["rule"].rule_id: r["trigger"] for r in describe_rules(DetectionConfig())}
    assert f"Triggered by: {triggers[alert.rule_id]}" in text
    assert RULE_CATALOG[alert.rule_id].what in text
    for other_id, trigger in triggers.items():
        if other_id != alert.rule_id:
            assert f"Triggered by: {trigger}" not in text


# --------------------------------------------------------------------------------------
# Explorer
# --------------------------------------------------------------------------------------


def test_explorer_headline_numbers_are_exact():
    app = view_app("explorer")
    next(t for t in app.sidebar.text_input if t.label == "Search").set_value("svc.reporting").run()
    metrics = metric_values(app)
    # 6 routine events + 16 failures + 1 success; the 17 failure/success events are alert evidence
    shown = (
        metrics["Events shown"],
        metrics["Failed authentications"],
        metrics["Part of an alert"],
    )
    assert shown == ("23", "16", "17")


def _many_events(count: int) -> str:
    lines = [HEADER.rstrip("\n")]
    for i in range(count):
        stamp = f"2026-03-02T{i // 3600 % 24:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z"
        lines.append(f"{stamp},192.0.2.{i % 250 + 1},user{i % 90},access,success,h,m{i}")
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(("count", "warned"), [(20_000, False), (20_001, True)])
def test_explorer_row_cap_warning_appears_only_above_20000(count, warned):
    app = page("explorer", _many_events(count))
    assert bool(app.warning) is warned
    assert len(app.dataframe[0].value) == min(count, 20_000)


# --------------------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------------------


def test_overview_reports_clean_files_as_clean_and_dirty_files_as_not():
    clean = page("overview", BENIGN)
    assert any("No problems found" in s.value for s in clean.success)
    dirty = page("overview", BENIGN + "not-a-time,192.0.2.1,x,login,success,h,m\n")
    assert not any("No problems found" in s.value for s in dirty.success)


def test_overview_lists_at_most_200_rejected_rows_but_counts_all():
    bad = "".join(f"not-a-time{i},192.0.2.1,x,login,success,h,m\n" for i in range(250))
    app = page("overview", BENIGN + bad)
    assert len(app.dataframe[1].value) == 200  # the "first rejected rows" table
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Rows rejected"] == "250"


def test_markdown_that_contains_html_is_rendered_as_html_not_shown_as_tags():
    tag = re.compile(r"</?(div|span|br|h1|p)\b")
    for name in ("overview", "alerts", "explorer", "reports"):
        app = view_app(name)
        for element in app.markdown:
            if tag.search(element.value):
                assert element.proto.allow_html, (name, element.value[:60])


# --------------------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------------------


def test_duplicate_removal_is_off_by_default_and_the_time_slider_steps_by_one_minute():
    app = load_demo(fresh_app())
    box = next(
        c for c in app.sidebar.checkbox if c.key == "opt_duplicate" or "duplicate" in c.label
    )
    assert box.value is False  # silently removing rows could hide a scripted attack
    slider = next(s for s in app.sidebar.slider if s.label == "Time range (UTC)")
    assert slider.step == 60_000_000  # microseconds: exactly one minute, as the README says


def test_a_single_event_on_an_exact_minute_gets_a_one_minute_slider_range():
    one = HEADER + "2026-03-02T10:00:00Z,192.0.2.1,solo,login,success,h,m\n"
    app = page("explorer", one)
    low, high = next(s for s in app.sidebar.slider if s.label == "Time range (UTC)").value
    assert (high - low).total_seconds() == 60 and low.minute == 0 and low.second == 0


def test_time_filter_end_minute_is_included_to_the_last_microsecond_but_not_beyond():
    from datetime import datetime

    rows = "".join(
        f"2026-03-02T{stamp},192.0.2.{i + 1},user{i},access,success,h,m\n"
        for i, stamp in enumerate(["10:00:00Z", "10:05:00Z", "10:05:59Z", "10:06:00Z", "10:07:00Z"])
    )
    app = page("explorer", HEADER + rows)
    slider = next(s for s in app.sidebar.slider if s.label == "Time range (UTC)")
    slider.set_range(datetime(2026, 3, 2, 10, 0), datetime(2026, 3, 2, 10, 5)).run()
    shown = [str(t) for t in app.dataframe[0].value["Time (UTC)"]]
    # 10:05:59 is inside the selected "10:05" minute, 10:06:00 is not
    assert shown == ["2026-03-02 10:00:00", "2026-03-02 10:05:00", "2026-03-02 10:05:59"]


@pytest.mark.parametrize(("distinct", "caption"), [(2000, False), (2001, True)])
def test_filter_pick_list_caption_appears_only_above_2000_distinct_values(distinct, caption):
    lines = [HEADER.rstrip("\n")]
    for i in range(distinct):
        lines.append(
            f"2026-03-02T10:{i // 60 % 60:02d}:{i % 60:02d}Z,"
            f"10.{i // 250}.{i % 250}.1,u{i},login,success,h,m"
        )
    app = page("explorer", "\n".join(lines) + "\n")
    assert any("most frequent values" in c.value for c in app.sidebar.caption) is caption


def test_settings_bounds_match_what_the_detection_config_accepts():
    app = load_demo(fresh_app())
    controls = {n.key.removeprefix("cfg_"): n for n in app.sidebar.number_input}
    assert len(controls) == 7
    for name, control in controls.items():
        is_threshold = name.endswith("threshold")
        assert (control.min, control.max, control.step) == (
            (2.0 if is_threshold else 1.0),
            (500.0 if is_threshold else 1440.0),
            1.0,
        )
        DetectionConfig(**{name: int(control.min)})  # the smallest offered value is valid
        with pytest.raises(ValueError):
            DetectionConfig(**{name: int(control.min) - 1})  # one below it would be refused


# --------------------------------------------------------------------------------------
# Components, state and tables
# --------------------------------------------------------------------------------------


def test_severity_labels_are_numbered_one_to_four_with_a_colour_marker():
    assert [severity_label(s) for s in SEVERITIES] == [
        f"{i} - {s.capitalize()} {SEVERITY_EMOJI[s]}" for i, s in enumerate(SEVERITIES, start=1)
    ]
    assert severity_label("low").startswith("1 - Low") and severity_label("critical").startswith(
        "4 - Critical"
    )


def test_welcome_steps_are_numbered_from_one():
    text = " ".join(m.value for m in welcome_app().markdown)
    for number, start in ((1, "Load the demo data"), (4, "Explore alerts")):
        assert f"<span class='ll-step'>{number}.</span> {start}" in text


def welcome_app():
    from streamlit.testing.v1 import AppTest

    return AppTest.from_file(APP, default_timeout=TIMEOUT).run()


def test_a_refused_file_lists_at_most_four_problems():
    bad = "".join(
        line + "\n"
        for line in (
            "not-a-time,192.0.2.1,a,login,success,h,m",  # timestamp
            "2026-03-02T10:00:00Z,999.9.9.9,a,login,success,h,m",  # source_ip
            "2026-03-02T10:00:00Z,192.0.2.1,,login,success,h,m",  # username missing
            "2026-03-02T10:00:00Z,192.0.2.1,a,teleport,success,h,m",  # event_type
            "2026-03-02T10:00:00Z,192.0.2.1,a,login,maybe,h,m",  # outcome
            f"2026-03-02T10:00:00Z,192.0.2.1,{'u' * 300},login,success,h,m",  # username too long
        )
    )
    dataset = build_dataset("f.csv", (HEADER + bad).encode())
    assert dataset.parse.rows_accepted == 0 and dataset.parse.rows_rejected == 6
    message = state._no_valid_rows_message("f.csv", dataset)
    assert "none of its 6 rows were valid" in message
    assert message.split("Most common problems - ")[1].count(" x ") == 4


def test_event_table_without_alert_ids_has_no_alerts_column_by_default():
    events = parse_csv(BENIGN).events  # a plain parser result has no alert_ids column
    assert "Alerts" not in tables.event_table(events).columns
    assert "alert_ids" not in events.columns


def test_session_scope_is_immutable():
    assert dataclasses.is_dataclass(state.Scope) and state.Scope.__dataclass_params__.frozen


# --------------------------------------------------------------------------------------
# Remaining UI survivors that were behaviour, not decoration
# --------------------------------------------------------------------------------------


def test_explorer_table_links_each_event_to_its_alert_ids():
    app = view_app("explorer")
    next(t for t in app.sidebar.text_input if t.label == "Search").set_value("priya.raman").run()
    table = app.dataframe[0].value
    assert "Alerts" in table.columns
    assert (table["Alerts"] == "ALR-0010").sum() == 6  # the six denials that form the alert
    assert set(table["Alerts"]) == {"", "ALR-0010"}  # her ordinary events belong to no alert


def test_evidence_table_lists_every_alert_each_event_supports():
    app = view_app("alerts")
    next(s for s in app.selectbox if s.key == "inspect_alert").select("ALR-0009").run()
    evidence = app.dataframe[1].value
    assert "Alerts" in evidence.columns and len(evidence) == 17
    failures = evidence[evidence["Outcome"] == "failure"]["Alerts"]
    assert set(failures) == {
        "ALR-0007, ALR-0008, ALR-0009"
    }  # supports the IP, account and LL-003 alerts
    assert list(evidence[evidence["Outcome"] == "success"]["Alerts"]) == ["ALR-0009"]


def test_the_welcome_page_renders_its_html_and_starts_with_everything_collapsed():
    app = welcome_app()
    steps = [m for m in app.markdown if "<span class='ll-step'>" in m.value]
    assert len(steps) == 1 and steps[0].proto.allow_html
    assert all(not e.proto.expanded for e in app.expander)
    loaded = load_demo(fresh_app())
    assert all(not e.proto.expanded for e in loaded.expander)  # incl. "Detection settings"
