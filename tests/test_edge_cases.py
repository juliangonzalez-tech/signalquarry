"""Edge cases found by the QA audit: empty states, tiny/huge inputs and rarely-run branches."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

import pytest
from conftest import at, build_events, deny, fail
from streamlit.testing.v1 import AppTest

from loglens.detection import DetectionConfig, run_detections
from loglens.filters import EventFilter
from loglens.parser import LogValidationError, parse_csv
from loglens.pipeline import annotate_events, build_dataset
from loglens.reporting import build_summary, events_to_csv

APP = str(Path(__file__).resolve().parent.parent / "app.py")
TIMEOUT = 180
HEADER = "timestamp,source_ip,username,event_type,outcome,host,message\n"


# --------------------------------------------------------------------------------------
# Pure-Python edge cases
# --------------------------------------------------------------------------------------


def test_sub_second_timestamps_survive_an_export_and_reimport():
    result = parse_csv(
        HEADER
        + "2026-03-02T10:00:00.250Z,192.0.2.1,a,login,failure,,\n"
        + "2026-03-02T10:00:01Z,192.0.2.1,a,login,failure,,\n"
    )
    exported = events_to_csv(result.events).decode()
    assert "2026-03-02T10:00:00.250000Z" in exported  # fractional seconds kept, never rounded
    again = parse_csv(exported)
    assert list(again.events["timestamp"]) == list(result.events["timestamp"])


def test_whole_second_exports_have_no_fractional_part():
    result = parse_csv(HEADER + "2026-03-02T10:00:00Z,192.0.2.1,a,login,failure,,\n")
    assert "2026-03-02T10:00:00Z," in events_to_csv(result.events).decode()


def test_alert_durations_are_formatted_for_seconds_minutes_and_hours():
    # 100 failures, one per minute, from one IP: a single 1h 39m cluster.
    sustained = [fail(at(minutes=i), "203.0.113.5", "alice") for i in range(100)]
    ll001 = [a for a in run_detections(build_events(sustained)) if a.rule_id == "LL-001"]
    assert len(ll001) == 1 and "within 1h 39m" in ll001[0].summary
    fast = [fail(at(seconds=i), "203.0.113.5", "alice") for i in range(6)]
    assert (
        "within 5s"
        in next(a for a in run_detections(build_events(fast)) if a.rule_id == "LL-001").summary
    )
    minutes = [fail(at(seconds=45 * i), "203.0.113.5", "alice") for i in range(6)]
    assert (
        "within 3m 45s"
        in next(a for a in run_detections(build_events(minutes)) if a.rule_id == "LL-001").summary
    )


def test_detection_accepts_a_frame_with_timezone_naive_timestamps():
    events = build_events([fail(at(seconds=10 * i)) for i in range(6)])
    naive = events.assign(timestamp=events["timestamp"].dt.tz_localize(None))
    aware_alerts = run_detections(events)
    naive_alerts = run_detections(naive)
    assert [(a.rule_id, a.event_ids) for a in naive_alerts] == [
        (a.rule_id, a.event_ids) for a in aware_alerts
    ]


def test_summary_lists_the_first_25_alerts_and_counts_the_rest():
    rows = []
    for account in range(30):  # 30 accounts, each with 4 denials: 30 LL-004 alerts
        rows += [
            deny(at(minutes=account * 60, seconds=i), user=f"user{account:02d}") for i in range(4)
        ]
    events = build_events(rows)
    alerts = run_detections(events)
    assert len(alerts) == 30
    dataset = build_dataset(
        "many.csv",
        b"timestamp,source_ip,username,event_type,outcome\n"
        b"2026-03-02T10:00:00Z,192.0.2.1,a,login,success\n",
    )
    text = build_summary(
        dataset, annotate_events(events, alerts), alerts, EventFilter(), DetectionConfig()
    )
    assert text.count("ALR-") == 25  # only 25 alert entries are written out
    assert "... and 5 more; see the alerts CSV export." in text


def test_a_csv_reader_error_is_reported_as_a_clear_file_error(monkeypatch):
    previous = csv.field_size_limit(500)
    try:
        with pytest.raises(LogValidationError, match="could not be read as CSV"):
            parse_csv(
                HEADER + "2026-03-02T10:00:00Z,192.0.2.1,a,login,failure,h," + "x" * 800 + "\n"
            )
    finally:
        csv.field_size_limit(previous)


def test_an_empty_rejection_summary_is_an_empty_frame():
    result = parse_csv(HEADER + "2026-03-02T10:00:00Z,192.0.2.1,a,login,failure,,\n")
    assert result.rejection_summary().empty
    assert list(result.rejection_summary().columns) == ["column", "reason", "rows"]


# --------------------------------------------------------------------------------------
# Streamlit pages: empty, tiny, huge and dirty data
# --------------------------------------------------------------------------------------


def _render_csv(page: str, csv_text: str) -> None:
    """Script executed by AppTest: install ``csv_text`` as an uploaded file, render ``page``."""
    import importlib

    import streamlit as st

    from loglens.pipeline import build_dataset
    from loglens.ui import sidebar, state

    state.init_state()
    if st.session_state[state.DATASET] is None:
        state._install(build_dataset("edge.csv", csv_text.encode()))
    sidebar.render()
    importlib.import_module(f"loglens.ui.views.{page}").render()


def page(name: str, csv_text: str) -> AppTest:
    app = AppTest.from_function(_render_csv, args=(name, csv_text), default_timeout=TIMEOUT)
    app.run()
    assert not app.exception
    return app


BENIGN = HEADER + "".join(
    f"2026-03-02T10:0{i}:00Z,192.0.2.{i + 1},user{i},login,success,h,ok\n" for i in range(5)
)
FIVE_FAILURES = HEADER + "".join(
    f"2026-03-02T10:0{i}:00Z,203.0.113.5,alice,login,failure,h,bad\n" for i in range(5)
)


def test_alerts_page_says_plainly_when_no_rule_fired():
    app = page("alerts", BENIGN)
    assert any("No detection rule fired" in s.value for s in app.success)
    assert not app.dataframe  # no empty table is drawn


def test_overview_with_no_alerts_shows_zero_cards_and_empty_alert_charts():
    app = page("overview", BENIGN)
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Flagged event clusters"] == "0" and metrics["Total events"] == "5"
    cards = " ".join(m.value for m in app.markdown)  # severity cards are HTML inside markdown
    for severity in ("critical", "high", "medium", "low"):
        assert f"{severity} alerts" in cards


def test_alerts_page_distinguishes_filtered_out_from_none_at_all():
    app = page("alerts", FIVE_FAILURES)
    next(t for t in app.sidebar.text_input if t.label == "Search").set_value("no-such-thing").run()
    assert any("No alerts have supporting events" in i.value for i in app.info)


def test_alerts_page_alert_filters_that_match_nothing_say_so():
    app = page("alerts", FIVE_FAILURES)  # two MEDIUM alerts
    next(m for m in app.multiselect if m.key == "alerts_severity").set_value(["critical"]).run()
    assert not app.exception
    assert any("No alerts match these alert filters" in i.value for i in app.info)
    assert not app.dataframe


@pytest.mark.parametrize("name", ["overview", "alerts", "explorer", "reports", "guide"])
def test_a_file_with_a_single_event_works_on_every_page(name):
    one = HEADER + "2026-03-02T10:00:00Z,192.0.2.1,solo,login,success,h,only event\n"
    app = page(name, one)  # the time slider has min == max here
    if name == "overview":
        assert {m.label: m.value for m in app.metric}["Total events"] == "1"


def test_explorer_caps_the_table_at_20000_rows_but_says_so():
    lines = [HEADER.rstrip("\n")]
    for i in range(20_050):
        stamp = f"2026-03-02T{i // 3600 % 24:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z"
        lines.append(f"{stamp},192.0.2.{i % 250 + 1},user{i % 90},access,success,h,m{i}")
    app = page("explorer", "\n".join(lines) + "\n")
    assert len(app.dataframe[0].value) == 20_000
    assert any("Showing the first 20,000 of 20,050 events" in w.value for w in app.warning)
    assert {m.label: m.value for m in app.metric}["Events shown"] == "20,050"


def test_overview_explains_a_dirty_file_without_rendering_its_markup():
    dirty = (
        "timestamp,source_ip,username,event_type,outcome,<b>sneaky</b>\n"
        "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,x\n"
        "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,x\n"  # duplicate
        "not-a-time,192.0.2.1,bob,login,success,x\n"  # rejected
    )
    app = page("overview", dirty)
    html = " ".join(e.value for e in app.get("html"))
    assert "Rejected 1 of 3 rows" in html and "Kept 1 exact duplicate row" in html
    assert "&lt;b&gt;sneaky&lt;/b&gt;" in html and "<b>sneaky</b>" not in html
    assert len(app.dataframe) >= 2  # rejection summary + first rejected rows


def test_the_main_app_shows_a_refused_upload_message_as_inert_text():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT)
    app.session_state["load_error"] = "Could not load <script>alert(1)</script>.csv: nope"
    app.run()
    assert not app.exception
    boxes = [e.value for e in app.get("html") if 'role="alert"' in e.value]
    assert len(boxes) == 1
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.csv" in boxes[0] and "<script>" not in boxes[0]


def test_the_time_filter_slider_handles_a_single_timestamp_dataset():
    one_minute = HEADER + "".join(
        f"2026-03-02T10:00:{i:02d}Z,192.0.2.{i + 1},u{i},login,success,h,m\n" for i in range(5)
    )
    app = page("explorer", one_minute)
    slider = next(s for s in app.sidebar.slider if s.label == "Time range (UTC)")
    low, high = slider.value
    assert isinstance(low, datetime) and (high - low).total_seconds() >= 60
    assert len(app.dataframe[0].value) == 5


def test_every_page_survives_a_dataset_where_all_events_share_one_timestamp():
    same = HEADER + "".join(
        f"2026-03-02T10:00:00Z,192.0.2.1,u,login,failure,h,m{i}\n" for i in range(6)
    )
    for name in ("overview", "alerts", "explorer", "reports"):
        page(name, same)
    app = page("alerts", same)
    assert len(app.dataframe[0].value) == 2  # LL-001 and LL-002: same-second failures still count


SCRIPTED_GUESSING = HEADER + "2026-03-02T10:00:00Z,203.0.113.5,alice,login,failure,h,bad\n" * 6


def test_alert_inspector_says_when_its_evidence_contains_exact_duplicates():
    app = page("alerts", SCRIPTED_GUESSING)  # six identical rows: both rules fire on all of them
    assert len(app.dataframe[0].value) == 2
    notices = [i.value for i in app.info if "exact duplicates" in i.value]
    assert len(notices) == 1
    assert notices[0].startswith("5 of these rows are exact duplicates of another row")


def test_alert_inspector_stays_quiet_when_the_evidence_has_no_duplicates():
    app = page("alerts", FIVE_FAILURES)
    assert not [i for i in app.info if "exact duplicates" in i.value]


def test_overview_reports_kept_duplicates_instead_of_hiding_them():
    app = page("overview", SCRIPTED_GUESSING)
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Duplicates kept"] == "5" and "Duplicates removed" not in metrics
    assert metrics["Events accepted"] == "6"  # nothing was thrown away


MIDNIGHT_BURST = (
    HEADER
    + "".join(
        f"2026-03-02T23:5{i}:00Z,203.0.113.5,alice,login,failure,h,bad\n" for i in (6, 7, 8, 9)
    )
    + "2026-03-03T00:01:00Z,203.0.113.5,alice,login,failure,h,bad\n"
)


def test_inspector_time_window_shows_the_end_date_when_an_alert_crosses_midnight():
    app = page("alerts", MIDNIGHT_BURST)
    windows = [t.value for t in app.text if t.value.startswith("Time window")]
    assert windows == ["Time window (UTC): 2026-03-02 23:56:00 to 2026-03-03 00:01:00"]
    same_day = page("alerts", FIVE_FAILURES)
    assert [t.value for t in same_day.text if t.value.startswith("Time window")] == [
        "Time window (UTC): 2026-03-02 10:00:00 to 10:04:00"
    ]


def test_alert_table_puts_the_explanation_before_the_wide_columns():
    app = page("alerts", FIVE_FAILURES)
    columns = list(app.dataframe[0].value.columns)
    assert columns.index("Why it was flagged") < columns.index("Account")
    assert set(app.dataframe[0].value["Rule"]) == {"LL-001", "LL-002"}


def test_evidence_table_shows_alert_links_before_the_free_text_columns():
    app = page("alerts", FIVE_FAILURES)
    columns = list(app.dataframe[1].value.columns)
    assert columns.index("Alerts") < columns.index("Host") < columns.index("Message")
