"""Tests added after mutation testing showed behaviours that no earlier test pinned down.

Each test names the gap it closes. They check exact values (boundaries, wording, output shape),
because a check that only compares two quantities computed the same way cannot notice both being
wrong in the same way.
"""

from __future__ import annotations

import dataclasses

import pandas as pd
import pytest
from conftest import at, build_events, fail, ok

from loglens.detection import DetectionConfig, run_detections
from loglens.filters import EventFilter, apply_event_filter
from loglens.metrics import OverviewMetrics, top_source_ips
from loglens.parser import ISSUE_COLUMNS, LogValidationError, parse_csv
from loglens.pipeline import annotate_events, build_dataset
from loglens.reporting import build_summary

HEADER = "timestamp,source_ip,username,event_type,outcome,host,message\n"


def row(
    user="alice",
    host="h",
    message="m",
    ts="2026-03-02T10:00:00Z",
    ip="192.0.2.1",
    outcome="success",
):
    return f"{ts},{ip},{user},login,{outcome},{host},{message}\n"


# --------------------------------------------------------------------------------------
# Parser: boundaries and exact output shape
# --------------------------------------------------------------------------------------


def test_username_and_host_length_limit_is_exactly_256():
    result = parse_csv(
        HEADER
        + row(user="u" * 256, host="h" * 256)  # at the limit: accepted
        + row(user="v" * 257, ts="2026-03-02T10:00:01Z")  # one over: rejected
        + row(host="h" * 257, ts="2026-03-02T10:00:02Z")  # one over: rejected
    )
    assert result.rows_accepted == 1 and result.rows_rejected == 2
    assert sorted(result.issues["column"]) == ["host", "username"]


def test_message_truncation_limit_is_exactly_2000():
    result = parse_csv(
        HEADER + row(message="a" * 2000) + row(message="b" * 2001, ts="2026-03-02T10:00:01Z")
    )
    assert list(result.events["message"].str.len()) == [2000, 2000]
    assert result.truncated_messages == 1  # only the 2001-character one was cut


def test_parser_output_has_exactly_the_documented_columns_and_a_clean_index():
    result = parse_csv(HEADER + row() + row(ts="not-a-time"))
    assert list(result.events.columns) == [
        "event_id", "timestamp", "source_ip", "username", "event_type", "outcome",
        "host", "message", "source_row",
    ]  # fmt: skip
    assert list(result.issues.columns) == ISSUE_COLUMNS
    assert isinstance(result.events.index, pd.RangeIndex)
    assert isinstance(result.issues.index, pd.RangeIndex)
    assert list(result.rejection_summary().columns) == ["column", "reason", "rows"]
    assert isinstance(result.rejection_summary().index, pd.RangeIndex)


def test_warning_wording_is_singular_for_one_and_plural_for_more():
    naive_one = parse_csv(HEADER + row(ts="2026-03-02T10:00:00", user="a") + row(user="b"))
    assert "Assumed UTC for 1 timestamp with no UTC offset." in naive_one.warnings()
    naive_two = parse_csv(
        HEADER + row(ts="2026-03-02T10:00:00", user="a") + row(ts="2026-03-02T10:00:01", user="b")
    )
    assert "Assumed UTC for 2 timestamps with no UTC offset." in naive_two.warnings()

    one_dupe = parse_csv(HEADER + row() + row(), drop_duplicates=True)
    assert one_dupe.warnings() == ["Removed 1 exact duplicate row (identical in every field)."]
    two_dupes = parse_csv(HEADER + row() + row() + row(), drop_duplicates=True)
    assert two_dupes.warnings() == ["Removed 2 exact duplicate rows (identical in every field)."]

    kept_one = parse_csv(HEADER + row() + row())
    assert kept_one.warnings() == [
        "Kept 1 exact duplicate row (identical in every field). It counts toward the detections. "
        "If it is a repeated log line rather than a repeated event, switch on the "
        "'Remove exact duplicate rows' option."
    ]
    kept_two = parse_csv(HEADER + row() + row() + row())
    assert kept_two.warnings() == [
        "Kept 2 exact duplicate rows (identical in every field). They count toward the "
        "detections. If they are repeated log lines rather than repeated events, switch on the "
        "'Remove exact duplicate rows' option."
    ]

    assert "Skipped 1 blank line." in parse_csv(HEADER + row() + "\n").warnings()
    assert "Skipped 2 blank lines." in parse_csv(HEADER + row() + "\n\n").warnings()


def test_ignored_column_warning_lists_at_most_eight_names_cut_at_thirty_characters():
    extras = [f"{chr(97 + i)}" * 40 for i in range(10)]  # ten 40-character column names
    text = (
        "timestamp,source_ip,username,event_type,outcome," + ",".join(extras) + "\n"
        "2026-03-02T10:00:00Z,192.0.2.1,a,login,success," + ",".join("x" * 10) + "\n"
    )
    warning = next(w for w in parse_csv(text).warnings() if "Unrecognised columns" in w)
    assert warning.count("'") == 16  # eight quoted names
    assert "'" + "a" * 30 + "'" in warning and "a" * 31 not in warning
    assert "'" + "h" * 30 + "'" in warning  # the 8th column
    assert "i" * 30 not in warning  # the 9th is not listed


def test_missing_column_error_echoes_at_most_ten_header_names_cut_at_forty_characters():
    names = [f"{chr(97 + i)}" * 50 for i in range(15)]
    with pytest.raises(LogValidationError) as excinfo:
        parse_csv(",".join(names) + "\n" + ",".join("1" * 15) + "\n")
    message = str(excinfo.value)
    assert "'" + "a" * 40 + "'" in message and "a" * 41 not in message
    assert "'" + "j" * 40 + "'" in message  # the 10th name
    assert "k" * 40 not in message  # the 11th is not listed


def test_wrong_delimiter_hint_only_for_a_single_column_header():
    with pytest.raises(LogValidationError) as single:
        parse_csv("timestamp;source_ip;username\n1;2;3\n")
    assert "different delimiter" in str(single.value)
    with pytest.raises(LogValidationError) as several:
        parse_csv("timestamp,source;ip,username\n1,2,3\n")  # ';' inside one of several columns
    assert "different delimiter" not in str(several.value)


def test_size_limit_message_reports_megabytes():
    data = (HEADER + row()).encode() + b"#" * (2 * 1024 * 1024)
    with pytest.raises(LogValidationError, match=r"The file is 2\.0 MB; the limit is 1 MB"):
        parse_csv(data, max_bytes=1024 * 1024)


def test_csv_reader_error_message_names_the_row():
    import csv

    previous = csv.field_size_limit(300)
    try:
        with pytest.raises(LogValidationError, match="near row 2:"):
            parse_csv(HEADER + row(message="x" * 500))
    finally:
        csv.field_size_limit(previous)


# --------------------------------------------------------------------------------------
# Detection: several bursts for one account
# --------------------------------------------------------------------------------------


def test_three_bursts_for_one_account_each_followed_by_a_success_make_three_alerts():
    rows = []
    for burst in range(3):
        base = burst * 120  # minutes: bursts two hours apart
        rows += [fail(at(minutes=base + m), "203.0.113.5", "erin") for m in range(5)]
        rows.append(ok(at(minutes=base + 8), "203.0.113.5", "erin"))
    alerts = [a for a in run_detections(build_events(rows)) if a.rule_id == "LL-003"]
    assert len(alerts) == 3
    for burst, alert in enumerate(alerts):
        assert alert.event_count == 6  # exactly its own five failures + its own success
        assert alert.timestamp == at(minutes=burst * 120)
        assert alert.end_timestamp == at(minutes=burst * 120 + 8)


# --------------------------------------------------------------------------------------
# Filters: descriptions, literal search, output shape
# --------------------------------------------------------------------------------------


def test_filter_description_for_open_ended_time_ranges():
    start_only = EventFilter(start=pd.Timestamp("2026-03-02T09:30Z")).describe()
    end_only = EventFilter(end=pd.Timestamp("2026-03-02T18:45Z")).describe()
    assert start_only == ["Time (UTC): 2026-03-02 09:30 to end"]
    assert end_only == ["Time (UTC): start to 2026-03-02 18:45"]


def test_filter_description_shortens_long_selections_and_search_text():
    users = tuple(f"user{i}" for i in range(6))
    text = EventFilter(usernames=users).describe()[0]
    assert text == "Username: user0, user1, user2, user3 +2 more"
    assert EventFilter(usernames=users[:4]).describe()[0] == "Username: user0, user1, user2, user3"
    long_search = EventFilter(search="x" * 100).describe()[0]
    assert long_search == "Search: " + "x" * 60


def test_search_is_a_literal_substring_never_a_pattern():
    events = build_events([fail(at(seconds=i), "203.0.113.5", "alice") for i in range(3)])
    assert len(apply_event_filter(events, EventFilter(search="alice"))) == 3
    for pattern in (".*", "a.i", "(", "[", "a|b", "^alice$", "\\"):
        assert apply_event_filter(events, EventFilter(search=pattern)).empty, pattern


def test_filtered_frame_keeps_the_same_columns_and_a_fresh_index():
    events = annotate_events(build_events([fail(at(seconds=i)) for i in range(5)]), [])
    filtered = apply_event_filter(events, EventFilter(search="EVT-000003"))
    assert list(filtered.columns) == list(events.columns)
    assert isinstance(filtered.index, pd.RangeIndex) and list(filtered.index) == [0]


# --------------------------------------------------------------------------------------
# Metrics and summary: exact values
# --------------------------------------------------------------------------------------


def test_top_source_ips_exact_counts_ordering_columns_and_default_limit():
    rows = [
        fail(at(seconds=0), "203.0.113.2"), fail(at(seconds=1), "203.0.113.2"),
        ok(at(seconds=2), "203.0.113.2"),
        ok(at(seconds=3), "203.0.113.1"), ok(at(seconds=4), "203.0.113.1"),
        ok(at(seconds=5), "203.0.113.1"),
    ]  # fmt: skip
    top = top_source_ips(build_events(rows))
    assert list(top.columns) == ["source_ip", "total", "success", "failure", "denied"]
    assert isinstance(top.index, pd.RangeIndex)
    # equal totals (3 and 3) are ordered by IP; a missing outcome is exactly 0, not 1
    assert top.to_dict("records") == [
        {"source_ip": "203.0.113.1", "total": 3, "success": 3, "failure": 0, "denied": 0},
        {"source_ip": "203.0.113.2", "total": 3, "success": 1, "failure": 2, "denied": 0},
    ]
    many = build_events([ok(at(seconds=i), f"203.0.113.{i + 1}") for i in range(15)])
    assert len(top_source_ips(many)) == 10  # default limit
    assert len(top_source_ips(many, 3)) == 3


def test_summary_shows_five_accounts_and_ips_per_alert_and_pluralises_duplicates():
    spray = [fail(at(seconds=10 * i), "203.0.113.5", f"user{i}") for i in range(8)]
    events = build_events(spray)
    alerts = run_detections(events)
    dataset = build_dataset("s.csv", (HEADER + row() + row()).encode(), drop_duplicates=True)
    assert dataset.parse.duplicates_removed == 1
    text = build_summary(
        dataset, annotate_events(events, alerts), alerts, EventFilter(), DetectionConfig()
    )
    assert "1 duplicate removed" in text
    # five names, and the summary says how many it left out
    assert "    accounts: user0, user1, user2, user3, user4 +3 more\n" in text
    two = build_dataset("s.csv", (HEADER + row() + row() + row()).encode(), drop_duplicates=True)
    assert two.parse.duplicates_removed == 2
    again = build_summary(
        two, annotate_events(events, alerts), alerts, EventFilter(), DetectionConfig()
    )
    assert "2 duplicates removed" in again
    kept = build_dataset("s.csv", (HEADER + row() + row() + row()).encode())
    assert kept.parse.duplicates_removed == 0 and kept.parse.duplicate_rows == 2
    assert "2 duplicates kept" in build_summary(
        kept, annotate_events(events, alerts), alerts, EventFilter(), DetectionConfig()
    )


@pytest.mark.parametrize("cls", [EventFilter, OverviewMetrics, DetectionConfig])
def test_value_objects_are_immutable(cls):
    assert dataclasses.is_dataclass(cls) and cls.__dataclass_params__.frozen


# --------------------------------------------------------------------------------------
# Found by probing: RFC 3339 lower-case 't'/'z' and Unicode-equivalent account names
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling", ["2026-03-02T10:00:00z", "2026-03-02t10:00:00Z", "2026-03-02t10:00:00z"]
)
def test_rfc3339_lowercase_t_and_z_are_accepted(spelling):
    result = parse_csv(HEADER + row(ts=spelling))
    assert result.rows_accepted == 1 and result.naive_timestamp_rows == 0
    assert result.events["timestamp"].iloc[0] == pd.Timestamp("2026-03-02T10:00:00Z")


def test_a_rejected_timestamp_is_still_quoted_as_written():
    result = parse_csv(HEADER + row(ts="nope-z"))
    assert result.issues["value"].iloc[0] == "nope-z"  # not the upper-cased working copy


def test_composed_and_decomposed_spellings_of_a_name_are_one_account():
    composed = "zo" + chr(0xE9)  # one code point for the accented letter
    decomposed = "zoe" + chr(0x301)  # letter + combining accent: same text on screen
    lines = [
        row(user=composed.upper(), ts=f"2026-03-02T10:00:0{i}Z", outcome="failure")
        for i in range(2)
    ]
    lines += [
        row(user=decomposed, ts=f"2026-03-02T10:00:0{i}Z", outcome="failure") for i in range(2, 5)
    ]
    result = parse_csv(HEADER + "".join(lines))
    assert result.events["username"].nunique() == 1
    assert [a.rule_id for a in run_detections(result.events)].count("LL-002") == 1


# --------------------------------------------------------------------------------------
# Round-2 survivors: dataset labelling, summary contents, small boundaries
# --------------------------------------------------------------------------------------


def test_uploaded_data_is_never_labelled_as_demo_by_default():
    from loglens.pipeline import Dataset, load_demo_dataset

    upload = build_dataset("mine.csv", (HEADER + row()).encode())
    assert upload.is_demo is False and upload.drop_duplicates is False
    assert len(upload.dataset_id) == 12
    demo = load_demo_dataset()
    assert demo.is_demo is True and demo.drop_duplicates is False
    assert dataclasses.is_dataclass(Dataset) and Dataset.__dataclass_params__.frozen


def test_dataset_id_depends_on_the_duplicate_setting_and_the_content():
    data = (HEADER + row()).encode()
    keep = build_dataset("a.csv", data, drop_duplicates=False).dataset_id
    drop = build_dataset("a.csv", data, drop_duplicates=True).dataset_id
    assert keep != drop
    assert build_dataset("b.csv", data + b" ", drop_duplicates=True).dataset_id != drop
    assert build_dataset("renamed.csv", data, drop_duplicates=True).dataset_id == drop


def test_delimiter_hint_requires_a_single_column_header():
    with pytest.raises(LogValidationError) as excinfo:
        parse_csv("time;stamp,source_ip,username\n1,2,3\n")  # first cell contains ';' but 3 columns
    assert "different delimiter" not in str(excinfo.value)


def test_filter_description_shortens_at_exactly_the_fifth_value():
    five = EventFilter(usernames=tuple("abcde")).describe()[0]
    assert five == "Username: a, b, c, d +1 more"
    assert EventFilter(usernames=tuple("abcd")).describe()[0] == "Username: a, b, c, d"


def test_empty_alert_frame_has_utc_for_both_time_columns():
    from loglens.detection import alerts_to_frame

    frame = alerts_to_frame([])
    assert str(frame["timestamp"].dt.tz) == "UTC" and str(frame["end_timestamp"].dt.tz) == "UTC"


def _demo_summary():
    from loglens.pipeline import load_demo_dataset

    dataset = load_demo_dataset()
    alerts = run_detections(dataset.events)
    events = annotate_events(dataset.events, alerts)
    text = build_summary(dataset, events, alerts, EventFilter(), DetectionConfig())
    return text, alerts


def test_summary_counts_alerts_per_rule_exactly():
    text, _ = _demo_summary()
    section = text.split("ALERTS BY RULE\n--------------\n")[1].split("\n\n")[0].splitlines()
    counts = {line.split()[0]: int(line.split()[-1]) for line in section}
    assert counts == {"LL-001": 3, "LL-002": 4, "LL-003": 2, "LL-004": 1}


def test_summary_layout_title_width_top_ips_and_source_ip_cap():
    text, alerts = _demo_summary()
    lines = text.splitlines()
    assert lines[0] == "LOGLENS SECURITY ANALYSIS SUMMARY" and lines[1] == "=" * len(lines[0])
    assert max(len(line) for line in lines) <= 96  # fits a 96-column terminal
    top = text.split("TOP SOURCE IPS (by event count)\n")[1].split("\n\n")[0].splitlines()
    assert len(top[1:]) == 5  # heading underline + exactly five IPs
    s3 = next(a for a in alerts if len(a.source_ips) == 7)  # the 7-IP distributed attack
    shown = [
        line for line in lines if line.startswith("    source IPs: ") and "198.51.100.21" in line
    ]
    assert shown and shown[0].count(",") == 4  # five addresses, never all seven
    assert "198.51.100.27" not in shown[0] and len(s3.source_ips) == 7


@pytest.mark.parametrize(
    ("count", "tail"), [(25, None), (26, "... and 1 more; see the alerts CSV export.")]
)
def test_summary_alert_list_boundary_at_25(count, tail):
    from conftest import deny

    rows = []
    for account in range(count):
        rows += [
            deny(at(minutes=account * 60, seconds=i), user=f"user{account:02d}") for i in range(4)
        ]
    events = build_events(rows)
    alerts = run_detections(events)
    dataset = build_dataset("x.csv", (HEADER + row()).encode())
    text = build_summary(
        dataset, annotate_events(events, alerts), alerts, EventFilter(), DetectionConfig()
    )
    assert len(alerts) == count and text.count("ALR-") == 25
    assert ("more; see the alerts CSV export." in text) == (tail is not None)
    if tail:
        assert tail in text


def test_csv_reader_error_in_the_header_row_is_reported_as_row_one():
    import csv

    previous = csv.field_size_limit(300)
    try:
        with pytest.raises(LogValidationError, match="near row 1:"):
            parse_csv("timestamp," + "h" * 500 + ",username\n2026-03-02T10:00:00Z,192.0.2.1,a\n")
    finally:
        csv.field_size_limit(previous)


def test_summary_key_numbers_line_up_in_one_column():
    text, _ = _demo_summary()
    block = text.split("KEY NUMBERS\n-----------\n")[1].split("\n\n")[0].splitlines()
    assert len(block) == 5
    starts = {len(line) - len(line.split()[-1]) for line in block}
    assert len(starts) == 1, block
