"""CSV ingestion: valid files, file-level errors, row-level rejection, time handling, duplicates."""

from __future__ import annotations

import random

import pandas as pd
import pytest

from loglens.parser import LogValidationError, parse_csv

HEADER = "timestamp,source_ip,username,event_type,outcome,host,message\n"


def csv_of(*lines: str) -> str:
    return HEADER + "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------
# Valid input
# --------------------------------------------------------------------------------------


def test_valid_csv_is_parsed_and_normalised():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:00:05Z,192.0.2.10,Alice,LOGIN,Success,vpn-1,Password auth",
            "2026-03-02T10:00:01Z,2001:DB8:0:0:0:0:0:1, bob ,access,denied,,",
        )
    )
    events = result.events
    assert list(events["event_id"]) == ["EVT-000001", "EVT-000002"]
    assert list(events["username"]) == ["bob", "alice"]  # trimmed, lower-cased, sorted by time
    assert list(events["source_ip"]) == ["2001:db8::1", "192.0.2.10"]  # IPv6 compressed
    assert list(events["event_type"]) == ["access", "login"]
    assert list(events["outcome"]) == ["denied", "success"]
    assert str(events["timestamp"].dt.tz) == "UTC"
    assert result.rows_read == 2
    assert result.rows_accepted == 2
    assert result.rows_rejected == 0
    assert len(result.warnings()) == 1  # only the out-of-order notice
    assert "chronological order" in result.warnings()[0]


def test_clean_sorted_file_produces_no_warnings():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:00:00Z,192.0.2.10,alice,login,success,vpn-1,ok",
            "2026-03-02T10:00:01Z,192.0.2.11,bob,login,failure,vpn-1,bad password",
        )
    )
    assert result.warnings() == []


def test_optional_columns_may_be_missing_entirely_or_blank():
    no_optional = parse_csv(
        "timestamp,source_ip,username,event_type,outcome\n"
        "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success\n"
    )
    assert list(no_optional.events["host"]) == [""]
    assert list(no_optional.events["message"]) == [""]

    blank = parse_csv(csv_of("2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,,"))
    assert blank.rows_accepted == 1
    assert list(blank.events["host"]) == [""]


def test_headers_are_case_and_whitespace_insensitive_and_extra_columns_are_reported():
    result = parse_csv(
        " Timestamp , Source_IP ,USERNAME,Event_Type,Outcome,Notes\n"
        "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,something\n"
    )
    assert result.rows_accepted == 1
    assert result.ignored_columns == ["Notes"]
    assert any("Notes" in warning for warning in result.warnings())


def test_outcome_aliases_are_mapped_to_canonical_values():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:00:00Z,192.0.2.1,a,login,Failed,,",
            "2026-03-02T10:00:01Z,192.0.2.1,a,access,Denial,,",
            "2026-03-02T10:00:02Z,192.0.2.1,a,login,successful,,",
        )
    )
    assert list(result.events["outcome"]) == ["failure", "denied", "success"]


def test_quoted_fields_commas_bom_and_windows_line_endings():
    text = (
        "\ufefftimestamp,source_ip,username,event_type,outcome,host,message\r\n"
        '2026-03-02T10:00:00Z,192.0.2.1,alice,login,failure,sso,"Bad password, retry"\r\n'
    )
    result = parse_csv(text.encode("utf-8"))
    assert result.rows_accepted == 1
    assert result.events["message"].iloc[0] == "Bad password, retry"


def test_blank_lines_are_skipped_and_reported():
    result = parse_csv(csv_of("2026-03-02T10:00:00Z,192.0.2.1,a,login,success,,", "", "   ,,,,,,"))
    assert result.rows_accepted == 1
    assert result.blank_lines == 2
    assert any("blank" in warning for warning in result.warnings())


# --------------------------------------------------------------------------------------
# File-level errors
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("content", [b"", b"   \n\n  ", ""])
def test_empty_file_is_rejected_with_clear_message(content):
    with pytest.raises(LogValidationError, match="empty"):
        parse_csv(content)


def test_header_without_data_rows_is_rejected():
    with pytest.raises(LogValidationError, match="no data rows"):
        parse_csv(HEADER)


def test_missing_required_columns_names_them_and_lists_what_was_found():
    with pytest.raises(LogValidationError) as excinfo:
        parse_csv("timestamp,source_ip,message\n2026-03-02T10:00:00Z,192.0.2.1,hi\n")
    message = str(excinfo.value)
    assert "username" in message
    assert "event_type" in message
    assert "outcome" in message
    assert "'message'" in message  # shows the columns that were found


def test_wrong_delimiter_gets_a_helpful_hint():
    with pytest.raises(LogValidationError, match="delimiter"):
        parse_csv("timestamp;source_ip;username;event_type;outcome\n1;2;3;4;5\n")


def test_duplicate_header_names_are_rejected():
    with pytest.raises(LogValidationError, match="more than once"):
        parse_csv("timestamp,source_ip,username,username,event_type,outcome\n1,2,3,4,5,6\n")


def test_repeated_columns_that_are_ignored_anyway_do_not_block_the_file():
    result = parse_csv(
        "timestamp,source_ip,username,event_type,outcome,notes,notes\n"
        "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,a,b\n"
    )
    assert result.rows_accepted == 1
    assert result.ignored_columns == ["notes", "notes"]


def test_ipv4_mapped_ipv6_is_the_same_address_as_plain_ipv4():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:00:00Z,::ffff:192.0.2.1,alice,login,failure,,",
            "2026-03-02T10:00:01Z,::FFFF:C000:201,alice,login,failure,,",  # hex form, same host
            "2026-03-02T10:00:02Z,192.0.2.1,alice,login,failure,,",
            "2026-03-02T10:00:03Z,2001:db8::1,alice,login,failure,,",  # genuine IPv6 is untouched
        )
    )
    assert list(result.events["source_ip"]) == [
        "192.0.2.1",
        "192.0.2.1",
        "192.0.2.1",
        "2001:db8::1",
    ]


def test_attack_spread_over_ipv4_and_mapped_forms_is_still_one_source_for_ll001():
    from loglens.detection import run_detections

    lines = []
    for i in range(6):  # six failures from one host, logged alternately in both notations
        ip = "::ffff:203.0.113.9" if i % 2 else "203.0.113.9"
        lines.append(f"2026-03-02T10:00:{i:02d}Z,{ip},u{i},login,failure,,")
    alerts = run_detections(parse_csv(csv_of(*lines)).events)
    assert [(a.rule_id, a.event_count) for a in alerts if a.rule_id == "LL-001"] == [("LL-001", 6)]


def test_long_message_is_truncated_and_counted_not_rejected():
    long_message = "x" * 5000
    result = parse_csv(
        csv_of(
            f"2026-03-02T10:00:00Z,192.0.2.1,alice,login,failure,h,{long_message}",
            "2026-03-02T10:00:01Z,192.0.2.1,alice,login,failure,h,short",
        )
    )
    assert result.rows_accepted == 2 and result.rows_rejected == 0
    assert result.truncated_messages == 1
    assert list(result.events["message"].str.len()) == [2000, 5]
    assert any("Truncated 1 message" in warning for warning in result.warnings())


def test_a_message_over_the_csv_modules_default_field_limit_does_not_reject_the_file():
    # The csv module's default limit is 131,072 characters; one huge cell used to fail the
    # whole upload instead of just being truncated.
    huge = "y" * 300_000
    result = parse_csv(
        csv_of(
            f"2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,h,{huge}",
            "2026-03-02T10:00:01Z,192.0.2.1,bob,login,success,h,ok",
        )
    )
    assert result.rows_accepted == 2 and result.truncated_messages == 1
    assert result.events["message"].str.len().max() == 2000


def test_leading_bom_in_text_input_is_ignored():
    text = chr(0xFEFF) + csv_of("2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,,")
    assert parse_csv(text).rows_accepted == 1


def test_binary_and_non_utf8_files_are_rejected():
    with pytest.raises(LogValidationError, match="binary"):
        parse_csv(b"PK\x03\x04\x00\x00\x00 not a csv")
    with pytest.raises(LogValidationError, match="UTF-8"):
        parse_csv(b"timestamp,source_ip\n\xff\xfe\xfd,1\n")


def test_utf16_files_are_named_as_such_rather_than_called_binary():
    for encoding in ("utf-16", "utf-16-be"):
        data = csv_of("2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,,").encode(encoding)
        if encoding == "utf-16-be":
            data = b"\xfe\xff" + data
        with pytest.raises(LogValidationError, match="UTF-16"):
            parse_csv(data)


def test_oversized_upload_is_rejected_before_parsing():
    payload = csv_of("2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,,").encode()
    with pytest.raises(LogValidationError, match="limit"):
        parse_csv(payload, max_bytes=len(payload) - 1)
    assert parse_csv(payload, max_bytes=len(payload)).rows_accepted == 1


def test_unbalanced_quote_swallows_the_rest_of_the_line_and_the_row_is_rejected_with_reasons():
    # The stray quote opens a field that never closes, so the row ends up without an event_type
    # or outcome. It must be rejected and explained, not crash and not be accepted.
    result = parse_csv(HEADER + '2026-03-02T10:00:00Z,192.0.2.1,"alice,login,success,,\n')
    assert (result.rows_read, result.rows_accepted, result.rows_rejected) == (1, 0, 1)
    assert sorted(result.issues["column"]) == ["event_type", "outcome"]
    assert set(result.issues["reason"]) == {"missing value"}


# --------------------------------------------------------------------------------------
# Row-level validation: reported, never silently dropped
# --------------------------------------------------------------------------------------


def test_every_row_is_accounted_for():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,,",  # row 2: ok
            "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,,",  # row 3: duplicate
            "yesterday,192.0.2.1,alice,login,success,,",  # row 4: bad timestamp
            "2026-03-02T10:00:01Z,not-an-ip,alice,login,success,,",  # row 5: bad ip
            "2026-03-02T10:00:02Z,192.0.2.1,,login,success,,",  # row 6: missing user
            "2026-03-02T10:00:03Z,192.0.2.1,alice,teleport,success,,",  # row 7: bad type
            "2026-03-02T10:00:04Z,192.0.2.1,alice,login,maybe,,",  # row 8: bad outcome
        ),
        drop_duplicates=True,
    )
    assert result.rows_read == 7
    assert result.rows_rejected == 5
    assert result.duplicates_removed == 1
    assert result.rows_accepted == 1
    assert (
        result.rows_accepted + result.rows_rejected + result.duplicates_removed == result.rows_read
    )
    assert sorted(result.issues["row"]) == [4, 5, 6, 7, 8]  # spreadsheet row numbers
    reasons = " | ".join(result.issues["reason"])
    for expected in ("ISO 8601", "IPv4 or IPv6", "missing value", "event_type", "outcome"):
        assert expected in reasons


def test_row_with_several_problems_is_one_rejected_row_with_several_issues():
    result = parse_csv(csv_of("nope,999.1.1.1,,login,success,,"))
    assert result.rows_rejected == 1
    assert len(result.issues) == 3
    assert result.rows_accepted == 0


def test_rejection_summary_groups_by_reason():
    result = parse_csv(
        csv_of(
            "bad,192.0.2.1,a,login,success,,",
            "also-bad,192.0.2.1,a,login,success,,",
            "2026-03-02T10:00:00Z,192.0.2.1,a,teleport,success,,",
        )
    )
    summary = result.rejection_summary()
    top = summary.iloc[0]
    assert top["column"] == "timestamp"
    assert top["rows"] == 2


def test_ragged_rows_are_rejected_or_padded_but_never_misaligned():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success,host,message,EXTRA,FIELDS",
            "2026-03-02T10:00:01Z,192.0.2.1,alice,login,success",  # short row: optional padded
            "2026-03-02T10:00:02Z,192.0.2.1,alice",  # short row: required fields missing
        )
    )
    assert result.rows_accepted == 1
    assert result.rows_rejected == 2
    assert "more fields" in " ".join(result.issues["reason"])


def test_free_text_is_never_echoed_in_issues():
    secret = "hunter2-" + "x" * 300
    result = parse_csv(csv_of(f"2026-03-02T10:00:00Z,192.0.2.1,{secret},login,success,,"))
    assert result.rows_rejected == 1
    assert "longer than" in result.issues["reason"].iloc[0]
    assert secret not in result.issues.to_csv()
    assert result.issues["value"].iloc[0] == ""


def test_control_characters_in_username_are_rejected():
    result = parse_csv(csv_of("2026-03-02T10:00:00Z,192.0.2.1,al\x1b[31mice,login,success,,"))
    assert result.rows_rejected == 1
    assert "control characters" in result.issues["reason"].iloc[0]


def test_c1_control_characters_are_rejected_like_c0_ones():
    next_line = chr(0x85)  # NEL: a line break in Unicode, a control character in Latin-1
    result = parse_csv(csv_of(f"2026-03-02T10:00:00Z,192.0.2.1,al{next_line}ice,login,success,,"))
    assert result.rows_rejected == 1
    assert "control characters" in result.issues["reason"].iloc[0]


@pytest.mark.parametrize("codepoint", [0x202E, 0x202A, 0x2066, 0x200F, 0x200B, 0xFEFF])
@pytest.mark.parametrize("column", ["username", "host"])
def test_invisible_formatting_characters_that_disguise_a_value_are_rejected(codepoint, column):
    # 'adm' + RIGHT-TO-LEFT OVERRIDE + 'nimda' is displayed as 'admadmin'.
    disguised = "adm" + chr(codepoint) + "nimda"
    user, host = (disguised, "h") if column == "username" else ("alice", disguised)
    result = parse_csv(csv_of(f"2026-03-02T10:00:00Z,192.0.2.1,{user},login,success,{host},"))
    assert result.rows_rejected == 1
    issue = result.issues.iloc[0]
    assert issue["column"] == column and "invisible" in issue["reason"]
    assert issue["value"] == ""  # free text is never quoted back


def test_joiners_used_by_real_scripts_are_still_accepted():
    # ZERO WIDTH NON-JOINER / JOINER are part of correct spelling in Persian and Indic scripts.
    for joiner in (chr(0x200C), chr(0x200D)):
        result = parse_csv(csv_of(f"2026-03-02T10:00:00Z,192.0.2.1,a{joiner}b,login,success,,"))
        assert result.rows_accepted == 1


@pytest.mark.parametrize(
    "zoned",
    [
        "fe80::1%eth0",
        "fe80::1%<a href='https:example.invalid'>click",  # was drawn as a link in a chart
        "fe80::1%" + "A" * 5000,  # Python accepts a zone ID of any length
    ],
)
def test_ipv6_zone_ids_are_rejected_and_their_text_is_not_quoted_back(zoned):
    result = parse_csv(csv_of(f"2026-03-02T10:00:00Z,{zoned},alice,login,failure,,"))
    assert result.rows_accepted == 0
    assert list(result.issues["column"]) == ["source_ip"]  # one reason, not two
    assert "zone ID" in result.issues["reason"].iloc[0]
    assert result.issues["value"].iloc[0] == ""


def test_accepted_source_ips_contain_only_address_characters():
    import re

    from loglens.sample_data import generate_csv

    events = parse_csv(generate_csv()).events
    assert events["source_ip"].map(lambda ip: bool(re.fullmatch(r"[0-9a-f:.]+", ip))).all()


# --------------------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "not-a-time",
        "2026-03-02",  # date without a time
        "03/02/2026 10:00:00",  # not ISO 8601
        "2026-13-45T10:00:00Z",  # impossible date
        "2026-02-30T10:00:00Z",  # no such day
        "2026-03-02T25:00:00Z",  # impossible hour
        "1969-12-31T23:59:59Z",  # outside supported range
        "9999-01-01T00:00:00Z",  # outside supported range
        "1772445600",  # epoch seconds are not supported
    ],
)
def test_malformed_timestamps_are_rejected_with_a_reason(bad_timestamp):
    result = parse_csv(
        csv_of(
            f"{bad_timestamp},192.0.2.1,alice,login,success,,",
            "2026-03-02T10:00:00Z,192.0.2.1,bob,login,success,,",
        )
    )
    assert result.rows_accepted == 1
    assert list(result.events["username"]) == ["bob"]
    assert result.rows_rejected == 1
    assert result.issues["column"].iloc[0] == "timestamp"
    assert result.issues["row"].iloc[0] == 2


def test_timestamps_are_normalised_to_utc():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:00:00Z,192.0.2.1,a,login,success,,",
            "2026-03-02T05:00:00-05:00,192.0.2.2,b,login,success,,",
            "2026-03-02T11:00:00+01:00,192.0.2.3,c,login,success,,",
            "2026-03-02 10:00:00,192.0.2.4,d,login,success,,",  # naive -> UTC
            "2026-03-02T10:00:00.250Z,192.0.2.5,e,login,success,,",
        )
    )
    stamps = result.events.set_index("username")["timestamp"]
    expected = pd.Timestamp("2026-03-02T10:00:00", tz="UTC")
    for user in "abcd":
        assert stamps[user] == expected
    assert stamps["e"] == expected + pd.Timedelta(milliseconds=250)
    assert result.naive_timestamp_rows == 1
    assert any("Assumed UTC" in warning for warning in result.warnings())


def test_unsorted_rows_are_sorted_chronologically_and_reported():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:30:00Z,192.0.2.1,a,login,success,,",
            "2026-03-02T10:10:00Z,192.0.2.1,a,login,success,,",
            "2026-03-02T10:20:00Z,192.0.2.1,a,login,success,,",
        )
    )
    assert result.events["timestamp"].is_monotonic_increasing
    assert result.out_of_order_rows == 2
    assert list(result.events["source_row"]) == [3, 4, 2]  # still traceable to the file


def test_event_ids_do_not_depend_on_row_order():
    lines = [
        f"2026-03-02T10:{minute:02d}:00Z,192.0.2.{minute},user{minute % 3},login,"
        f"{'failure' if minute % 2 else 'success'},,m{minute}"
        for minute in range(30)
    ]
    reference = parse_csv(csv_of(*lines)).events.drop(columns="source_row")
    for seed in range(5):
        shuffled = lines[:]
        random.Random(seed).shuffle(shuffled)
        again = parse_csv(csv_of(*shuffled)).events.drop(columns="source_row")
        pd.testing.assert_frame_equal(reference, again)


# --------------------------------------------------------------------------------------
# Duplicates
# --------------------------------------------------------------------------------------


def test_exact_duplicates_are_kept_and_counted_by_default():
    # Removing them silently would lower the counts every rule depends on: with one-second
    # timestamps, five identical failed logins in one second ARE five attempts.
    line = "2026-03-02T10:00:00Z,192.0.2.1,alice,login,failure,sso,bad password"
    result = parse_csv(csv_of(line, line, line))
    assert result.rows_accepted == 3
    assert (result.duplicate_rows, result.duplicates_removed) == (2, 0)
    assert result.duplicates_dropped is False
    assert result.rows_accepted + result.rows_rejected + result.duplicates_removed == 3
    (warning,) = [w for w in result.warnings() if "duplicate" in w]
    assert warning.startswith("Kept 2 exact duplicate rows") and "They count" in warning


def test_exact_duplicates_can_be_removed_and_counted():
    line = "2026-03-02T10:00:00Z,192.0.2.1,alice,login,failure,sso,bad password"
    result = parse_csv(csv_of(line, line, line), drop_duplicates=True)
    assert result.rows_accepted == 1
    assert (result.duplicate_rows, result.duplicates_removed) == (2, 2)
    assert result.duplicates_dropped is True
    assert any(w.startswith("Removed 2 exact duplicate rows") for w in result.warnings())


def test_a_file_without_duplicates_says_nothing_about_them():
    result = parse_csv(csv_of("2026-03-02T10:00:00Z,192.0.2.1,alice,login,failure,sso,x"))
    assert result.duplicate_rows == 0
    assert not any("duplicate" in w for w in result.warnings())


def test_duplicates_can_be_kept_and_near_duplicates_are_never_removed():
    line = "2026-03-02T10:00:00Z,192.0.2.1,alice,login,failure,sso,bad password"
    other = "2026-03-02T10:00:00Z,192.0.2.1,alice,login,failure,sso,different message"
    kept = parse_csv(csv_of(line, line), drop_duplicates=False)
    assert kept.rows_accepted == 2
    assert kept.duplicates_removed == 0
    assert parse_csv(csv_of(line, other)).rows_accepted == 2


def test_duplicates_are_detected_after_normalisation():
    result = parse_csv(
        csv_of(
            "2026-03-02T10:00:00Z,192.0.2.1,Alice,LOGIN,Failure,,",
            "2026-03-02T05:00:00-05:00,192.0.2.1,alice,login,failure,,",
        ),
        drop_duplicates=True,
    )
    assert result.rows_accepted == 1
    assert result.duplicates_removed == 1


def test_echoed_values_in_issues_are_cut_at_40_characters():
    result = parse_csv(csv_of(f"{'9' * 100},192.0.2.1,alice,login,success,,"))
    assert len(result.issues["value"].iloc[0]) == 40


def test_rejection_summary_orders_by_count_then_column_name():
    result = parse_csv(
        csv_of(
            "bad,192.0.2.1,a,login,success,,",
            "worse,192.0.2.1,a,login,success,,",
            "2026-03-02T10:00:00Z,999.1.1.1,a,login,success,,",
            "2026-03-02T10:00:01Z,888.1.1.1,a,login,success,,",
            "2026-03-02T10:00:02Z,192.0.2.1,a,teleport,success,,",
        )
    )
    summary = result.rejection_summary()
    assert list(summary["rows"]) == [2, 2, 1]
    assert list(summary["column"]) == ["source_ip", "timestamp", "event_type"]  # ties: A to Z
