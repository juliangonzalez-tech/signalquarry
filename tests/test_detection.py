"""Detection rules LL-001..LL-004: thresholds, windows, correlation, dedup and ordering."""

from __future__ import annotations

import random

import pytest
from conftest import access, at, build_events, deny, fail, ok

from signalquarry.detection import DetectionConfig, run_detections, severity_counts
from signalquarry.detection.models import CLASSIFICATION

IP_A, IP_B, IP_C = "203.0.113.10", "203.0.113.11", "203.0.113.12"


def alerts_for(rows, rule_id=None, config=None):
    alerts = run_detections(build_events(rows), config)
    return [a for a in alerts if rule_id is None or a.rule_id == rule_id]


def failures(ip=IP_A, user="alice", count=5, spacing_s=60, start_s=0):
    return [fail(at(seconds=start_s + i * spacing_s), ip, user) for i in range(count)]


# --------------------------------------------------------------------------------------
# LL-001  failed logins from one IP
# --------------------------------------------------------------------------------------


def test_qualifying_burst_from_one_ip_raises_one_alert_with_expected_fields():
    events = build_events(failures(count=5, spacing_s=60))  # 5 failures in 4 minutes
    alerts = run_detections(events)
    ll001 = [a for a in alerts if a.rule_id == "LL-001"]

    assert len(ll001) == 1
    alert = ll001[0]
    assert alert.event_count == 5
    assert alert.severity == "medium"
    assert alert.source_ips == (IP_A,)
    assert alert.usernames == ("alice",)
    assert alert.timestamp == events["timestamp"].iloc[0]
    assert alert.end_timestamp == events["timestamp"].iloc[-1]
    assert set(alert.event_ids) == set(events["event_id"])  # evidence = the five failures
    assert alert.classification == CLASSIFICATION == "Heuristic flag"
    assert alert.alert_id.startswith("ALR-")
    assert "5 failed logins" in alert.explanation


def test_burst_below_threshold_does_not_alert():
    assert alerts_for(failures(count=4, spacing_s=30), "LL-001") == []


def test_threshold_boundary_is_exact():
    assert len(alerts_for(failures(count=5, spacing_s=10), "LL-001")) == 1
    assert alerts_for(failures(count=4, spacing_s=10), "LL-001") == []


def test_window_boundary_is_inclusive_to_the_second():
    exactly_ten_minutes = [fail(at(seconds=s)) for s in (0, 150, 300, 450, 600)]
    one_second_over = [fail(at(seconds=s)) for s in (0, 150, 300, 450, 601)]
    assert len(alerts_for(exactly_ten_minutes, "LL-001")) == 1
    assert alerts_for(one_second_over, "LL-001") == []


def test_rolling_window_ignores_failures_spread_over_time():
    # Five failures overall, but only ever two or three inside any 10-minute span.
    spread = [fail(at(minutes=m)) for m in (0, 4, 8, 12, 16)]
    assert alerts_for(spread, "LL-001") == []
    # Same count of rows, packed in time: now it alerts. Row count alone is not the signal.
    packed = [fail(at(minutes=m)) for m in (0, 1, 2, 3, 4)]
    assert len(alerts_for(packed, "LL-001")) == 1


def test_a_slow_trickle_that_stays_under_the_rate_never_alerts():
    one_every_three_minutes = [fail(at(minutes=3 * i)) for i in range(20)]  # 4 per 10 min
    assert alerts_for(one_every_three_minutes, "LL-001") == []


def test_failures_from_different_ips_are_not_combined_for_ll001():
    mixed = failures(IP_A, count=3) + failures(IP_B, count=3, start_s=5)
    assert alerts_for(mixed, "LL-001") == []


def test_other_event_types_and_successes_do_not_count_as_failed_logins():
    rows = failures(count=3) + [ok(at(seconds=200)), deny(at(seconds=210), IP_A)]
    rows += [access(at(seconds=220), IP_A), (at(seconds=230), IP_A, "alice", "logout", "failure")]
    assert alerts_for(rows, "LL-001") == []


def test_ll001_records_every_targeted_account_in_a_spray():
    spray = [fail(at(seconds=20 * i), IP_A, f"user{i}") for i in range(8)]
    ll001 = alerts_for(spray, "LL-001")
    assert len(ll001) == 1
    assert ll001[0].usernames == tuple(sorted(f"user{i}" for i in range(8)))
    assert alerts_for(spray, "LL-002") == []  # one failure per account: not an account alert


# --------------------------------------------------------------------------------------
# Deduplication, overlap and separate bursts
# --------------------------------------------------------------------------------------


def test_sustained_burst_is_one_alert_not_one_per_event():
    sustained = failures(count=30, spacing_s=30)  # 30 failures over ~15 minutes
    ll001 = alerts_for(sustained, "LL-001")
    assert len(ll001) == 1
    assert ll001[0].event_count == 30
    assert ll001[0].severity == "high"  # 30 >= 3 x threshold: escalated one level


def test_overlapping_windows_produce_a_single_alert_with_all_events():
    # Windows [0..4], [1..5], [2..6] all qualify and overlap -> one alert of 7 events.
    overlapping = [fail(at(minutes=m)) for m in (0, 2, 4, 6, 8, 10, 12)]
    ll001 = alerts_for(overlapping, "LL-001")
    assert len(ll001) == 1
    assert ll001[0].event_count == 7


def test_bursts_separated_by_more_than_the_window_are_separate_alerts():
    two_bursts = failures(count=5, spacing_s=30) + failures(count=5, spacing_s=30, start_s=3600)
    ll001 = alerts_for(two_bursts, "LL-001")
    assert len(ll001) == 2
    assert not set(ll001[0].event_ids) & set(ll001[1].event_ids)
    assert ll001[0].timestamp < ll001[1].timestamp


def test_alert_ids_are_unique_and_sequential():
    rows = failures(IP_A, "alice", 6) + failures(IP_B, "bob", 6, start_s=7200)
    alerts = alerts_for(rows)
    ids = [a.alert_id for a in alerts]
    assert len(ids) == len(set(ids)) >= 4
    assert ids == [f"ALR-{i:04d}" for i in range(1, len(ids) + 1)]


# --------------------------------------------------------------------------------------
# LL-002  failed logins against one account (any IP)
# --------------------------------------------------------------------------------------


def test_ll002_flags_distributed_failures_against_one_account():
    distributed = [fail(at(seconds=40 * i), f"203.0.113.{100 + i}", "dana") for i in range(6)]
    assert alerts_for(distributed, "LL-001") == []  # no single IP is noisy
    ll002 = alerts_for(distributed, "LL-002")
    assert len(ll002) == 1
    assert ll002[0].usernames == ("dana",)
    assert len(ll002[0].source_ips) == 6
    assert "6 different source IPs" in ll002[0].explanation


def test_ll002_is_not_triggered_by_failures_spread_across_accounts():
    rows = [fail(at(seconds=20 * i), IP_A, f"user{i % 5}") for i in range(10)]  # 2 per account
    assert alerts_for(rows, "LL-002") == []


def test_ll002_does_not_mix_usernames_case_insensitively_apart():
    rows = [
        fail(at(seconds=10 * i), IP_A, user)
        for i, user in enumerate(["Dana", "dana", "DANA", "dana", "Dana"])
    ]
    assert len(alerts_for(rows, "LL-002")) == 1  # one account, however it is capitalised


def test_same_events_can_support_alerts_from_different_rules():
    ids = {a.rule_id for a in alerts_for(failures(IP_A, "alice", 6))}
    assert ids == {"LL-001", "LL-002"}  # one IP and one account both crossed their thresholds


# --------------------------------------------------------------------------------------
# LL-003  success after repeated failures
# --------------------------------------------------------------------------------------

BURST = [fail(at(minutes=m), IP_A, "erin") for m in (0, 1, 2, 3, 4)]  # last failure at 10:04


def test_success_after_qualifying_burst_is_correlated_with_its_failures():
    success = ok(at(minutes=7), IP_A, "erin")
    events = build_events([*BURST, success])
    alerts = [a for a in run_detections(events) if a.rule_id == "LL-003"]

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "high"
    assert alert.usernames == ("erin",)
    assert alert.event_count == 6  # five failures + the success
    success_id = events[events["outcome"] == "success"]["event_id"].iloc[0]
    assert success_id in alert.event_ids
    assert alert.end_timestamp == events[events["outcome"] == "success"]["timestamp"].iloc[0]
    assert alert.timestamp == events["timestamp"].iloc[0]  # starts at the first failure
    assert "from an IP that also produced failures" in alert.explanation


def test_success_from_a_different_ip_still_correlates_by_account():
    alerts = alerts_for([*BURST, ok(at(minutes=6), IP_C, "erin")], "LL-003")
    assert len(alerts) == 1
    assert "different IP" in alerts[0].explanation
    assert set(alerts[0].source_ips) == {IP_A, IP_C}


def test_success_before_the_burst_is_not_flagged():
    assert alerts_for([ok(at(minutes=-5), IP_A, "erin"), *BURST], "LL-003") == []


def test_success_after_sub_threshold_failures_is_not_flagged():
    assert alerts_for([*BURST[:4], ok(at(minutes=6), IP_A, "erin")], "LL-003") == []


def test_failures_of_other_accounts_do_not_count_toward_the_success():
    other = [fail(at(minutes=m), IP_A, "frank") for m in (0, 1, 2, 3, 4)]
    assert alerts_for([*other, ok(at(minutes=6), IP_A, "erin")], "LL-003") == []


def test_investigation_window_runs_from_the_last_failure_of_the_burst():
    # BURST ends at 10:04. "Within 15 minutes" means within 15 minutes of that last failure,
    # inclusive: 10:19:00 is flagged, 10:19:01 is not.
    assert len(alerts_for([*BURST, ok(at(minutes=19), IP_A, "erin")], "LL-003")) == 1
    assert alerts_for([*BURST, ok(at(minutes=19, seconds=1), IP_A, "erin")], "LL-003") == []


@pytest.mark.parametrize("burst_minutes", [0, 4, 8, 10])
def test_investigation_window_does_not_shrink_as_the_burst_gets_longer(burst_minutes):
    # Regression: the window used to be measured back from the success to the burst START, so
    # a 10-minute burst left only 5 of the 15 minutes. The gap that counts is last-failure ->
    # success, whatever the burst's duration.
    step = burst_minutes / 4
    burst = [fail(at(minutes=i * step), IP_A, "erin") for i in range(5)]
    last = burst_minutes
    assert len(alerts_for([*burst, ok(at(minutes=last + 15), IP_A, "erin")], "LL-003")) == 1
    assert alerts_for([*burst, ok(at(minutes=last + 15, seconds=1), IP_A, "erin")], "LL-003") == []


def test_two_bursts_inside_the_window_are_both_evidence_of_one_alert():
    first = [fail(at(minutes=m), IP_A, "erin") for m in (0, 1, 2, 3, 4)]
    second = [fail(at(minutes=m), IP_C, "erin") for m in (9, 10, 11, 12, 13)]
    alerts = alerts_for([*first, *second, ok(at(minutes=16), IP_A, "erin")], "LL-003")
    assert len(alerts) == 1
    assert alerts[0].event_count == 11  # 10 failures + the success
    assert set(alerts[0].source_ips) == {IP_A, IP_C}


def test_an_older_burst_outside_the_window_is_not_evidence():
    old = [fail(at(minutes=m), IP_A, "erin") for m in (0, 1, 2, 3, 4)]
    recent = [fail(at(minutes=m), IP_A, "erin") for m in (40, 41, 42, 43, 44)]
    alerts = alerts_for([*old, *recent, ok(at(minutes=50), IP_A, "erin")], "LL-003")
    assert len(alerts) == 1
    assert alerts[0].event_count == 6  # only the recent burst (5) + the success
    assert alerts[0].timestamp == at(minutes=40)


def test_success_in_the_middle_of_a_continuing_burst_is_flagged_once():
    failures_ = [fail(at(minutes=m), IP_A, "erin") for m in range(0, 30)]  # one per minute
    rows = [*failures_, ok(at(minutes=6, seconds=30), IP_A, "erin")]
    rows.append(ok(at(minutes=20, seconds=30), IP_C, "erin"))
    alerts = alerts_for(rows, "LL-003")
    assert len(alerts) == 1  # the later success belongs to the same burst
    # evidence stops at the LAST success's moment: 21 failures happened before 10:20:30
    assert alerts[0].event_count == 21 + 2


def test_a_burst_that_only_qualifies_with_later_failures_does_not_flag_an_earlier_success():
    # Only 3 failures precede the success; the other 2 come after it, so no burst existed yet.
    rows = [fail(at(minutes=m), IP_A, "erin") for m in (0, 1, 2)]
    rows += [ok(at(minutes=3), IP_A, "erin")]
    rows += [fail(at(minutes=m), IP_A, "erin") for m in (4, 5)]
    assert alerts_for(rows, "LL-003") == []
    assert len(alerts_for(rows, "LL-002")) == 1  # the five failures do qualify as LL-002


def test_failure_at_the_same_second_as_the_success_is_not_treated_as_earlier():
    rows = [*BURST[:4], fail(at(minutes=7), IP_A, "erin"), ok(at(minutes=7), IP_A, "erin")]
    assert alerts_for(rows, "LL-003") == []  # only 4 failures strictly before the success


def test_several_successes_after_one_burst_make_one_alert():
    rows = [*BURST, ok(at(minutes=6), IP_A, "erin"), ok(at(minutes=9), IP_C, "erin")]
    alerts = alerts_for(rows, "LL-003")
    assert len(alerts) == 1
    assert alerts[0].event_count == 7  # 5 failures + 2 successes
    assert "plus 1 more success" in alerts[0].explanation


def test_two_separate_bursts_each_followed_by_a_success_make_two_alerts():
    second = [fail(at(minutes=m), IP_A, "erin") for m in (60, 61, 62, 63, 64)]
    rows = [*BURST, ok(at(minutes=6), IP_A, "erin"), *second, ok(at(minutes=66), IP_A, "erin")]
    assert len(alerts_for(rows, "LL-003")) == 2


def test_only_login_successes_count_for_ll003():
    assert alerts_for([*BURST, access(at(minutes=6), IP_A, "erin")], "LL-003") == []


def test_long_burst_followed_by_success_is_critical():
    long_burst = [fail(at(seconds=20 * i), IP_A, "erin") for i in range(16)]
    success = ok(at(seconds=20 * 16 + 120), IP_A, "erin")
    alerts = alerts_for([*long_burst, success], "LL-003")
    assert [a.severity for a in alerts] == ["critical"]


# --------------------------------------------------------------------------------------
# LL-004  repeated access denials
# --------------------------------------------------------------------------------------


def denials(count, user="gina", spacing_s=60):
    return [deny(at(seconds=i * spacing_s), user=user) for i in range(count)]


def test_access_denial_burst_raises_alert_at_threshold():
    alerts = alerts_for(denials(4), "LL-004")
    assert len(alerts) == 1
    assert alerts[0].event_count == 4
    assert alerts[0].severity == "low"
    assert alerts[0].usernames == ("gina",)


def test_denials_below_threshold_or_spread_out_do_not_alert():
    assert alerts_for(denials(3), "LL-004") == []
    assert alerts_for(denials(4, spacing_s=240), "LL-004") == []  # 4 denials over 12 minutes


def test_denials_are_tracked_per_account():
    rows = denials(2, "gina") + denials(2, "hank") + denials(2, "ivy")
    assert alerts_for(rows, "LL-004") == []


@pytest.mark.parametrize("event_type", ["access", "password_change", "login", "logout"])
def test_denials_of_any_event_type_count(event_type):
    rows = [(at(seconds=i * 30), "192.0.2.10", "gina", event_type, "denied") for i in range(4)]
    alerts = alerts_for(rows, "LL-004")
    assert len(alerts) == 1 and alerts[0].event_count == 4


def test_denials_of_different_event_types_add_up_in_one_window():
    kinds = ["access", "password_change", "login", "access"]
    rows = [
        (at(seconds=i * 30), "192.0.2.10", "gina", kind, "denied") for i, kind in enumerate(kinds)
    ]
    assert len(alerts_for(rows, "LL-004")) == 1


def test_denied_logins_are_not_failed_logins():
    rows = [(at(seconds=i * 10), IP_A, "gina", "login", "denied") for i in range(8)]
    assert alerts_for(rows, "LL-001") == [] and alerts_for(rows, "LL-002") == []


def test_failed_logins_and_successful_access_are_not_denials():
    rows = [fail(at(seconds=i), IP_A, "gina") for i in range(4)]
    rows += [access(at(seconds=10 + i), IP_A, "gina") for i in range(4)]
    assert alerts_for(rows, "LL-004") == []


def test_large_denial_burst_escalates_to_medium():
    assert [a.severity for a in alerts_for(denials(12, spacing_s=30), "LL-004")] == ["medium"]


# --------------------------------------------------------------------------------------
# Benign activity
# --------------------------------------------------------------------------------------


def test_busy_but_healthy_traffic_raises_no_alerts():
    rng = random.Random(7)
    rows = []
    for minute in range(120):  # two hours of heavy successful use by many accounts
        for user in range(15):
            rows.append(
                ok(
                    at(minutes=minute, seconds=rng.randint(0, 59)),
                    f"192.0.2.{user + 1}",
                    f"u{user}",
                )
            )
            rows.append(
                access(
                    at(minutes=minute, seconds=rng.randint(0, 59)),
                    f"192.0.2.{user + 1}",
                    f"u{user}",
                )
            )
    rows += [fail(at(minutes=30), "192.0.2.1", "u0"), fail(at(minutes=31), "192.0.2.2", "u1")]
    rows += [deny(at(minutes=40), "192.0.2.3", "u2")]
    assert alerts_for(rows) == []


def test_empty_events_produce_no_alerts():
    assert run_detections(build_events([fail(at())]).iloc[0:0]) == []


# --------------------------------------------------------------------------------------
# Consistency regardless of row order
# --------------------------------------------------------------------------------------


def scenario_rows():
    rows = failures(IP_A, "alice", 6) + [ok(at(seconds=500), IP_A, "alice")]
    rows += [fail(at(seconds=30 * i, minutes=90), f"203.0.113.{50 + i}", "bob") for i in range(6)]
    rows += denials(5, "carl") + [access(at(minutes=3), "192.0.2.9", "carl")]
    return rows


def alert_signature(alerts):
    return [
        (a.alert_id, a.rule_id, a.severity, a.timestamp, a.end_timestamp, a.usernames,
         a.source_ips, a.event_ids, a.explanation)
        for a in alerts
    ]  # fmt: skip


@pytest.mark.parametrize("seed", range(6))
def test_shuffled_rows_give_identical_alerts(seed):
    rows = scenario_rows()
    reference = alert_signature(run_detections(build_events(rows)))
    assert len(reference) >= 5  # the scenario really does exercise several rules

    shuffled = rows[:]
    random.Random(seed).shuffle(shuffled)
    assert alert_signature(run_detections(build_events(shuffled))) == reference


def test_reversed_rows_give_identical_alerts():
    rows = scenario_rows()
    forward = alert_signature(run_detections(build_events(rows)))
    assert alert_signature(run_detections(build_events(rows[::-1]))) == forward


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------


def test_thresholds_are_configurable():
    rows = failures(IP_A, "alice", 3)
    assert alerts_for(rows, "LL-001") == []
    assert len(alerts_for(rows, "LL-001", DetectionConfig(ip_failure_threshold=3))) == 1
    assert len(alerts_for(rows, "LL-002", DetectionConfig(account_failure_threshold=3))) == 1


def test_windows_are_configurable():
    slow = [fail(at(minutes=3 * i)) for i in range(5)]  # spans 12 minutes
    assert alerts_for(slow, "LL-001") == []
    assert len(alerts_for(slow, "LL-001", DetectionConfig(ip_failure_window_minutes=12))) == 1


def test_investigation_window_is_configurable():
    rows = [*BURST, ok(at(minutes=30), IP_A, "erin")]
    assert alerts_for(rows, "LL-003") == []
    assert len(alerts_for(rows, "LL-003", DetectionConfig(success_investigation_minutes=30))) == 1


def test_denial_threshold_is_configurable():
    assert len(alerts_for(denials(3), "LL-004", DetectionConfig(denial_threshold=3))) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ip_failure_threshold": 1},
        {"account_failure_threshold": 0},
        {"denial_threshold": -3},
        {"ip_failure_window_minutes": 0},
        {"success_investigation_minutes": 0},
        {"escalation_factor": 1},
    ],
)
def test_invalid_configuration_is_rejected(kwargs):
    with pytest.raises(ValueError):
        DetectionConfig(**kwargs)


def test_escalation_factor_controls_severity():
    rows = failures(IP_A, "alice", 10, spacing_s=10)
    assert [a.severity for a in alerts_for(rows, "LL-001")] == ["medium"]
    assert [
        a.severity for a in alerts_for(rows, "LL-001", DetectionConfig(escalation_factor=2))
    ] == ["high"]


def test_missing_columns_raise_a_clear_error():
    with pytest.raises(ValueError, match="missing columns"):
        run_detections(build_events([fail(at())]).drop(columns=["username"]))


def test_severity_counts_lists_every_level():
    counts = severity_counts(alerts_for(failures(IP_A, "alice", 6)))
    assert list(counts) == ["low", "medium", "high", "critical"]
    assert counts["medium"] == 2


def test_explanations_never_claim_certainty():
    for alert in alerts_for(scenario_rows()):
        text = alert.explanation.lower()
        assert "consistent with" in text or "rule:" in text
        for overclaim in ("confirmed", "proves", "definitely", "is an attack", "compromised"):
            assert overclaim not in text


# --------------------------------------------------------------------------------------
# Explanations: exact wording (this is what analysts read, so it is pinned, not eyeballed)
# --------------------------------------------------------------------------------------


def test_ll001_summary_wording_for_one_account_and_for_many():
    one = [fail(at(minutes=m), IP_A, "alice") for m in range(5)]
    ll001 = alerts_for(one, "LL-001")[0]
    assert (
        ll001.summary
        == "5 failed logins from 203.0.113.10 within 4m 00s, targeting 1 account (alice)."
    )
    spray = [fail(at(seconds=20 * i), IP_A, f"user{i}") for i in range(8)]
    assert alerts_for(spray, "LL-001")[0].summary == (
        "8 failed logins from 203.0.113.10 within 2m 20s, "
        "targeting 8 accounts (user0, user1, user2 +5 more)."
    )


def test_ll002_summary_wording_for_one_ip_and_for_many():
    same_ip = [fail(at(minutes=m), IP_A, "alice") for m in range(5)]
    assert alerts_for(same_ip, "LL-002")[0].summary == (
        "5 failed logins against 'alice' within 4m 00s, from 203.0.113.10."
    )
    many_ips = [fail(at(minutes=m), f"203.0.113.{m + 1}", "alice") for m in range(5)]
    assert alerts_for(many_ips, "LL-002")[0].summary == (
        "5 failed logins against 'alice' within 4m 00s, from 5 different source IPs."
    )


def test_ll004_summary_wording():
    alerts = alerts_for([deny(at(minutes=m), user="gina") for m in range(4)], "LL-004")
    assert alerts[0].summary == "4 authorization denials for 'gina' within 3m 00s."
    assert (
        "Rule: 4+ events with outcome 'denied' per account within 10 min." in alerts[0].explanation
    )


def test_ll003_summary_wording_singular_plural_and_gap():
    one_ip = [fail(at(minutes=m), IP_A, "erin") for m in range(5)]
    alert = alerts_for([*one_ip, ok(at(minutes=7), IP_A, "erin")], "LL-003")[0]
    assert alert.summary == (
        "A successful login for 'erin' at 2026-03-02 10:07:00 UTC came 3m 00s after the last of "
        "5 failed attempts from 1 source IP; the success came from an IP that also produced "
        "failures."
    )
    three_ips = [fail(at(minutes=m), f"203.0.113.{m % 3 + 1}", "erin") for m in range(5)]
    plural = alerts_for([*three_ips, ok(at(minutes=7), IP_C, "erin")], "LL-003")[0]
    assert "5 failed attempts from 3 source IPs;" in plural.summary
    assert "from a different IP than the failures" in plural.summary
    assert "the burst's last failure" in plural.explanation


def test_ll003_gap_is_measured_to_the_last_failure_strictly_before_the_first_success():
    # A failure shares the first success's exact timestamp. It is evidence for the LATER success
    # but must not shrink the reported gap of the first one to 0s.
    rows = [fail(at(minutes=m), IP_A, "erin") for m in range(5)]
    rows += [ok(at(minutes=8), IP_A, "erin"), fail(at(minutes=8), IP_A, "erin")]
    rows += [ok(at(minutes=10), IP_A, "erin")]
    alert = alerts_for(rows, "LL-003")[0]
    assert alert.event_count == 6 + 2  # 6 failures + both successes
    assert "came 4m 00s after the last of 6 failed attempts" in alert.summary


def test_limited_join_truncates_after_three_by_default():
    from signalquarry.detection import limited_join

    assert limited_join(["a", "b", "c"]) == "a, b, c"
    assert limited_join(["a", "b", "c", "d", "e"]) == "a, b, c +2 more"
    assert limited_join(["a", "b", "c", "d"], limit=2) == "a, b +2 more"
    assert limited_join([]) == ""


def test_severity_escalation_boundaries_and_cap():
    from signalquarry.detection.models import escalate

    assert escalate("low", 14, 5, 3) == "low"  # one below factor x threshold
    assert escalate("low", 15, 5, 3) == "medium"  # exactly at it
    assert escalate("high", 15, 5, 3) == "critical"
    assert escalate("critical", 1000, 5, 3) == "critical"  # never past the top level


def test_core_data_structures_are_immutable():
    import dataclasses

    from signalquarry.detection import RULE_CATALOG

    alert = alerts_for(failures(IP_A, "alice", 6), "LL-001")[0]
    for obj, attribute in ((alert, "severity"), (DetectionConfig(), "denial_threshold"),
                           (RULE_CATALOG["LL-001"], "name")):  # fmt: skip
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, attribute, "changed")


def test_empty_alert_table_keeps_its_column_types():
    from signalquarry.detection import alerts_to_frame

    frame = alerts_to_frame([])
    assert frame.empty and str(frame["timestamp"].dt.tz) == "UTC"
    assert str(frame["event_count"].dtype) == "int64"


def test_default_configuration_matches_the_documentation():
    config = DetectionConfig()
    assert (config.ip_failure_threshold, config.ip_failure_window_minutes) == (5, 10)
    assert (config.account_failure_threshold, config.account_failure_window_minutes) == (5, 10)
    assert config.success_investigation_minutes == 15
    assert (config.denial_threshold, config.denial_window_minutes) == (4, 10)
    assert config.escalation_factor == 3


def test_ll002_default_window_is_exactly_ten_minutes_inclusive():
    exactly = [
        fail(at(seconds=s), f"203.0.113.{i + 1}", "alice")
        for i, s in enumerate((0, 150, 300, 450, 600))
    ]
    over = [
        fail(at(seconds=s), f"203.0.113.{i + 1}", "alice")
        for i, s in enumerate((0, 150, 300, 450, 601))
    ]
    assert len(alerts_for(exactly, "LL-002")) == 1
    assert alerts_for(over, "LL-002") == []


def test_ll004_default_window_is_exactly_ten_minutes_inclusive():
    exactly = [deny(at(seconds=s), user="gina") for s in (0, 200, 400, 600)]
    over = [deny(at(seconds=s), user="gina") for s in (0, 200, 400, 601)]
    assert len(alerts_for(exactly, "LL-004")) == 1
    assert alerts_for(over, "LL-004") == []
