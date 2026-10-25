"""The bundled synthetic dataset: deterministic, safe, and producing the documented alerts."""

from __future__ import annotations

import ipaddress
import re

import pytest

from signalquarry.detection import run_detections
from signalquarry.parser import parse_csv
from signalquarry.pipeline import load_demo_dataset
from signalquarry.sample_data import (
    EXPECTED_ALERTS,
    SAMPLE_PATH,
    generate_csv,
    generate_events,
)

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]


@pytest.fixture(scope="module")
def demo():
    return load_demo_dataset()


@pytest.fixture(scope="module")
def demo_alerts(demo):
    return run_detections(demo.events)


def test_generation_is_deterministic():
    assert generate_csv() == generate_csv()
    assert generate_events() == generate_events()


def test_bundled_csv_matches_the_generator():
    # If this fails, regenerate the file with:  python -m signalquarry.sample_data
    assert SAMPLE_PATH.read_text(encoding="utf-8") == generate_csv()


def test_demo_data_parses_cleanly(demo):
    parse = demo.parse
    assert demo.is_demo
    assert parse.rows_rejected == 0
    assert parse.duplicates_removed == 0
    assert parse.warnings() == []
    assert parse.rows_accepted == parse.rows_read > 500


def test_bundled_sample_produces_exactly_the_documented_alerts(demo_alerts):
    actual = sorted(
        (a.rule_id, a.severity, a.usernames, a.source_ips, a.event_count) for a in demo_alerts
    )
    expected = sorted(
        (e.rule_id, e.severity, e.usernames, e.source_ips, e.event_count) for e in EXPECTED_ALERTS
    )
    assert actual == expected
    assert len(demo_alerts) == 10


@pytest.mark.parametrize(
    ("scenario", "rules"),
    [
        ("S1", {"LL-001", "LL-002"}),
        ("S2", {"LL-001"}),
        ("S3", {"LL-002"}),
        ("S4", {"LL-002", "LL-003"}),
        ("S5", {"LL-001", "LL-002", "LL-003"}),
        ("S6", {"LL-004"}),
    ],
)
def test_each_scripted_scenario_triggers_only_its_documented_rules(scenario, rules):
    assert {e.rule_id for e in EXPECTED_ALERTS if e.scenario == scenario} == rules


def test_benign_high_activity_is_not_flagged(demo, demo_alerts):
    flagged_ids = {event_id for alert in demo_alerts for event_id in alert.event_ids}
    events = demo.events

    def flagged(mask):
        return bool(set(events.loc[mask, "event_id"]) & flagged_ids)

    # B2: nightly ETL - 41 events per night, all successful.
    etl = events["username"] == "svc.etl"
    assert etl.sum() >= 120
    assert not flagged(etl)
    # B3: four failures from a shared NAT address (one below the IP threshold).
    nat_failures = (events["source_ip"] == "192.0.2.250") & (events["outcome"] == "failure")
    assert nat_failures.sum() == 4
    assert not flagged(events["source_ip"] == "192.0.2.250")
    # B4 and B5: below the account-failure and denial thresholds.
    assert not flagged(events["username"] == "ben.carter")
    assert not flagged(events["username"] == "emma.larsen")
    # B1: twenty logins within five minutes on Tuesday morning produce no alert.
    surge = (
        (events["event_type"] == "login")
        & (events["outcome"] == "success")
        & (events["timestamp"] >= "2026-03-03T09:00:00Z")
        & (events["timestamp"] <= "2026-03-03T09:05:00Z")
    )
    assert surge.sum() >= 20
    assert not flagged(surge)


def test_demo_data_covers_every_event_type_and_outcome(demo):
    assert set(demo.events["event_type"]) == {"login", "logout", "access", "password_change"}
    assert set(demo.events["outcome"]) == {"success", "failure", "denied"}


def test_only_documentation_ip_ranges_are_used(demo):
    for raw in demo.events["source_ip"].unique():
        address = ipaddress.ip_address(raw)
        assert any(address in network for network in DOCUMENTATION_NETWORKS), raw


def test_demo_data_contains_no_credentials_or_real_looking_secrets(demo):
    secret_like = re.compile(r"(passw(or)?d|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.I)
    for message in demo.events["message"]:
        assert not secret_like.search(message), message
    assert not demo.events["username"].str.contains("@").any()  # no real e-mail addresses


def test_all_demo_usernames_are_fictitious_pattern(demo):
    assert demo.events["username"].str.fullmatch(r"[a-z]+\.[a-z]+|svc\.[a-z]+").all()


def test_sample_file_round_trips_through_the_public_parser():
    result = parse_csv(SAMPLE_PATH.read_bytes())
    assert result.rows_rejected == 0
    assert len(result.events) == len(generate_events())
