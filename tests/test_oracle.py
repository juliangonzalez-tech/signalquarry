"""Differential tests: the real engine against a brute-force reference written from the spec.

The reference deliberately avoids the production algorithm. It enumerates *every* candidate
window, links the events they contain with union-find, and for LL-003 recomputes the failure
clusters from scratch for each success. It is O(n^3) and only fit for tiny inputs, which is
exactly where we can generate thousands of random, boundary-heavy cases (event times sit on a
coarse grid so that "exactly on the window edge" and "identical timestamps" happen constantly).

Specification the reference encodes
-----------------------------------
* Qualifying window: >= N events of one group whose first and last timestamps differ by <= W.
* Cluster: events connected through qualifying windows that share at least one event.
  One alert per cluster.
* LL-001 groups failed logins by source IP, LL-002 by username; LL-004 groups every event whose
  outcome is "denied" by username.
* LL-003, per account: for a successful login at time s consider the account's failed logins
  strictly before s, build their LL-002 clusters, and keep the clusters whose last failure is at
  most L before s (the investigation window runs from the END of the burst). Successes that
  share a cluster make one alert. Evidence = those clusters + the successes.
* Severity: a per-rule base level, raised one level at >= factor x threshold events
  (LL-003 counts failures only).
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import timedelta

import pytest
from conftest import T0, build_events

from loglens.detection import DetectionConfig, run_detections

SEVERITIES = ["low", "medium", "high", "critical"]
BASE = {"LL-001": "medium", "LL-002": "medium", "LL-003": "high", "LL-004": "low"}


# --------------------------------------------------------------------------------------
# Brute-force reference
# --------------------------------------------------------------------------------------


def brute_clusters(times: list[int], threshold: int, window: int) -> list[list[int]]:
    """Index lists of the clusters of ``times`` (sorted). Enumerates every window."""
    count = len(times)
    parent = list(range(count))
    in_window = [False] * count

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for first in range(count):
        for last in range(first + threshold - 1, count):
            if times[last] - times[first] <= window:
                for member in range(first, last + 1):
                    in_window[member] = True
                    parent[find(member)] = find(first)
    groups: dict[int, list[int]] = {}
    for index in range(count):
        if in_window[index]:
            groups.setdefault(find(index), []).append(index)
    return sorted(groups.values())


@dataclass(frozen=True)
class Expected:
    rule_id: str
    severity: str
    usernames: tuple[str, ...]
    source_ips: tuple[str, ...]
    event_ids: tuple[str, ...]
    start: object
    end: object


def severity(rule_id: str, count: int, threshold: int, config: DetectionConfig) -> str:
    rank = SEVERITIES.index(BASE[rule_id])
    if count >= config.escalation_factor * threshold:
        rank = min(rank + 1, 3)
    return SEVERITIES[rank]


def expected_from(rule_id, rows, threshold, config):
    rows = sorted(rows, key=lambda r: (r["timestamp"], r["event_id"]))
    return Expected(
        rule_id=rule_id,
        severity=severity(rule_id, len(rows), threshold, config),
        usernames=tuple(sorted({r["username"] for r in rows})),
        source_ips=tuple(sorted({r["source_ip"] for r in rows})),
        event_ids=tuple(r["event_id"] for r in rows),
        start=rows[0]["timestamp"],
        end=rows[-1]["timestamp"],
    )


def reference_alerts(events, config: DetectionConfig) -> list[Expected]:
    records = events.to_dict("records")
    seconds = lambda r: int((r["timestamp"] - events["timestamp"].min()).total_seconds())  # noqa: E731
    results: list[Expected] = []

    def threshold_rule(rule_id, selected, key, threshold, window_minutes):
        groups: dict[str, list[dict]] = {}
        for record in sorted(selected, key=lambda r: (r["timestamp"], r["event_id"])):
            groups.setdefault(record[key], []).append(record)
        for rows in groups.values():
            times = [seconds(r) for r in rows]
            for cluster in brute_clusters(times, threshold, window_minutes * 60):
                results.append(
                    expected_from(rule_id, [rows[i] for i in cluster], threshold, config)
                )

    failures = [r for r in records if r["event_type"] == "login" and r["outcome"] == "failure"]
    denials = [r for r in records if r["outcome"] == "denied"]
    threshold_rule(
        "LL-001",
        failures,
        "source_ip",
        config.ip_failure_threshold,
        config.ip_failure_window_minutes,
    )
    threshold_rule(
        "LL-002",
        failures,
        "username",
        config.account_failure_threshold,
        config.account_failure_window_minutes,
    )
    threshold_rule(
        "LL-004", denials, "username", config.denial_threshold, config.denial_window_minutes
    )

    # LL-003
    successes = [r for r in records if r["event_type"] == "login" and r["outcome"] == "success"]
    for user in sorted({r["username"] for r in successes}):
        user_failures = sorted(
            (r for r in failures if r["username"] == user),
            key=lambda r: (r["timestamp"], r["event_id"]),
        )
        user_successes = sorted(
            (r for r in successes if r["username"] == user),
            key=lambda r: (r["timestamp"], r["event_id"]),
        )
        groups: list[
            tuple[set[str], list[dict], list[dict]]
        ] = []  # failure ids, failures, successes
        for success in user_successes:
            earlier = [f for f in user_failures if f["timestamp"] < success["timestamp"]]
            times = [seconds(f) for f in earlier]
            evidence: list[dict] = []
            for cluster in brute_clusters(
                times, config.account_failure_threshold, config.account_failure_window_minutes * 60
            ):
                last_failure = times[cluster[-1]]
                if seconds(success) - last_failure <= config.success_investigation_minutes * 60:
                    evidence.extend(earlier[i] for i in cluster)
            if not evidence:
                continue
            ids = {f["event_id"] for f in evidence}
            if groups and groups[-1][0] & ids:
                groups[-1][0].update(ids)
                known = {f["event_id"] for f in groups[-1][1]}
                groups[-1][1].extend(f for f in evidence if f["event_id"] not in known)
                groups[-1][2].append(success)
            else:
                groups.append((ids, list(evidence), [success]))
        for _, group_failures, group_successes in groups:
            rows = group_failures + group_successes
            expected = expected_from("LL-003", rows, 0, config)
            level = severity(
                "LL-003", len(group_failures), config.account_failure_threshold, config
            )
            results.append(
                Expected(
                    **{**expected.__dict__, "severity": level}
                )  # severity counts failures only
            )
    return results


def signature(items) -> list[tuple]:
    return sorted(
        (i.rule_id, i.severity, i.usernames, i.source_ips, i.event_ids, str(i.start), str(i.end))
        for i in items
    )


def engine_signature(alerts) -> list[tuple]:
    return sorted(
        (
            a.rule_id,
            a.severity,
            a.usernames,
            a.source_ips,
            a.event_ids,
            str(a.timestamp),
            str(a.end_timestamp),
        )
        for a in alerts
    )


# --------------------------------------------------------------------------------------
# Random scenario generation (coarse grid => constant boundary hits and timestamp ties)
# --------------------------------------------------------------------------------------

KINDS = [
    ("login", "failure"),
    ("login", "failure"),
    ("login", "failure"),
    ("login", "success"),
    ("access", "denied"),
    ("password_change", "denied"),
    ("login", "denied"),
    ("access", "success"),
    ("logout", "success"),
]


def random_rows(rng: random.Random, size: int, span_minutes: int):
    ips = ["192.0.2.1", "192.0.2.2", "203.0.113.9"]
    users = ["ann", "bob", "cy"]
    rows = []
    for _ in range(size):
        grid = rng.randrange(0, span_minutes * 2 + 1) * 30  # multiples of 30 seconds
        kind, outcome = rng.choice(KINDS)
        rows.append(
            (T0 + timedelta(seconds=grid), rng.choice(ips), rng.choice(users), kind, outcome)
        )
    return rows


def random_config(rng: random.Random) -> DetectionConfig:
    return DetectionConfig(
        ip_failure_threshold=rng.choice([2, 3, 4]),
        ip_failure_window_minutes=rng.choice([1, 2, 3, 5]),
        account_failure_threshold=rng.choice([2, 3, 4]),
        account_failure_window_minutes=rng.choice([1, 2, 3, 5]),
        success_investigation_minutes=rng.choice([1, 2, 4, 7]),
        denial_threshold=rng.choice([2, 3, 4]),
        denial_window_minutes=rng.choice([1, 2, 3, 5]),
        escalation_factor=rng.choice([2, 3]),
    )


@pytest.mark.parametrize("seed", range(40))
def test_engine_matches_brute_force_reference(seed):
    rng = random.Random(seed)
    for _ in range(12):
        config = random_config(rng)
        events = build_events(
            random_rows(rng, rng.randint(5, 45), span_minutes=rng.choice([6, 12, 25]))
        )
        engine = engine_signature(run_detections(events, config))
        reference = signature(reference_alerts(events, config))
        assert engine == reference, f"seed={seed} config={config}"


def test_reference_itself_agrees_with_hand_computed_cases():
    """Guard the guard: the reference must reproduce a few answers worked out by hand."""
    assert brute_clusters([0, 60, 120, 180, 240], 5, 600) == [[0, 1, 2, 3, 4]]
    assert brute_clusters([0, 60, 120, 180, 241 + 600], 5, 600) == []
    assert brute_clusters([0, 1, 2, 12, 13, 14], 3, 10) == [[0, 1, 2], [3, 4, 5]]
    assert brute_clusters([0, 1, 2, 5, 11, 12, 13], 3, 10) == [[0, 1, 2, 3, 4, 5, 6]]
