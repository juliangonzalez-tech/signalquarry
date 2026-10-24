"""The detection rules.

Each rule is a plain function ``(events, config) -> list[Alert]`` and is registered in
``RULES``. To add a rule: write the function, describe it with a ``RuleInfo`` and append it to
``RULES`` / ``RULE_CATALOG`` - the engine, dashboard and exports pick it up automatically.

Event semantics (see ``loglens.schema``):
  failed login          = event_type "login" and outcome "failure"
  successful login      = event_type "login" and outcome "success"
  authorization denial  = ANY event_type with outcome "denied" (access, password_change, ...)

Rules read the events as a *set*: they sort by timestamp themselves, so the order of rows in
the uploaded file never affects the result.
"""

from __future__ import annotations

from collections.abc import Callable

import numpy as np
import pandas as pd

from ..schema import DENIED, FAILURE, LOGIN, SUCCESS
from .config import DetectionConfig
from .models import Alert, RuleInfo, escalate, limited_join
from .windows import chain_ends, find_clusters, qualifying_window_ends

RuleFunction = Callable[[pd.DataFrame, DetectionConfig], list[Alert]]

LL001 = RuleInfo(
    rule_id="LL-001",
    name="Repeated failed logins from one IP",
    base_severity="medium",
    what="Many failed logins originate from the same source IP address in a short time.",
    benign_causes=(
        "Many users behind one shared NAT, proxy or VPN address each mistyping a password.",
        "A misconfigured application or script retrying with a stale password.",
        "An internal vulnerability scanner or load test.",
    ),
)
LL002 = RuleInfo(
    rule_id="LL-002",
    name="Repeated failed logins against one account",
    base_severity="medium",
    what="Many failed logins target the same account in a short time, from any source IP.",
    benign_causes=(
        "A user locked out after forgetting or changing their password.",
        "A device or mail client still using an old saved password.",
        "A service account whose credential was rotated but not updated everywhere.",
    ),
)
LL003 = RuleInfo(
    rule_id="LL-003",
    name="Successful login after repeated failures",
    base_severity="high",
    what=(
        "A login succeeds shortly after a burst of failed logins against the same account, "
        "which can mean a guessed or stolen password worked."
    ),
    benign_causes=(
        "A user who mistyped their password several times before getting it right.",
        "A legitimate user logging in while someone else's (or a stale client's) failures "
        "hit the same account.",
    ),
)
LL004 = RuleInfo(
    rule_id="LL-004",
    name="Repeated access denials",
    base_severity="low",
    what="One account is repeatedly refused (outcome 'denied') in a short time.",
    benign_causes=(
        "A missing role or permission after a job change or new deployment.",
        "An application or script polling a resource the account was never granted.",
        "A user browsing a system where most items are restricted.",
    ),
)

RULE_CATALOG: dict[str, RuleInfo] = {r.rule_id: r for r in (LL001, LL002, LL003, LL004)}


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _select(events: pd.DataFrame, event_type: str, outcome: str) -> pd.DataFrame:
    mask = (events["event_type"] == event_type) & (events["outcome"] == outcome)
    return events.loc[mask].sort_values(["timestamp", "event_id"], kind="stable")


def _select_outcome(events: pd.DataFrame, outcome: str) -> pd.DataFrame:
    """Events of every type with the given outcome, in time order."""
    return events.loc[events["outcome"] == outcome].sort_values(
        ["timestamp", "event_id"], kind="stable"
    )


def _groups(frame: pd.DataFrame, column: str, min_size: int) -> dict[str, np.ndarray]:
    """Row positions per key, for keys with at least ``min_size`` rows. Keys in sorted order.

    ``frame`` must already be time-sorted; positions are ascending, so they stay in time order.
    Keys with fewer than ``min_size`` rows can never reach a threshold, so they are skipped up
    front: without this, a log with hundreds of thousands of distinct IPs or accounts made
    detection take minutes and gigabytes (one pandas object per key).
    """
    series = frame[column]
    # Rows whose key occurs at least ``min_size`` times. (groupby-size is linear; Series.isin
    # against a data-sized key list is not: 5 s for 300k keys on pandas 3 string columns.)
    sizes = series.groupby(series, sort=False).transform("size").to_numpy()
    positions = np.flatnonzero(sizes >= min_size)
    if len(positions) == 0:
        return {}
    subset = series.iloc[positions]
    grouped = subset.groupby(subset, sort=True).indices
    return {str(key): positions[rows] for key, rows in sorted(grouped.items())}


def _timestamps(frame: pd.DataFrame) -> np.ndarray:
    """Timestamps as UTC ``datetime64[ns]`` for fast window arithmetic."""
    series = frame["timestamp"]
    if series.dt.tz is not None:
        series = series.dt.tz_convert("UTC").dt.tz_localize(None)
    return series.to_numpy(dtype="datetime64[ns]")


def _minutes(value: int) -> np.timedelta64:
    return np.timedelta64(value, "m")


def _fmt_time(ts: pd.Timestamp) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


def _fmt_duration(start: pd.Timestamp, end: pd.Timestamp) -> str:
    seconds = int((end - start).total_seconds())
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _build_alert(
    rule: RuleInfo, evidence: pd.DataFrame, severity: str, summary: str, detail: str
) -> Alert:
    """``summary`` states what was observed; ``detail`` states the rule and its caveats."""
    # Order evidence by (timestamp, event_id). Two stable numpy sorts are ~50x cheaper than
    # DataFrame.sort_values on the many small frames a noisy log produces (one per alert).
    ids = evidence["event_id"].to_numpy(dtype=object)
    stamps = _timestamps(evidence)
    by_id = np.argsort(ids, kind="stable")
    order = by_id[np.argsort(stamps[by_id], kind="stable")]
    timestamps = evidence["timestamp"]
    return Alert(
        alert_id="",  # assigned by the engine once all alerts are collected and ordered
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=severity,
        timestamp=timestamps.iloc[order[0]],
        end_timestamp=timestamps.iloc[order[-1]],
        usernames=tuple(sorted(set(evidence["username"].tolist()))),
        source_ips=tuple(sorted(set(evidence["source_ip"].tolist()))),
        event_ids=tuple(ids[order].tolist()),
        summary=summary,
        explanation=f"{summary} {detail}",
    )


# --------------------------------------------------------------------------------------
# LL-001
# --------------------------------------------------------------------------------------


def detect_failed_logins_by_ip(events: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """LL-001: >= threshold failed logins from one source IP within the rolling window."""
    threshold = config.ip_failure_threshold
    window_minutes = config.ip_failure_window_minutes
    alerts: list[Alert] = []
    failures = _select(events, LOGIN, FAILURE)
    times = _timestamps(failures)
    for ip, rows in _groups(failures, "source_ip", threshold).items():
        for first, last in find_clusters(times[rows], threshold, _minutes(window_minutes)):
            cluster = failures.iloc[rows[first : last + 1]]
            accounts = sorted(set(cluster["username"]))
            span = _fmt_duration(cluster["timestamp"].iloc[0], cluster["timestamp"].iloc[-1])
            targets = (
                f"1 account ({accounts[0]})"
                if len(accounts) == 1
                else f"{len(accounts)} accounts ({limited_join(accounts)})"
            )
            summary = f"{len(cluster)} failed logins from {ip} within {span}, targeting {targets}."
            detail = (
                f"Rule: {threshold}+ failures from one IP within {window_minutes} min. "
                "Consistent with password guessing or spraying, but can also come from a "
                "misconfigured client or a shared NAT address."
            )
            severity = escalate(
                LL001.base_severity, len(cluster), threshold, config.escalation_factor
            )
            alerts.append(_build_alert(LL001, cluster, severity, summary, detail))
    return alerts


# --------------------------------------------------------------------------------------
# LL-002
# --------------------------------------------------------------------------------------


def detect_failed_logins_by_account(events: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """LL-002: >= threshold failed logins against one username within the rolling window."""
    threshold = config.account_failure_threshold
    window_minutes = config.account_failure_window_minutes
    alerts: list[Alert] = []
    failures = _select(events, LOGIN, FAILURE)
    times = _timestamps(failures)
    for username, rows in _groups(failures, "username", threshold).items():
        for first, last in find_clusters(times[rows], threshold, _minutes(window_minutes)):
            cluster = failures.iloc[rows[first : last + 1]]
            ips = sorted(set(cluster["source_ip"]))
            span = _fmt_duration(cluster["timestamp"].iloc[0], cluster["timestamp"].iloc[-1])
            origin = ips[0] if len(ips) == 1 else f"{len(ips)} different source IPs"
            summary = (
                f"{len(cluster)} failed logins against '{username}' within {span}, from {origin}."
            )
            detail = (
                f"Rule: {threshold}+ failures per account within {window_minutes} min. "
                "Consistent with password guessing or credential stuffing, but can also be a "
                "locked-out user or a stale saved password."
            )
            severity = escalate(
                LL002.base_severity, len(cluster), threshold, config.escalation_factor
            )
            alerts.append(_build_alert(LL002, cluster, severity, summary, detail))
    return alerts


# --------------------------------------------------------------------------------------
# LL-003
# --------------------------------------------------------------------------------------


def detect_success_after_failures(events: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """LL-003: a successful login shortly after a qualifying failure burst for the same account.

    Correlation key: the **username** (failures from any source IP count). For a successful
    login at time ``s`` the candidates are that account's failed logins strictly before ``s``.
    A *qualifying burst* is a cluster of them as defined for LL-002 (``threshold`` failures
    within the account window, overlapping windows merged). The success is flagged when a
    burst's **last failure** is at most ``success_investigation_minutes`` before ``s``: the
    investigation window runs from the end of the burst, so it does not shrink as the burst
    gets longer.

    Evidence is every burst that ended inside that window, plus the success. Successes that
    follow the same burst are merged into one alert.

    Runs in O(F log F + S log F) per account (F failures, S successes) by locating bursts once
    and then only binary-searching for each success.
    """
    threshold = config.account_failure_threshold
    burst_window = _minutes(config.account_failure_window_minutes)
    investigation = _minutes(config.success_investigation_minutes)

    failures = _select(events, LOGIN, FAILURE)
    failure_groups = _groups(failures, "username", threshold)  # no burst without enough failures
    if not failure_groups:
        return []
    successes = _select(events, LOGIN, SUCCESS)
    with_failures = set(failure_groups)
    # A boolean ndarray (not a list: ``df[[]]`` would select zero COLUMNS, not zero rows).
    keep = np.fromiter(
        (name in with_failures for name in successes["username"].tolist()),
        dtype=bool,
        count=len(successes),
    )
    successes = successes.loc[keep]
    success_groups = _groups(successes, "username", 1)
    all_failure_times = _timestamps(failures)
    all_success_times = _timestamps(successes)
    alerts: list[Alert] = []

    for username, failure_rows in failure_groups.items():
        success_rows = success_groups.get(username)
        if success_rows is None:
            continue
        failure_times = all_failure_times[failure_rows]
        success_times = all_success_times[success_rows]

        ends = qualifying_window_ends(failure_times, threshold, burst_window)
        if len(ends) == 0:
            continue
        bursts = chain_ends(ends, threshold)  # (first_event, last_event, first_pos, stop_pos)
        burst_of_end = np.repeat(np.arange(len(bursts)), [b[3] - b[2] for b in bursts])
        # For each success: how many failures precede it strictly, and how many qualifying
        # window ends are among them (those ends are all ``< before``).
        before = np.searchsorted(failure_times, success_times, side="left")
        usable = np.searchsorted(ends, before, side="left")

        groups: list[tuple[dict[int, int], list[int]]] = []  # (burst -> last usable end, successes)
        for success_pos, usable_ends in enumerate(usable):
            if usable_ends == 0:
                continue
            hits: dict[int, int] = {}
            burst = int(burst_of_end[usable_ends - 1])
            while burst >= 0:
                last_end = min(bursts[burst][3], int(usable_ends)) - 1
                if success_times[success_pos] - failure_times[ends[last_end]] > investigation:
                    break  # older bursts ended even earlier
                hits[burst] = last_end
                burst -= 1
            if not hits:
                continue
            if groups and groups[-1][0].keys() & hits.keys():
                for burst_id, last_end in hits.items():
                    groups[-1][0][burst_id] = max(groups[-1][0].get(burst_id, last_end), last_end)
                groups[-1][1].append(success_pos)
            else:
                groups.append((hits, [success_pos]))

        for hits, success_positions in groups:
            failed_positions = np.concatenate(
                [
                    np.arange(bursts[b][0], ends[last_end] + 1)
                    for b, last_end in sorted(hits.items())
                ]
            )
            failed = failures.iloc[failure_rows[failed_positions]]
            succeeded = successes.iloc[success_rows[success_positions]]
            alerts.append(_success_after_failures_alert(username, failed, succeeded, config))
    return alerts


def _success_after_failures_alert(
    username: str, failed: pd.DataFrame, succeeded: pd.DataFrame, config: DetectionConfig
) -> Alert:
    failure_ips = set(failed["source_ip"])
    success_ips = set(succeeded["source_ip"])
    if success_ips <= failure_ips:
        origin = "from an IP that also produced failures"
    elif success_ips & failure_ips:
        origin = "partly from IPs that also produced failures"
    else:
        origin = "from a different IP than the failures"

    first_success = succeeded.iloc[0]
    last_failure = failed.loc[failed["timestamp"] < first_success["timestamp"], "timestamp"].max()
    gap = _fmt_duration(last_failure, first_success["timestamp"])
    extra = len(succeeded) - 1
    success_text = f"A successful login for '{username}' at {_fmt_time(first_success['timestamp'])}"
    if extra:
        success_text += f" (plus {_plural(extra, 'more success')})"
    summary = (
        f"{success_text} came {gap} after the last of {len(failed)} failed attempts from "
        f"{_plural(len(failure_ips), 'source IP')}; the success came {origin}."
    )
    detail = (
        f"Rule: a burst of {config.account_failure_threshold}+ failures within "
        f"{config.account_failure_window_minutes} min, then a success within "
        f"{config.success_investigation_minutes} min of the burst's last failure. Consistent "
        "with a guessed or stolen password, but can also be a user who mistyped repeatedly."
    )
    severity = escalate(
        LL003.base_severity, len(failed), config.account_failure_threshold, config.escalation_factor
    )
    return _build_alert(LL003, pd.concat([failed, succeeded]), severity, summary, detail)


# --------------------------------------------------------------------------------------
# LL-004
# --------------------------------------------------------------------------------------


def detect_access_denials(events: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """LL-004: >= threshold authorization denials for one username within the rolling window.

    A denial is any event whose outcome is "denied", whatever its event type.
    """
    threshold = config.denial_threshold
    window_minutes = config.denial_window_minutes
    alerts: list[Alert] = []
    denials = _select_outcome(events, DENIED)
    times = _timestamps(denials)
    for username, rows in _groups(denials, "username", threshold).items():
        for first, last in find_clusters(times[rows], threshold, _minutes(window_minutes)):
            cluster = denials.iloc[rows[first : last + 1]]
            span = _fmt_duration(cluster["timestamp"].iloc[0], cluster["timestamp"].iloc[-1])
            summary = f"{len(cluster)} authorization denials for '{username}' within {span}."
            detail = (
                f"Rule: {threshold}+ events with outcome 'denied' per account within "
                f"{window_minutes} min. "
                "Consistent with probing for resources outside the account's permissions, but "
                "often caused by a missing role or a misconfigured application."
            )
            severity = escalate(
                LL004.base_severity, len(cluster), threshold, config.escalation_factor
            )
            alerts.append(_build_alert(LL004, cluster, severity, summary, detail))
    return alerts


RULES: tuple[RuleFunction, ...] = (
    detect_failed_logins_by_ip,
    detect_failed_logins_by_account,
    detect_success_after_failures,
    detect_access_denials,
)


def describe_rules(config: DetectionConfig) -> list[dict[str, object]]:
    """Rule descriptions with the *current* thresholds filled in, for the in-app guide."""
    return [
        {
            "rule": LL001,
            "trigger": f"{config.ip_failure_threshold}+ failed logins from the same source IP "
            f"within {config.ip_failure_window_minutes} minutes.",
        },
        {
            "rule": LL002,
            "trigger": f"{config.account_failure_threshold}+ failed logins against the same "
            f"username within {config.account_failure_window_minutes} minutes, from any IP.",
        },
        {
            "rule": LL003,
            "trigger": "A successful login within "
            f"{config.success_investigation_minutes} minutes after the last failure of a "
            f"qualifying LL-002 burst ({config.account_failure_threshold}+ failures within "
            f"{config.account_failure_window_minutes} minutes) against the same username.",
        },
        {
            "rule": LL004,
            "trigger": f"{config.denial_threshold}+ events with outcome 'denied' (any event type) "
            f"for the same username within {config.denial_window_minutes} minutes.",
        },
    ]
