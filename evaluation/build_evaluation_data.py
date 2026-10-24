"""Build the independent LogLens evaluation dataset and its ground truth.

Everything here is SYNTHETIC. This module is deliberately independent of LogLens:

* it imports nothing from ``loglens`` (``tests/test_evaluation.py`` enforces that);
* it does not use ``loglens/sample_data.py`` (different accounts, addresses, dates, style);
* the expected alerts are written by hand next to each case, from the rule definitions in the
  README and the original project brief (thresholds 5/10 min, 5/10 min, 15 min, 4/10 min and
  the severity table), never by running LogLens and copying what it printed.

Every case owns its accounts and IP addresses, so any alert can be attributed to exactly one
case. A case is one of:

* ``positive``    - activity the rules should flag (the expected alerts are listed);
* ``boundary``    - activity exactly on, or one step beyond, a threshold or window edge;
* ``negative``    - benign or near-miss activity that must produce no alert;
* ``limitation``  - attack-like activity the documented rules cannot see. The expected alerts
  are what the rules *should* do; ``missed_by_design`` lists what an analyst would want and
  LogLens will not report;
* ``background``  - routine traffic spread over a week, guaranteed to stay below every
  threshold (failures and denials are at least 36 minutes apart).

Regenerate with ``python -m evaluation.build_evaluation_data``; the output is deterministic.
"""

from __future__ import annotations

import csv
import ipaddress
import itertools
import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSV_PATH = HERE / "eval_logs_synthetic.csv"
TRUTH_PATH = HERE / "eval_ground_truth.json"

SEED = 20260609
WEEK_START = datetime(2026, 6, 8, 0, 0, tzinfo=UTC)  # a Monday
COLUMNS = ("timestamp", "source_ip", "username", "event_type", "outcome", "host", "message")

# Documented rule parameters (README, "How the detections work"). Used only to document the
# reasoning in this file; the expected values below are written out literally.
#   LL-001 / LL-002: 5 failures in 10 min   LL-003: success <= 15 min after a LL-002 burst
#   LL-004: 4 denials in 10 min             severity +1 level at >= 3x the threshold

_SURNAMES = (
    "abara", "bergstrom", "castellano", "dvorak", "eriksen", "fontaine", "grigoryan", "haldane",
    "ibarra", "jovanovic", "kowalczyk", "lindqvist", "moreau", "nakagawa", "okafor", "pellegrini",
    "quintero", "rasmussen", "sandoval", "takahashi", "ulloa", "varga", "wojcik", "xiong",
    "yilmaz", "zielinski", "andrade", "brennan", "cardoso", "delacroix", "espinoza", "forsberg",
)  # fmt: skip
_INITIALS = "abcdefghijklmnoprstvw"


def normalise_user(name: str) -> str:
    return name.strip().lower()


def normalise_ip(text: str) -> str:
    address = ipaddress.ip_address(text.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


class Actors:
    """Hands out fictitious accounts and documentation-range addresses; never repeats one."""

    def __init__(self) -> None:
        names = [f"{i}{s}" for s, i in itertools.product(_SURNAMES, _INITIALS)]
        random.Random(SEED).shuffle(names)
        self._names = iter(names)
        self._next_ip = 10

    def user(self) -> str:
        return next(self._names)

    def users(self, count: int) -> list[str]:
        return [self.user() for _ in range(count)]

    def ip(self) -> str:
        address = f"198.51.100.{self._next_ip}"  # RFC 5737 TEST-NET-2
        self._next_ip += 1
        assert self._next_ip < 255, "ran out of documentation addresses"
        return address

    def ips(self, count: int) -> list[str]:
        return [self.ip() for _ in range(count)]


def render_time(moment: datetime, style: str) -> str:
    """Write a UTC instant as text: ``z`` (Zulu), ``naive`` (no offset) or ``+hh:mm``/``-hh:mm``."""
    if style in ("z", "naive"):
        text = moment.strftime("%Y-%m-%dT%H:%M:%S")
        if moment.microsecond:
            text += f".{moment.microsecond // 1000:03d}"
        return text + ("Z" if style == "z" else "")
    sign = 1 if style[0] == "+" else -1
    hours, minutes = style[1:].split(":")
    zone = timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))
    return moment.astimezone(zone).isoformat()


@dataclass
class Case:
    case_id: str
    kind: str
    title: str
    why: str
    start: datetime
    duplicates_matter: bool = False
    rows: list[dict[str, str]] = field(default_factory=list)
    users: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    expected: list[dict[str, object]] = field(default_factory=list)
    missed: list[dict[str, str]] = field(default_factory=list)

    def event(
        self,
        seconds: float,
        ip: str,
        user: str,
        event_type: str,
        outcome: str,
        *,
        host: str = "auth-01",
        message: str = "",
        style: str = "z",
    ) -> None:
        moment = self.start + timedelta(seconds=seconds)
        self.rows.append(
            {
                "timestamp": render_time(moment, style),
                "source_ip": ip,
                "username": user,
                "event_type": event_type,
                "outcome": outcome,
                "host": host,
                "message": message,
            }
        )
        self.users.add(normalise_user(user))
        self.ips.add(normalise_ip(ip))

    def fail(self, seconds, ip, user, message="Invalid password", **kw) -> None:
        self.event(seconds, ip, user, "login", "failure", message=message, **kw)

    def ok(self, seconds, ip, user, message="Login accepted", **kw) -> None:
        self.event(seconds, ip, user, "login", "success", message=message, **kw)

    def deny(self, seconds, ip, user, message="Access denied: /finance/payroll", **kw) -> None:
        self.event(
            seconds, ip, user, kw.pop("event_type", "access"), "denied", message=message, **kw
        )

    def expect(self, rule: str, entity: str, severity: str, events: int) -> None:
        """One alert the rules should raise. ``entity`` is the IP for LL-001, else the account."""
        self.expected.append(
            {"rule": rule, "entity": entity, "severity": severity, "events": events}
        )

    def miss(self, rule: str, entity: str, why: str) -> None:
        self.missed.append({"rule": rule, "entity": entity, "why": why})


class Builder:
    def __init__(self) -> None:
        self.actors = Actors()
        self.cases: list[Case] = []

    def case(
        self,
        case_id: str,
        kind: str,
        title: str,
        why: str,
        *,
        start: datetime | None = None,
        duplicates_matter: bool = False,
    ) -> Case:
        # Each case gets its own three-hour slot of the week, so cases never overlap in time.
        slot = WEEK_START + timedelta(hours=3 * len(self.cases) + 3)
        case = Case(case_id, kind, title, why, start or slot, duplicates_matter)
        self.cases.append(case)
        return case


# --------------------------------------------------------------------------------------
# The cases
# --------------------------------------------------------------------------------------


def define_cases(b: Builder) -> None:
    a = b.actors

    # ---------------- positives ----------------
    c = b.case(
        "P01",
        "positive",
        "Password spraying, window exactly 10:00",
        "5 failures from one IP spanning exactly 600 s: windows are inclusive, so LL-001 "
        "fires. Each account fails once, so LL-002 must not.",
    )
    ip, users = a.ip(), a.users(5)
    for k, user in enumerate(users):
        c.fail(150 * k, ip, user)
    c.expect("LL-001", ip, "medium", 5)

    c = b.case(
        "P02",
        "positive",
        "One IP hammering one account",
        "6 failures in 3 minutes from one IP against one account satisfies both LL-001 "
        "and LL-002; each rule reports one alert.",
    )
    ip, user = a.ip(), a.user()
    for k in range(6):
        c.fail(36 * k, ip, user)
    c.expect("LL-001", ip, "medium", 6)
    c.expect("LL-002", user, "medium", 6)

    c = b.case(
        "P03",
        "positive",
        "One account, five source IPs",
        "5 failures against one account from 5 different IPs in 6 minutes: LL-002 only; "
        "no single IP reaches 5.",
    )
    ips, user = a.ips(5), a.user()
    for k, ip in enumerate(ips):
        c.fail(90 * k, ip, user)
    c.expect("LL-002", user, "medium", 5)

    c = b.case(
        "P04",
        "positive",
        "High-volume spray escalates severity",
        "15 failures (one per account) from one IP in 9m20s: 15 = 3 x threshold, so "
        "LL-001 is raised from medium to high.",
    )
    ip, users = a.ip(), a.users(15)
    for k, user in enumerate(users):
        c.fail(40 * k, ip, user)
    c.expect("LL-001", ip, "high", 15)

    c = b.case(
        "P05",
        "positive",
        "Sustained attack is ONE alert per rule",
        "40 failures, one every 90 s for 58 minutes, from one IP against one account. "
        "Overlapping windows must merge into a single cluster per rule, not 36 alerts.",
    )
    ip, user = a.ip(), a.user()
    for k in range(40):
        c.fail(90 * k, ip, user)
    c.expect("LL-001", ip, "high", 40)
    c.expect("LL-002", user, "high", 40)

    c = b.case(
        "P06",
        "positive",
        "Two bursts 36 minutes apart are two alerts",
        "5 failures, then 5 more starting 36 minutes after the first burst ended "
        "(window is 10 min): separate clusters, so two alerts per rule.",
    )
    ip, user = a.ip(), a.user()
    for k in range(5):
        c.fail(60 * k, ip, user)
    for k in range(5):
        c.fail(2400 + 60 * k, ip, user)
    for rule, entity in (("LL-001", ip), ("LL-002", user)):
        c.expect(rule, entity, "medium", 5)
        c.expect(rule, entity, "medium", 5)

    c = b.case(
        "P07",
        "positive",
        "Failures from 3 IPs, success from a new IP",
        "6 failures against one account (2 from each of 3 IPs) then a success 4 minutes "
        "later from a fourth IP: LL-002, and LL-003 (high) with 6 failures + 1 success.",
    )
    ips, user, new_ip = a.ips(3), a.user(), a.ip()
    for k in range(6):
        c.fail(60 * k, ips[k % 3], user)
    c.ok(540, new_ip, user)
    c.expect("LL-002", user, "medium", 6)
    c.expect("LL-003", user, "high", 7)

    c = b.case(
        "P08",
        "positive",
        "Large burst then success: critical",
        "16 failures (4 from each of 4 IPs) then a success: LL-002 high (16 >= 15) and "
        "LL-003 raised from high to critical (16 failures >= 15).",
    )
    ips, user, new_ip = a.ips(4), a.user(), a.ip()
    for k in range(16):
        c.fail(30 * k, ips[k % 4], user)
    c.ok(570, new_ip, user)
    c.expect("LL-002", user, "high", 16)
    c.expect("LL-003", user, "critical", 17)

    c = b.case(
        "P09",
        "positive",
        "Four denials, window exactly 10:00",
        "4 access denials spanning exactly 600 s: LL-004 fires (inclusive window).",
    )
    ip, user = a.ip(), a.user()
    for k in range(4):
        c.deny(200 * k, ip, user)
    c.expect("LL-004", user, "low", 4)

    c = b.case(
        "P10",
        "positive",
        "Denied password changes count as denials",
        "LL-004 counts every event with outcome 'denied', not only event_type 'access': "
        "the brief defines the outcome vocabulary as success / failure / denial.",
    )
    ip, user = a.ip(), a.user()
    for k in range(4):
        c.deny(45 * k, ip, user, "Password change refused by policy", event_type="password_change")
    c.expect("LL-004", user, "low", 4)

    c = b.case(
        "P11",
        "positive",
        "Twelve denials escalate LL-004",
        "12 denials = 3 x the threshold of 4: severity low -> medium.",
    )
    ip, user = a.ip(), a.user()
    for k in range(12):
        c.deny(40 * k, ip, user)
    c.expect("LL-004", user, "medium", 12)

    c = b.case(
        "P12",
        "positive",
        "Mixed time-zone offsets",
        "5 failures within 8 UTC minutes, written with five different UTC offsets. The "
        "local clock readings span 20 hours, so only correct UTC conversion detects it.",
    )
    ip, users = a.ip(), a.users(5)
    for k, (user, style) in enumerate(
        zip(users, ("+05:30", "-07:00", "z", "+13:00", "-03:30"), strict=True)
    ):
        c.fail(120 * k, ip, user, style=style)
    c.expect("LL-001", ip, "medium", 5)

    c = b.case(
        "P13",
        "positive",
        "Account name case and padding",
        "5 failures against 'Xxxx', 'xxxx' and padded variants from 5 IPs: one account.",
    )
    ips, user = a.ips(5), a.user()
    for k, (ip, variant) in enumerate(
        zip(ips, (user.title(), user, f"  {user.upper()} ", user, user.capitalize()), strict=True)
    ):
        c.fail(60 * k, ip, variant)
    c.expect("LL-002", user, "medium", 5)

    c = b.case(
        "P14",
        "positive",
        "One IPv6 host written two ways",
        "5 failures from 2001:db8:e1::17, spelled compressed and fully expanded in "
        "upper case: one source address.",
    )
    users = a.users(5)
    spellings = ("2001:db8:e1::17", "2001:0DB8:00E1:0000:0000:0000:0000:0017") * 3
    for k, user in enumerate(users):
        c.fail(60 * k, spellings[k], user)
    c.expect("LL-001", "2001:db8:e1::17", "medium", 5)

    c = b.case(
        "P15",
        "positive",
        "IPv4 and IPv4-mapped IPv6 are one host",
        "3 failures from 198.51.100.x and 2 from ::ffff:198.51.100.x: one source.",
    )
    ip, users = a.ip(), a.users(5)
    for k, user in enumerate(users):
        c.fail(60 * k, ip if k < 3 else f"::ffff:{ip}", user)
    c.expect("LL-001", ip, "medium", 5)

    c = b.case(
        "P16",
        "positive",
        "Six failures in the same second",
        "Identical timestamps, different messages: all six count (windows use real "
        "time, and a zero-length span is inside any window).",
    )
    ip, user = a.ip(), a.user()
    for k in range(6):
        c.fail(0, ip, user, f"Invalid password (attempt {k + 1})")
    c.expect("LL-001", ip, "medium", 6)
    c.expect("LL-002", user, "medium", 6)

    c = b.case(
        "P17",
        "positive",
        "Two successes after one burst: one LL-003 alert",
        "5 failures, then successes 2 and 6 minutes after the last one. Successes that "
        "follow the same burst are merged: one LL-003 alert (5 failures + 2 successes).",
    )
    ips, user, new_ip = a.ips(2), a.user(), a.ip()
    for k in range(5):
        c.fail(60 * k, ips[k % 2], user)
    c.ok(360, new_ip, user)
    c.ok(600, new_ip, user)
    c.expect("LL-002", user, "medium", 5)
    c.expect("LL-003", user, "high", 7)

    c = b.case(
        "P18",
        "positive",
        "Success in the middle of an ongoing attack",
        "5 failures, a success, then 5 more failures (10 in exactly 10:00, spread over "
        "3 IPs). LL-002 sees one cluster of 10; LL-003 flags the success against the "
        "first 5 failures only (the later ones came after it).",
    )
    ips, user, new_ip = a.ips(3), a.user(), a.ip()
    for k in range(5):
        c.fail(60 * k, ips[k % 3], user)
    c.ok(300, new_ip, user)
    for k in range(5):
        c.fail(360 + 60 * k, ips[(k + 5) % 3], user)
    c.expect("LL-002", user, "medium", 10)
    c.expect("LL-003", user, "high", 6)

    c = b.case(
        "P19",
        "positive",
        "Timestamps without an offset are read as UTC",
        "5 failures from one IP, timestamps written without any UTC offset.",
    )
    ip, users = a.ip(), a.users(5)
    for k, user in enumerate(users):
        c.fail(60 * k, ip, user, style="naive")
    c.expect("LL-001", ip, "medium", 5)

    c = b.case(
        "P20",
        "positive",
        "Fractional seconds",
        "5 failures within 0.8 s, timestamps with milliseconds.",
    )
    ip, users = a.ip(), a.users(5)
    for k, user in enumerate(users):
        c.fail(0.2 * k, ip, user)
    c.expect("LL-001", ip, "medium", 5)

    c = b.case(
        "P21",
        "positive",
        "Scripted guessing logged at one-second resolution",
        "10 identical failure rows (5 per second for 2 s). They are genuinely 10 "
        "attempts, but they are exact duplicates once the timestamp is rounded to the "
        "second. Detected only if exact duplicates are kept.",
        duplicates_matter=True,
    )
    ip, user = a.ip(), a.user()
    for second in (0, 1):
        for _ in range(5):
            c.fail(second, ip, user)
    c.expect("LL-001", ip, "medium", 10)
    c.expect("LL-002", user, "medium", 10)

    c = b.case(
        "P22",
        "positive",
        "Denied logins are LL-004, not LL-001/LL-002",
        "5 login events with outcome 'denied' (for example account locked): they are "
        "denials, not 'failed logins', so only LL-004 fires.",
    )
    ip, user = a.ip(), a.user()
    for k in range(5):
        c.deny(48 * k, ip, user, "Account locked", event_type="login")
    c.expect("LL-004", user, "low", 5)

    c = b.case(
        "P23",
        "positive",
        "Burst across UTC midnight",
        "6 failures from 23:57:00 to 00:02:00 UTC: the day boundary must not split it.",
        start=datetime(2026, 6, 12, 23, 57, tzinfo=UTC),
    )
    ip, user = a.ip(), a.user()
    for k in range(6):
        c.fail(60 * k, ip, user)
    c.expect("LL-001", ip, "medium", 6)
    c.expect("LL-002", user, "medium", 6)

    # ---------------- boundaries ----------------
    c = b.case(
        "B01",
        "boundary",
        "Success exactly 15:00 after the burst",
        "5 failures ending at 4:00, a success at 19:00: gap of exactly 900 s, inclusive.",
    )
    ips, user, new_ip = a.ips(2), a.user(), a.ip()
    for k in range(5):
        c.fail(60 * k, ips[k % 2], user)
    c.ok(240 + 900, new_ip, user)
    c.expect("LL-002", user, "medium", 5)
    c.expect("LL-003", user, "high", 6)

    c = b.case(
        "B02",
        "boundary",
        "Success 15:01 after the burst",
        "Same as B01 but one second later: outside the investigation window, so only LL-002 fires.",
    )
    ips, user, new_ip = a.ips(2), a.user(), a.ip()
    for k in range(5):
        c.fail(60 * k, ips[k % 2], user)
    c.ok(240 + 901, new_ip, user)
    c.expect("LL-002", user, "medium", 5)

    c = b.case(
        "B03",
        "boundary",
        "Failure and success in the same second",
        "4 failures, then a 5th failure and a success both at 4:00. A failure logged in "
        "the same second as the success is not assumed to precede it, so the burst is "
        "not 'qualifying' yet and LL-003 stays silent (documented design decision).",
    )
    ips, user, new_ip = a.ips(2), a.user(), a.ip()
    for k in range(5):
        c.fail(60 * k, ips[k % 2], user)
    c.ok(240, new_ip, user)
    c.expect("LL-002", user, "medium", 5)

    c = b.case(
        "B04",
        "boundary",
        "Success BEFORE the failures",
        "A success at 0:00 and 5 failures afterwards: a success cannot 'follow' failures "
        "that have not happened yet. LL-002 only.",
    )
    ips, user, new_ip = a.ips(2), a.user(), a.ip()
    c.ok(0, new_ip, user)
    for k in range(5):
        c.fail(120 + 60 * k, ips[k % 2], user)
    c.expect("LL-002", user, "medium", 5)

    # ---------------- negatives ----------------
    c = b.case("N01", "negative", "Four failures from one IP", "One below the LL-001 threshold.")
    ip, users = a.ip(), a.users(4)
    for k, user in enumerate(users):
        c.fail(40 * k, ip, user)

    c = b.case(
        "N02",
        "negative",
        "Five failures spanning 10:01 (one IP)",
        "The 5th failure is 601 s after the first: outside the 10-minute window.",
    )
    ip, users = a.ip(), a.users(5)
    for k, user in enumerate(users):
        c.fail([0, 150, 300, 450, 601][k], ip, user)

    c = b.case(
        "N03",
        "negative",
        "Five failures spanning 10:01 (one account)",
        "Same, but against one account from five IPs.",
    )
    ips, user = a.ips(5), a.user()
    for k, ip in enumerate(ips):
        c.fail([0, 150, 300, 450, 601][k], ip, user)

    c = b.case(
        "N04",
        "negative",
        "Three denials; four denials spanning 10:01",
        "Below the LL-004 threshold, and just outside its window.",
    )
    ip, first, second = a.ip(), a.user(), a.user()
    for k in range(3):
        c.deny(60 * k, ip, first)
    for offset in (0, 200, 400, 601):
        c.deny(offset, ip, second)

    c = b.case(
        "N05",
        "negative",
        "Success after only four failures",
        "No qualifying burst (4 < 5), so a following success is not suspicious.",
    )
    ips, user, new_ip = a.ips(2), a.user(), a.ip()
    for k in range(4):
        c.fail(60 * k, ips[k % 2], user)
    c.ok(240, new_ip, user)

    c = b.case(
        "N06",
        "negative",
        "Morning rush: 30 accounts log in within 3 minutes",
        "High volume of successes from one office IP is normal.",
    )
    ip, users = a.ip(), a.users(30)
    for k, user in enumerate(users):
        c.ok(6 * k, ip, user)

    c = b.case(
        "N07",
        "negative",
        "Nightly batch job: 60 successful accesses in 5 minutes",
        "A service account reading many resources; all successes.",
    )
    ip, user = a.ip(), a.user()
    for k in range(60):
        c.event(5 * k, ip, user, "access", "success", host="etl-01", message="Read dataset")

    c = b.case(
        "N08",
        "negative",
        "Shared NAT address, slow trickle of mistakes",
        "8 colleagues behind one IP mistype a password once each, 20 minutes apart.",
    )
    ip, users = a.ip(), a.users(8)
    for k, user in enumerate(users):
        c.fail(1200 * k, ip, user)

    c = b.case(
        "N09",
        "negative",
        "Typo, typo, typo, success",
        "A user fails 3 times and then logs in: the everyday pattern LL-003 must not "
        "flag (below the burst threshold).",
    )
    ip, user = a.ip(), a.user()
    for k in range(3):
        c.fail(20 * k, ip, user)
    c.ok(100, ip, user)

    c = b.case(
        "N10",
        "negative",
        "Five failures, five IPs, five accounts",
        "Five failures in 4 minutes, but no IP and no account has more than one.",
    )
    ips, users = a.ips(5), a.users(5)
    for k in range(5):
        c.fail(60 * k, ips[k], users[k])

    c = b.case(
        "N11",
        "negative",
        "Six denials spread over three accounts",
        "Two denials per account is below the per-account threshold.",
    )
    ip, users = a.ip(), a.users(3)
    for k in range(6):
        c.deny(50 * k, ip, users[k % 3])

    c = b.case(
        "N12",
        "negative",
        "Logouts and successful password changes",
        "Routine account maintenance events: no failures, no denials.",
    )
    ip, user = a.ip(), a.user()
    for k in range(10):
        c.event(30 * k, ip, user, "logout", "success")
        c.event(30 * k + 10, ip, user, "password_change", "success")

    c = b.case(
        "N13",
        "negative",
        "Intermittent failures, 6 minutes apart",
        "Failure / success alternating every 3 minutes: 5 failures take 24 minutes, "
        "far outside the 10-minute window.",
    )
    ip, user = a.ip(), a.user()
    for k in range(5):
        c.fail(360 * k, ip, user)
        c.ok(360 * k + 180, ip, user)

    c = b.case(
        "N14",
        "negative",
        "Replayed log lines (each failure shipped twice)",
        "3 genuine failures, each appearing twice because a log forwarder retried. If "
        "exact duplicates are kept the account looks like it has 6 failures.",
        duplicates_matter=True,
    )
    ip, user = a.ip(), a.user()
    for k in range(3):
        c.fail(60 * k, ip, user)
        c.fail(60 * k, ip, user)

    # ---------------- limitations (documented blind spots) ----------------
    c = b.case(
        "K01",
        "limitation",
        "Low and slow guessing",
        "40 failures against one account over two hours, one every 3 minutes. No "
        "10-minute window holds more than 4, so nothing fires. Fixed thresholds cannot "
        "see this.",
    )
    ip, user = a.ip(), a.user()
    for k in range(40):
        c.fail(180 * k, ip, user)
    c.miss("LL-001", ip, "never 5 failures within 10 minutes")
    c.miss("LL-002", user, "never 5 failures within 10 minutes")

    c = b.case(
        "K02",
        "limitation",
        "Distributed spray: 40 IPs x 40 accounts",
        "40 failures in 10 minutes, but every IP and every account appears once. Each "
        "rule groups by one key, so none sees the campaign.",
    )
    ips, users = a.ips(40), a.users(40)
    for k in range(40):
        c.fail(15 * k, ips[k], users[k])
    c.miss("(none)", "-", "no single IP or account has more than one failure")

    c = b.case(
        "K03",
        "limitation",
        "One identity written three ways",
        "6 failures against corp\\x, x@example.test and x (2 each). LogLens treats them "
        "as three accounts, so no burst reaches 5.",
    )
    ips, user = a.ips(6), a.user()
    variants = (f"corp\\{user}", f"{user}@example.test", user)
    for k, ip in enumerate(ips):
        c.fail(45 * k, ip, variants[k % 3])
    c.miss("LL-002", user, "account-name variants are different accounts to LogLens")

    c = b.case(
        "K04",
        "limitation",
        "Password spray, then a success from the same IP",
        "8 accounts fail once each from one IP (LL-001 fires), then one of them "
        "succeeds from that IP. LL-003 needs 5 failures against the SAME account, so "
        "the success is not linked to the spray.",
    )
    ip, users = a.ip(), a.users(8)
    for k, user in enumerate(users):
        c.fail(30 * k, ip, user)
    c.ok(330, ip, users[0])
    c.expect("LL-001", ip, "medium", 8)
    c.miss("LL-003", users[0], "LL-003 correlates per account; the spray is per IP")


# --------------------------------------------------------------------------------------
# Background traffic: a week of routine events that cannot reach any threshold
# --------------------------------------------------------------------------------------


def background(b: Builder) -> Case:
    rng = random.Random(SEED + 1)
    case = Case(
        "BG",
        "background",
        "A week of routine traffic (30 accounts)",
        "About 1,000 successful logins/accesses, plus single failures at least 36 minutes "
        "apart and single denials at least 53 minutes apart. By construction no rule applies.",
        WEEK_START,
    )
    users = b.actors.users(30)
    pool = b.actors.ips(12)
    home = {user: pool[i % len(pool)] for i, user in enumerate(users)}
    week = 7 * 24 * 3600
    for user in users:
        for day in range(7):
            for _ in range(rng.randint(3, 6)):
                second = day * 86400 + rng.randint(7 * 3600, 19 * 3600)
                kind = rng.choice(("login", "login", "access", "access", "logout"))
                case.event(second, home[user], user, kind, "success", host="sso-01")
    for second in range(0, week, 41 * 60):  # one failure every 41 minutes (+ up to 5 minutes)
        user = rng.choice(users)
        case.fail(second + rng.randint(0, 300), home[user], user)
    for second in range(0, week, 53 * 60):
        user = rng.choice(users)
        case.deny(second + rng.randint(0, 300), home[user], user)
    return case


# --------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------


def build() -> tuple[list[dict[str, str]], dict[str, object]]:
    """Return the shuffled CSV rows and the ground-truth description."""
    builder = Builder()
    define_cases(builder)
    cases = [*builder.cases, background(builder)]

    seen_users: dict[str, str] = {}
    seen_ips: dict[str, str] = {}
    for case in cases:  # every entity must belong to exactly one case
        for user in case.users:
            assert seen_users.setdefault(user, case.case_id) == case.case_id, (user, case.case_id)
        for address in case.ips:
            assert seen_ips.setdefault(address, case.case_id) == case.case_id, (address, case)

    rows = [row for case in cases for row in case.rows]
    random.Random(SEED + 2).shuffle(rows)  # the file is not in chronological order

    truth = {
        "description": "Independent synthetic evaluation set for LogLens. All data is made up.",
        "seed": SEED,
        "total_rows": len(rows),
        "cases": [
            {
                "id": case.case_id,
                "kind": case.kind,
                "title": case.title,
                "why": case.why,
                "duplicates_matter": case.duplicates_matter,
                "rows": len(case.rows),
                "users": sorted(case.users),
                "ips": sorted(case.ips),
                "expected_alerts": case.expected,
                "missed_by_design": case.missed,
            }
            for case in cases
        ],
    }
    return rows, truth


def write_files() -> None:
    rows, truth = build()
    with CSV_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    TRUTH_PATH.write_text(json.dumps(truth, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    write_files()
    print(f"wrote {CSV_PATH.name} and {TRUTH_PATH.name}")
