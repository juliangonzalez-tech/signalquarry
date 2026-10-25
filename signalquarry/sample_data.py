"""Deterministic generator for the bundled SYNTHETIC demo dataset.

Everything produced here is made up: fictitious usernames, IP addresses from the
documentation ranges reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
RFC 3849 (2001:db8::/32), and no credentials of any kind. None of it is a real incident.

The dataset mixes ordinary activity with six scripted suspicious scenarios (S1-S6) and several
benign high-activity situations (B1-B5) that must NOT raise alerts. ``EXPECTED_ALERTS`` is the
ground truth for the default detection settings; the test-suite checks the engine against it.

Regenerate the bundled file with:  python -m signalquarry.sample_data
"""

from __future__ import annotations

import csv
import io
import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .schema import CANONICAL_COLUMNS

SEED = 20260302
START = datetime(2026, 3, 2, tzinfo=UTC)  # a Monday
DAYS = 3
SAMPLE_FILENAME = "sample_logs_synthetic.csv"
SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / SAMPLE_FILENAME

# fmt: off
REGULAR_USERS = (
    "alice.morgan", "ben.carter", "chloe.nguyen", "dan.okafor", "emma.larsen", "farid.haddad",
    "grace.liu", "hector.silva", "irene.kowalski", "jonas.weber", "kara.singh", "liam.oconnor",
    "marcus.lee", "nina.petrov", "omar.said", "priya.raman", "quinn.davies", "rosa.mendes",
    "sam.fischer", "tara.brooks", "uma.patel", "victor.cho", "dana.whitfield", "tom.becker",
)
# Only these accounts get random one-off failures/denials, so scripted scenarios stay exact.
NOISY_USERS = (
    "alice.morgan", "rosa.mendes", "sam.fischer", "tara.brooks", "uma.patel", "victor.cho",
    "tom.becker",
)
SPRAY_TARGETS = (
    "chloe.nguyen", "dan.okafor", "farid.haddad", "grace.liu",
    "hector.silva", "irene.kowalski", "jonas.weber", "kara.singh",
)
OFFICE_NAT_USERS = ("liam.oconnor", "nina.petrov", "omar.said", "quinn.davies")
ACCESS_HOSTS = ("file-srv-01", "web-app-01", "hr-portal-01", "db-admin-01")
RESOURCES = (
    "reports/q1-summary.pdf", "wiki/onboarding", "crm/accounts", "shared/design-assets",
    "tickets/queue", "finance/forecast.xlsx", "hr/policies", "dashboards/sales",
)
RESTRICTED_RESOURCES = (
    "finance/payroll.xlsx", "hr/personnel-files", "admin/user-management", "db/prod-backup",
    "security/audit-logs", "legal/contracts",
)
# fmt: on
OFFICE_NAT_IP = "192.0.2.250"
S4_IPS = ("203.0.113.60", "203.0.113.61", "203.0.113.62")


@dataclass(frozen=True)
class ExpectedAlert:
    """What the engine should raise (with default settings) for a scripted scenario."""

    scenario: str
    rule_id: str
    severity: str
    usernames: tuple[str, ...]
    source_ips: tuple[str, ...]
    event_count: int


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    when: str
    description: str
    expect: str  # human-readable expectation, used in the README


# fmt: off
SCENARIOS: tuple[Scenario, ...] = (
    Scenario("S1", "Single-source brute force", "Mon 03:12 UTC",
             "16 failed logins against svc.backup from 203.0.113.45 over ~6 minutes; no success.",
             "LL-001 (high) + LL-002 (high)"),
    Scenario("S2", "Password spraying from one IP", "Mon 14:05 UTC",
             "203.0.113.99 fails once each against 8 different accounts within ~4 minutes.",
             "LL-001 (medium) only - no single account reaches the account threshold"),
    Scenario("S3", "Distributed attempts on one account", "Tue 11:30 UTC",
             "7 failed logins against dana.whitfield, each from a different IP "
             "(198.51.100.21-27), within ~6 minutes.",
             "LL-002 (medium) only - no single IP reaches the IP threshold"),
    Scenario("S4", "Success after distributed failures", "Tue 16:20 UTC",
             "6 failures against marcus.lee from 3 IPs (203.0.113.60-62, two each), then a "
             "successful login from 203.0.113.60 four minutes later.",
             "LL-002 (medium) + LL-003 (high)"),
    Scenario("S5", "Brute force followed by success", "Wed 01:47 UTC",
             "16 failed logins against svc.reporting from 203.0.113.88, then a successful login "
             "from the same IP three minutes later.",
             "LL-001 (high) + LL-002 (high) + LL-003 (critical)"),
    Scenario("S6", "Repeated access denials", "Wed 13:15 UTC",
             "priya.raman is denied access to 6 restricted resources within ~8 minutes.",
             "LL-004 (low)"),
)

BENIGN_SCENARIOS: tuple[Scenario, ...] = (
    Scenario("B1", "Tuesday morning login surge", "Tue 09:00-09:05 UTC",
             "20 users log in successfully within five minutes.",
             "No alerts - volume without failures"),
    Scenario("B2", "Nightly ETL batch job", "02:00 UTC daily",
             "svc.etl logs in and makes 40 successful accesses within ~6 minutes, every night.",
             "No alerts - high volume, all successful"),
    Scenario("B3", "Office NAT, just under threshold", "Wed 09:20 UTC",
             "4 employees behind one shared IP (192.0.2.250) mistype passwords within 8 minutes, "
             "then log in successfully.",
             "No alerts - 4 failures is one below the IP threshold of 5"),
    Scenario("B4", "Forgotten password", "Tue 08:45 UTC",
             "ben.carter fails 3 times, then logs in successfully.",
             "No alerts - 3 failures is below the account threshold of 5"),
    Scenario("B5", "Permission misconfiguration", "Wed 11:00 UTC",
             "emma.larsen is denied access 3 times in 4 minutes.",
             "No alerts - 3 denials is below the denial threshold of 4"),
)

EXPECTED_ALERTS: tuple[ExpectedAlert, ...] = (
    ExpectedAlert("S1", "LL-001", "high", ("svc.backup",), ("203.0.113.45",), 16),
    ExpectedAlert("S1", "LL-002", "high", ("svc.backup",), ("203.0.113.45",), 16),
    ExpectedAlert("S2", "LL-001", "medium", tuple(sorted(SPRAY_TARGETS)), ("203.0.113.99",), 8),
    ExpectedAlert("S3", "LL-002", "medium", ("dana.whitfield",),
                  tuple(f"198.51.100.{n}" for n in range(21, 28)), 7),
    ExpectedAlert("S4", "LL-002", "medium", ("marcus.lee",), S4_IPS, 6),
    ExpectedAlert("S4", "LL-003", "high", ("marcus.lee",), S4_IPS, 7),
    ExpectedAlert("S5", "LL-001", "high", ("svc.reporting",), ("203.0.113.88",), 16),
    ExpectedAlert("S5", "LL-002", "high", ("svc.reporting",), ("203.0.113.88",), 16),
    ExpectedAlert("S5", "LL-003", "critical", ("svc.reporting",), ("203.0.113.88",), 17),
    ExpectedAlert("S6", "LL-004", "low", ("priya.raman",), ("192.0.2.25",), 6),
)
# fmt: on


# --------------------------------------------------------------------------------------
# Row builders - one per kind of event, so scenario code reads like a story.
# --------------------------------------------------------------------------------------

Row = dict[str, str]


def _row(ts: datetime, ip: str, user: str, kind: str, outcome: str, host: str, message: str) -> Row:
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ip": ip,
        "username": user,
        "event_type": kind,
        "outcome": outcome,
        "host": host,
        "message": message,
    }


def _login_ok(ts: datetime, ip: str, user: str, host: str, message: str | None = None) -> Row:
    return _row(
        ts, ip, user, "login", "success", host, message or "Password authentication succeeded"
    )


def _login_fail(ts: datetime, ip: str, user: str, host: str) -> Row:
    return _row(ts, ip, user, "login", "failure", host, "Invalid username or password")


def _access_ok(ts: datetime, ip: str, user: str, host: str, resource: str) -> Row:
    return _row(ts, ip, user, "access", "success", host, f"Read access granted: {resource}")


def _access_denied(ts: datetime, ip: str, user: str, host: str, resource: str) -> Row:
    return _row(ts, ip, user, "access", "denied", host, f"Access denied: {resource}")


def _at(day: int, hour: int, minute: int = 0) -> datetime:
    return START + timedelta(days=day, hours=hour, minutes=minute)


def _seconds(n: int) -> timedelta:
    return timedelta(seconds=n)


def _rng(label: str) -> random.Random:
    # String seeds are hashed with SHA-512, so each label gets its own stable random stream
    # (independent of PYTHONHASHSEED), and editing one scenario never shifts another.
    return random.Random(f"{SEED}:{label}")


def _user_ip(index: int, user: str) -> str:
    """Stable 'home' address for each regular user."""
    if user in OFFICE_NAT_USERS:
        return OFFICE_NAT_IP
    if user == "uma.patel":
        return "2001:db8::a5"  # one IPv6 user, to exercise IPv6 handling
    if index % 5 == 0:
        return f"198.51.100.{100 + index}"  # remote worker on VPN
    return f"192.0.2.{10 + index}"


# --------------------------------------------------------------------------------------
# Ordinary activity
# --------------------------------------------------------------------------------------


def _normal_activity() -> list[Row]:
    rng = _rng("normal")
    rows: list[Row] = []
    for day in range(DAYS):
        for index, user in enumerate(REGULAR_USERS):
            ip = _user_ip(index, user)
            login_host = "vpn-gw-01" if ip.startswith("198.51.100.") else "sso-01"

            login_at = _at(day, 8) + _seconds(rng.randint(0, 150 * 60))
            if day == 1 and index < 20:  # B1: Tuesday morning surge
                login_at = _at(day, 9) + _seconds(rng.randint(0, 5 * 60))
            logout_at = _at(day, 16, 30) + _seconds(rng.randint(0, 90 * 60))
            session = int((logout_at - login_at).total_seconds())

            if user in NOISY_USERS and rng.random() < 0.35:  # a mistyped password
                miss_at = login_at - _seconds(rng.randint(15, 45))
                rows.append(_login_fail(miss_at, ip, user, login_host))
            message = rng.choice(("Password authentication succeeded", "MFA verified"))
            rows.append(_login_ok(login_at, ip, user, login_host, message))

            for _ in range(rng.randint(3, 8)):
                at = _within_session(rng, login_at, session)
                host, resource = rng.choice(ACCESS_HOSTS), rng.choice(RESOURCES)
                rows.append(_access_ok(at, ip, user, host, resource))
            if user in NOISY_USERS and rng.random() < 0.3:  # one-off denial
                at = _within_session(rng, login_at, session)
                host, resource = rng.choice(ACCESS_HOSTS), rng.choice(RESTRICTED_RESOURCES)
                rows.append(_access_denied(at, ip, user, host, resource))
            if rng.random() < 0.05:
                at = _within_session(rng, login_at, session)
                rows.append(
                    _row(
                        at,
                        ip,
                        user,
                        "password_change",
                        "success",
                        "sso-01",
                        "Password changed by user",
                    )
                )
            rows.append(_row(logout_at, ip, user, "logout", "success", login_host, "Session ended"))
    return rows


def _within_session(rng: random.Random, login_at: datetime, session_seconds: int) -> datetime:
    """A random moment between 5 minutes after login and 1 minute before logout."""
    return login_at + _seconds(rng.randint(300, session_seconds - 60))


def _service_accounts() -> list[Row]:
    """B2: nightly ETL batch (high volume, all successful) plus quiet backup/reporting jobs."""
    rng = _rng("service")
    rows: list[Row] = []
    etl_ip, backup_ip, report_ip = "192.0.2.200", "192.0.2.201", "192.0.2.202"
    service_auth = "Service account authentication succeeded"
    for day in range(DAYS):
        start = _at(day, 2)
        rows.append(_login_ok(start, etl_ip, "svc.etl", "db-admin-01", service_auth))
        for _ in range(40):
            at = start + _seconds(rng.randint(10, 6 * 60))
            rows.append(
                _row(
                    at,
                    etl_ip,
                    "svc.etl",
                    "access",
                    "success",
                    "db-admin-01",
                    f"Batch read: {rng.choice(RESOURCES)}",
                )
            )
        rows.append(
            _login_ok(_at(day, 4, 30), backup_ip, "svc.backup", "file-srv-01", service_auth)
        )
        rows.append(_login_ok(_at(day, 6), report_ip, "svc.reporting", "web-app-01", service_auth))
        rows.append(
            _access_ok(
                _at(day, 6, 20), report_ip, "svc.reporting", "web-app-01", "dashboards/sales"
            )
        )
    return rows


# --------------------------------------------------------------------------------------
# Benign situations that must not alert (B3-B5; B1 and B2 are in the code above)
# --------------------------------------------------------------------------------------


def _benign_edge_cases() -> list[Row]:
    rng = _rng("benign")
    rows: list[Row] = []

    # B3: four people behind one shared IP mistype within 8 minutes (threshold is 5).
    start = _at(2, 9, 20)
    for n, user in enumerate(OFFICE_NAT_USERS):
        miss_at = start + _seconds(n * 150 + rng.randint(0, 20))
        rows.append(_login_fail(miss_at, OFFICE_NAT_IP, user, "sso-01"))
        rows.append(
            _login_ok(miss_at + _seconds(rng.randint(30, 60)), OFFICE_NAT_IP, user, "sso-01")
        )

    # B4: three failures then success (threshold is 5).
    start = _at(1, 8, 45)
    for n in range(3):
        rows.append(_login_fail(start + _seconds(n * 20), "192.0.2.11", "ben.carter", "sso-01"))
    rows.append(_login_ok(start + _seconds(75), "192.0.2.11", "ben.carter", "sso-01"))

    # B5: three access denials in four minutes (threshold is 4).
    start = _at(2, 11)
    for n in range(3):
        rows.append(
            _access_denied(
                start + _seconds(n * 100),
                "192.0.2.14",
                "emma.larsen",
                "hr-portal-01",
                RESTRICTED_RESOURCES[n],
            )
        )
    return rows


# --------------------------------------------------------------------------------------
# Suspicious scenarios
# --------------------------------------------------------------------------------------


def _failure_burst(
    start: datetime,
    count: int,
    step: tuple[int, int],
    rng: random.Random,
    ip_for: Callable[[int], str],
    user_for: Callable[[int], str],
) -> tuple[list[Row], datetime]:
    """``count`` failed logins a random ``step`` seconds apart; returns the rows and last time."""
    rows: list[Row] = []
    at = start
    for n in range(count):
        if n:
            at += _seconds(rng.randint(*step))
        rows.append(_login_fail(at, ip_for(n), user_for(n), "vpn-gw-01"))
    return rows, at


def _suspicious_scenarios() -> list[Row]:
    rows: list[Row] = []

    # S1: single-source brute force against a service account (no success).
    burst, _ = _failure_burst(
        _at(0, 3, 12), 16, (16, 28), _rng("S1"), lambda n: "203.0.113.45", lambda n: "svc.backup"
    )
    rows += burst

    # S2: password spraying - one IP, one failure per account.
    burst, _ = _failure_burst(
        _at(0, 14, 5), 8, (25, 40), _rng("S2"), lambda n: "203.0.113.99", lambda n: SPRAY_TARGETS[n]
    )
    rows += burst

    # S3: distributed attempts on a single account, one failure per IP.
    burst, _ = _failure_burst(
        _at(1, 11, 30),
        7,
        (45, 70),
        _rng("S3"),
        lambda n: f"198.51.100.{21 + n}",
        lambda n: "dana.whitfield",
    )
    rows += burst

    # S4: failures from 3 IPs (two each), then a success from one of them.
    burst, last = _failure_burst(
        _at(1, 16, 20), 6, (60, 90), _rng("S4"), lambda n: S4_IPS[n % 3], lambda n: "marcus.lee"
    )
    rows += burst
    rows.append(_login_ok(last + timedelta(minutes=4), S4_IPS[0], "marcus.lee", "vpn-gw-01"))

    # S5: brute force from one IP that ends in a success from the same IP.
    burst, last = _failure_burst(
        _at(2, 1, 47), 16, (25, 25), _rng("S5"), lambda n: "203.0.113.88", lambda n: "svc.reporting"
    )
    rows += burst
    rows.append(
        _login_ok(
            last + timedelta(minutes=3),
            "203.0.113.88",
            "svc.reporting",
            "vpn-gw-01",
            "Service account authentication succeeded",
        )
    )

    # S6: repeated authorization denials against restricted resources.
    rng = _rng("S6")
    at = _at(2, 13, 15)
    for n, resource in enumerate(RESTRICTED_RESOURCES):
        if n:
            at += _seconds(rng.randint(60, 100))
        rows.append(_access_denied(at, "192.0.2.25", "priya.raman", "db-admin-01", resource))
    return rows


# --------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------


def generate_events() -> list[Row]:
    """All synthetic events in chronological order, without exact duplicates. Same every call."""
    rows = _normal_activity() + _service_accounts() + _benign_edge_cases() + _suspicious_scenarios()
    rows.sort(key=lambda r: tuple(r[c] for c in CANONICAL_COLUMNS))
    unique: list[Row] = []
    for row in rows:
        if not unique or row != unique[-1]:  # identical rows are adjacent after sorting
            unique.append(row)
    return unique


def generate_csv() -> str:
    """The demo dataset as CSV text in the canonical schema."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CANONICAL_COLUMNS), lineterminator="\n")
    writer.writeheader()
    writer.writerows(generate_events())
    return buffer.getvalue()


def write_sample_csv(path: Path = SAMPLE_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_csv(), encoding="utf-8", newline="")
    return path


if __name__ == "__main__":
    written = write_sample_csv()
    print(f"Wrote {len(generate_events()):,} synthetic events to {written}")
