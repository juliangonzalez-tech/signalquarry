"""Score SignalQuarry against the independent evaluation dataset.

    python -m evaluation.run_evaluation            # print the report
    python -m evaluation.run_evaluation --write    # also refresh evaluation/RESULTS.md

The ground truth (``eval_ground_truth.json``) was written by hand in
``build_evaluation_data.py``; this module only compares it with what the analyzer reports.

Matching rule: an alert belongs to the case that owns its key entity - the source IP for LL-001,
the account for LL-002 / LL-003 / LL-004. Every account and address belongs to exactly one case.
Per (rule, entity) the expected alerts and the actual alerts are compared in time order.

Five counts describe a run, and they always reconcile:

* expected   - alerts the hand-written ground truth says must be raised
* generated  - alerts SignalQuarry actually raised (every alert, wanted or not)
* matched    - generated alerts that are expected (same rule and entity)
* missed     - expected alerts that were not generated
* unexpected - generated alerts that were not expected

    expected  = matched + missed
    generated = matched + unexpected

Severity and evidence count are scored on the matched alerts; a matched alert with the wrong
severity is still matched.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from signalquarry.detection import Alert, DetectionConfig, run_detections
from signalquarry.parser import parse_csv

HERE = Path(__file__).resolve().parent
CSV_PATH = HERE / "eval_logs_synthetic.csv"
TRUTH_PATH = HERE / "eval_ground_truth.json"
RESULTS_PATH = HERE / "RESULTS.md"


@dataclass
class CaseResult:
    case_id: str
    kind: str
    title: str
    duplicates_matter: bool
    expected: int = 0  # alerts the ground truth requires
    generated: int = 0  # alerts SignalQuarry raised for this case's accounts and addresses
    matched: int = 0  # expected alerts that were generated
    missing: list[str] = field(default_factory=list)  # expected, not generated
    unexpected: list[str] = field(default_factory=list)  # generated, not expected
    wrong_severity: list[str] = field(default_factory=list)
    wrong_events: list[str] = field(default_factory=list)
    stray_evidence: list[str] = field(default_factory=list)  # evidence outside the case
    gaps_confirmed: int = 0  # limitation: attack-like activity correctly NOT reported
    gaps_unexpectedly_flagged: list[str] = field(default_factory=list)

    @property
    def missed(self) -> int:
        return len(self.missing)

    @property
    def passed(self) -> bool:
        return not (
            self.missing
            or self.unexpected
            or self.wrong_severity
            or self.wrong_events
            or self.stray_evidence
            or self.gaps_unexpectedly_flagged
        )

    def reconciliation_errors(self) -> list[str]:
        """Ways in which this case's counts fail to add up (empty when they do)."""
        problems = []
        if self.expected != self.matched + self.missed:
            problems.append(
                f"{self.case_id}: expected {self.expected} != matched {self.matched} "
                f"+ missed {self.missed}"
            )
        if self.generated != self.matched + len(self.unexpected):
            problems.append(
                f"{self.case_id}: generated {self.generated} != matched {self.matched} "
                f"+ unexpected {len(self.unexpected)}"
            )
        return problems


@dataclass
class Evaluation:
    drop_duplicates: bool
    rows_read: int
    events: int
    alerts: int  # every alert the analyzer returned, counted before any attribution to cases
    cases: list[CaseResult]

    def _sum(self, attribute: str) -> int:
        return sum(len(getattr(case, attribute)) for case in self.cases)

    @property
    def expected(self) -> int:
        return sum(case.expected for case in self.cases)

    @property
    def generated(self) -> int:
        return sum(case.generated for case in self.cases)

    @property
    def matched(self) -> int:
        return sum(case.matched for case in self.cases)

    @property
    def missed(self) -> int:
        return self._sum("missing")

    @property
    def unexpected(self) -> int:
        return self._sum("unexpected")

    @property
    def severity_correct(self) -> int:
        return self.matched - self._sum("wrong_severity")

    @property
    def evidence_correct(self) -> int:
        return self.matched - self._sum("wrong_events")

    @property
    def precision(self) -> float:
        """Share of the generated alerts that were expected."""
        return self.matched / self.generated if self.generated else 1.0

    @property
    def recall(self) -> float:
        """Share of the expected alerts that were generated."""
        return self.matched / self.expected if self.expected else 1.0

    @property
    def failing(self) -> list[str]:
        return [case.case_id for case in self.cases if not case.passed]

    def cases_of(self, *kinds: str) -> list[CaseResult]:
        return [case for case in self.cases if case.kind in kinds]

    def reconciliation_errors(self) -> list[str]:
        """Ways in which the counts fail to add up (empty when they reconcile).

        ``alerts`` comes straight from the analyzer; ``generated`` is rebuilt from the cases, so
        the first check catches an alert that was dropped or counted twice while attributing.
        """
        problems = []
        if self.alerts != self.generated:
            problems.append(
                f"the analyzer returned {self.alerts} alerts but the cases account for "
                f"{self.generated}"
            )
        if self.expected != self.matched + self.missed:
            problems.append(
                f"expected {self.expected} != matched {self.matched} + missed {self.missed}"
            )
        if self.generated != self.matched + self.unexpected:
            problems.append(
                f"generated {self.generated} != matched {self.matched} "
                f"+ unexpected {self.unexpected}"
            )
        for case in self.cases:
            problems += case.reconciliation_errors()
        return problems


def load_truth() -> dict:
    return json.loads(TRUTH_PATH.read_text(encoding="utf-8"))


def alert_entity(alert: Alert) -> str:
    """The key an alert is attributed by: the IP for LL-001, otherwise the account."""
    values = alert.source_ips if alert.rule_id == "LL-001" else alert.usernames
    return values[0] if len(values) == 1 else "|".join(values)


def evaluate(
    csv_bytes: bytes | None = None,
    truth: dict | None = None,
    *,
    drop_duplicates: bool,
    config: DetectionConfig | None = None,
) -> Evaluation:
    csv_bytes = CSV_PATH.read_bytes() if csv_bytes is None else csv_bytes
    truth = load_truth() if truth is None else truth
    parsed = parse_csv(csv_bytes, source_name=CSV_PATH.name, drop_duplicates=drop_duplicates)
    alerts = run_detections(parsed.events, config)

    owner: dict[tuple[str, str], str] = {}  # (kind of key, value) -> case id
    for case in truth["cases"]:
        for user in case["users"]:
            owner[("user", user)] = case["id"]
        for address in case["ips"]:
            owner[("ip", address)] = case["id"]

    by_case: dict[str, dict[tuple[str, str], list[Alert]]] = defaultdict(lambda: defaultdict(list))
    unattributed: list[Alert] = []
    for alert in alerts:
        kind = "ip" if alert.rule_id == "LL-001" else "user"
        case_id = owner.get((kind, alert_entity(alert)))
        if case_id is None:
            unattributed.append(alert)
        else:
            by_case[case_id][(alert.rule_id, alert_entity(alert))].append(alert)

    results: list[CaseResult] = []
    for case in truth["cases"]:
        result = CaseResult(
            case["id"], case["kind"], case["title"], case["duplicates_matter"],
            expected=len(case["expected_alerts"]),
        )  # fmt: skip
        expected: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for item in case["expected_alerts"]:
            expected[(item["rule"], item["entity"])].append(item)
        actual = by_case.get(case["id"], {})
        result.generated = sum(len(group) for group in actual.values())
        for key in sorted(set(expected) | set(actual)):
            want = expected.get(key, [])
            got = sorted(actual.get(key, []), key=lambda a: (a.timestamp, a.alert_id))
            label = f"{key[0]} on {key[1]}"
            result.matched += min(len(want), len(got))
            result.missing += [label] * max(0, len(want) - len(got))
            result.unexpected += [label] * max(0, len(got) - len(want))
            for expectation, alert in zip(want, got, strict=False):
                if alert.severity != expectation["severity"]:
                    result.wrong_severity.append(
                        f"{label}: expected {expectation['severity']}, got {alert.severity}"
                    )
                if alert.event_count != expectation["events"]:
                    result.wrong_events.append(
                        f"{label}: expected {expectation['events']} events, got {alert.event_count}"
                    )
        for alert in (a for group in actual.values() for a in group):
            if not (
                set(alert.usernames) <= set(case["users"])
                and set(alert.source_ips) <= set(case["ips"])
            ):
                result.stray_evidence.append(alert.alert_id)
        for gap in case["missed_by_design"]:
            flagged = (gap["rule"], gap["entity"]) in actual
            if flagged:
                result.gaps_unexpectedly_flagged.append(f"{gap['rule']} on {gap['entity']}")
            else:
                result.gaps_confirmed += 1
        results.append(result)

    if unattributed:  # an alert about an account or address that no case owns
        stray = CaseResult("??", "unattributed", "Alerts not owned by any case", False)
        stray.generated = len(unattributed)
        stray.unexpected = [f"{a.rule_id} on {alert_entity(a)}" for a in unattributed]
        results.append(stray)

    return Evaluation(drop_duplicates, parsed.rows_read, len(parsed.events), len(alerts), results)


# --------------------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------------------


def _percent(value: float) -> str:
    return f"{100 * value:.1f}%"


def _status(case: CaseResult) -> str:
    return "pass" if case.passed else "FAIL"


def reconciliation_line(run: Evaluation) -> str:
    """The two identities that tie the counts together, with the verdict."""
    verdict = "ok" if not run.reconciliation_errors() else "FAILED"
    return (
        f"Reconciliation ({verdict}): expected {run.expected} = matched {run.matched} + missed "
        f"{run.missed}; generated {run.generated} = matched {run.matched} + unexpected "
        f"{run.unexpected}."
    )


def format_report(runs: list[Evaluation], truth: dict | None = None) -> str:
    truth = load_truth() if truth is None else truth
    lines = [
        "# SignalQuarry evaluation results",
        "",
        "Synthetic evaluation set built independently of the demo generator "
        f"(`evaluation/build_evaluation_data.py`): {truth['total_rows']:,} rows, "
        f"{len(truth['cases']) - 1} scripted cases plus a week of background traffic. "
        "Expected alerts were written by hand from the documented rules, not copied from "
        "SignalQuarry output.",
        "",
        "How to read the counts:",
        "",
        "- **Expected** - alerts the ground truth says SignalQuarry must raise.",
        "- **Generated** - every alert SignalQuarry actually raised, wanted or not.",
        "- **Matched** - generated alerts that were expected (same rule and same key: the source "
        "IP for LL-001, the account for the other rules). Severity and evidence count are "
        "checked on matched alerts, so a matched alert can still have the wrong severity.",
        "- **Missed** - expected alerts that were not generated.",
        "- **Unexpected** - generated alerts that were not expected.",
        "",
        "Every run reconciles: expected = matched + missed, and generated = matched + unexpected. "
        "Precision is matched / generated; recall is matched / expected.",
        "",
    ]
    for run in runs:
        mode = "removed" if run.drop_duplicates else "kept"
        scripted = [c for c in run.cases if c.kind not in ("background",)]
        quiet = run.cases_of("negative", "background")
        gaps_total = sum(c.gaps_confirmed + len(c.gaps_unexpectedly_flagged) for c in run.cases)
        lines += [
            f"## Run: exact duplicate rows {mode}",
            "",
            f"{run.rows_read:,} rows read, {run.events:,} events analysed, "
            f"{run.generated} alerts generated.",
            "",
            "| Measure | Result |",
            "|---|---|",
            f"| Expected alerts | {run.expected} |",
            f"| Total alerts generated | {run.generated} |",
            f"| Correctly matched alerts | {run.matched} |",
            f"| Missed expected alerts | {run.missed} |",
            f"| Unexpected alerts | {run.unexpected} |",
            f"| Precision (matched / generated) | {_percent(run.precision)} |",
            f"| Recall (matched / expected) | {_percent(run.recall)} |",
            f"| Matched alerts with the expected severity | "
            f"{run.severity_correct} of {run.matched} |",
            f"| Matched alerts with the expected evidence count | "
            f"{run.evidence_correct} of {run.matched} |",
            f"| Negative and background cases that stayed silent | "
            f"{sum(not c.unexpected for c in quiet)} of {len(quiet)} |",
            f"| Documented blind spots that stayed silent, as documented | "
            f"{sum(c.gaps_confirmed for c in run.cases)} of {gaps_total} |",
            "",
            reconciliation_line(run),
            "",
            "| Case | Kind | Scenario | Expected | Generated | Matched | Missed | Unexpected "
            "| Result |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for case in scripted:
            lines.append(
                f"| {case.case_id} | {case.kind} | {case.title} | {case.expected} | "
                f"{case.generated} | {case.matched} | {case.missed} | {len(case.unexpected)} | "
                f"{_status(case)} |"
            )
        lines += [
            "",
            "The blind spots in the K cases are not counted as expected alerts: the activity "
            "there is attack-like but documented as not detected, and the check is that it "
            "stays silent.",
        ]
        problems = [c for c in run.cases if not c.passed]
        if problems:
            lines += ["", "Deviations:", ""]
            for case in problems:
                for label, items in (
                    ("missed", case.missing),
                    ("unexpected alert", case.unexpected),
                    ("wrong severity", case.wrong_severity),
                    ("wrong evidence count", case.wrong_events),
                    ("evidence outside the case", case.stray_evidence),
                    ("documented blind spot flagged after all", case.gaps_unexpectedly_flagged),
                ):
                    lines += [f"- {case.case_id} - {label}: {item}" for item in items]
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    runs = [evaluate(drop_duplicates=False), evaluate(drop_duplicates=True)]
    report = format_report(runs)
    print(report)
    problems = [error for run in runs for error in run.reconciliation_errors()]
    if problems:  # never publish a scorecard whose numbers do not add up
        print("The counts do not reconcile:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    if "--write" in argv:
        RESULTS_PATH.write_text(report + "\n", encoding="utf-8")
        print(f"wrote {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
