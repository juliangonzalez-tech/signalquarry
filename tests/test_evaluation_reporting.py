"""The evaluation scorecard: what each count means, and that the counts always add up.

The scorer once reported "41 expected, 41 reported, 0 missed, 2 unexpected", which reads as if 41
alerts were generated. The 41 was the number of *matched* alerts; the analyzer actually generated
43 (41 matched + 2 unexpected). These tests pin down the vocabulary and the arithmetic, first on a
small hand-built scenario whose every number is worked out here, then on the real evaluation set
with a recount that does not use the scorer.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evaluation import run_evaluation as runner
from loglens.detection import run_detections
from loglens.parser import parse_csv

README = Path(__file__).resolve().parent.parent / "README.md"
BASE = datetime(2026, 6, 8, 10, 0, 0, tzinfo=UTC)
HEADER = "timestamp,source_ip,username,event_type,outcome,host,message"


# --------------------------------------------------------------------------------------
# A small scenario with hand-computed numbers
# --------------------------------------------------------------------------------------


def _at(minutes: float) -> str:
    return (BASE + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _denials(user: str, ip: str, start: float, count: int = 4) -> list[str]:
    """`count` denied accesses, ten seconds apart: LL-004 (threshold 4) when count >= 4."""
    return [
        f"{_at(start + i / 6)},{ip},{user},access,denied,app-01,Access denied" for i in range(count)
    ]


def _failures(user: str, ip: str, start: float) -> str:
    return f"{_at(start)},{ip},{user},login,failure,auth-01,Invalid password"


def _case(case_id, kind, users, ips, expected=(), blind_spots=()):
    return {
        "id": case_id,
        "kind": kind,
        "title": f"scenario {case_id}",
        "duplicates_matter": False,
        "users": list(users),
        "ips": list(ips),
        "expected_alerts": [
            {"rule": rule, "entity": entity, "severity": severity, "events": events}
            for rule, entity, severity, events in expected
        ],
        "missed_by_design": [{"rule": rule, "entity": entity} for rule, entity in blind_spots],
    }


def _scenario() -> tuple[bytes, dict]:
    """Eight cases plus one stranger, chosen so that every count is non-trivial.

    Columns: expected / generated / matched / missed / unexpected.

    M1  5 failures from one IP, 5 accounts -> LL-001      1 / 1 / 1 / 0 / 0
    M2  only 3 denials, truth wants LL-004                1 / 0 / 0 / 1 / 0
    M3  4 denials, truth wants nothing                    0 / 1 / 0 / 0 / 1
    M4  4 denials, truth wants another severity/count     1 / 1 / 1 / 0 / 0
    M5  one burst, truth wants two LL-004 alerts          2 / 1 / 1 / 1 / 0
    M6  two bursts an hour apart, truth wants one         1 / 2 / 1 / 0 / 1
    M7  3 failures, a blind spot that stays silent        0 / 0 / 0 / 0 / 0
    M8  5 failures on one account from 5 IPs (LL-002),    0 / 1 / 0 / 0 / 1
        documented as a blind spot yet it alerts
    ??  4 denials for an account no case owns             0 / 1 / 0 / 0 / 1
    total                                                 6 / 8 / 4 / 2 / 4
    """
    rows = [
        *(_failures(f"m1-{n}", "198.51.100.1", n / 6) for n in range(5)),
        *_denials("m2", "198.51.100.2", 0, count=3),
        *_denials("m3", "198.51.100.3", 0),
        *_denials("m4", "198.51.100.4", 0),
        *_denials("m5", "198.51.100.5", 0),
        *_denials("m6", "198.51.100.6", 0),
        *_denials("m6", "198.51.100.6", 60),
        *(_failures("m7", "198.51.100.7", n) for n in range(3)),
        *(_failures("m8", f"198.51.100.{80 + n}", n) for n in range(5)),
        *_denials("stranger", "198.51.100.200", 0),
    ]
    truth = {
        "total_rows": len(rows),
        "cases": [
            _case(
                "M1",
                "positive",
                [f"m1-{n}" for n in range(5)],
                ["198.51.100.1"],
                [("LL-001", "198.51.100.1", "medium", 5)],
            ),
            _case("M2", "positive", ["m2"], ["198.51.100.2"], [("LL-004", "m2", "low", 4)]),
            _case("M3", "negative", ["m3"], ["198.51.100.3"]),
            _case("M4", "positive", ["m4"], ["198.51.100.4"], [("LL-004", "m4", "high", 99)]),
            _case(
                "M5",
                "positive",
                ["m5"],
                ["198.51.100.5"],
                [("LL-004", "m5", "low", 4), ("LL-004", "m5", "low", 4)],
            ),
            _case("M6", "positive", ["m6"], ["198.51.100.6"], [("LL-004", "m6", "low", 4)]),
            _case(
                "M7",
                "limitation",
                ["m7"],
                ["198.51.100.7"],
                blind_spots=[("LL-002", "m7")],
            ),
            _case(
                "M8",
                "limitation",
                ["m8"],
                [f"198.51.100.{80 + n}" for n in range(5)],
                blind_spots=[("LL-002", "m8")],
            ),
        ],
    }
    return ("\n".join([HEADER, *rows]) + "\n").encode(), truth


@pytest.fixture(scope="module")
def mini():
    csv_bytes, truth = _scenario()
    return runner.evaluate(csv_bytes, truth, drop_duplicates=False), csv_bytes, truth


def _numbers(case) -> tuple[int, int, int, int, int]:
    return case.expected, case.generated, case.matched, case.missed, len(case.unexpected)


def test_each_count_in_the_small_scenario_is_the_hand_computed_one(mini):
    run, _, _ = mini
    by_id = {case.case_id: _numbers(case) for case in run.cases}
    #            expected, generated, matched, missed, unexpected
    assert by_id == {
        "M1": (1, 1, 1, 0, 0),
        "M2": (1, 0, 0, 1, 0),
        "M3": (0, 1, 0, 0, 1),
        "M4": (1, 1, 1, 0, 0),
        "M5": (2, 1, 1, 1, 0),
        "M6": (1, 2, 1, 0, 1),
        "M7": (0, 0, 0, 0, 0),
        "M8": (0, 1, 0, 0, 1),
        "??": (0, 1, 0, 0, 1),
    }
    assert (run.expected, run.generated, run.matched, run.missed, run.unexpected) == (6, 8, 4, 2, 4)


def test_the_total_generated_is_every_alert_the_analyzer_returned(mini):
    run, csv_bytes, _ = mini
    alerts = run_detections(parse_csv(csv_bytes, source_name="mini.csv").events)
    assert len(alerts) == run.alerts == run.generated == 8


def test_the_small_scenario_reconciles_mathematically(mini):
    run, _, _ = mini
    assert run.expected == run.matched + run.missed
    assert run.generated == run.matched + run.unexpected
    assert run.reconciliation_errors() == []


def test_precision_and_recall_use_matched_over_generated_and_over_expected(mini):
    run, _, _ = mini
    assert run.precision == pytest.approx(4 / 8)  # not 6 / 8, and not 4 / 6
    assert run.recall == pytest.approx(4 / 6)


def test_a_matched_alert_with_the_wrong_severity_is_still_matched(mini):
    run, _, _ = mini
    wrong = next(case for case in run.cases if case.case_id == "M4")
    assert wrong.matched == 1 and wrong.passed is False
    assert len(wrong.wrong_severity) == 1 and len(wrong.wrong_events) == 1
    assert run.severity_correct == run.evidence_correct == run.matched - 1 == 3


def test_blind_spots_are_not_expected_alerts_but_one_that_alerts_is_flagged(mini):
    run, _, _ = mini
    silent = next(case for case in run.cases if case.case_id == "M7")
    flagged = next(case for case in run.cases if case.case_id == "M8")
    assert (silent.gaps_confirmed, silent.passed) == (1, True)
    assert flagged.gaps_unexpectedly_flagged == ["LL-002 on m8"] and flagged.passed is False
    assert silent.expected == flagged.expected == 0


def test_an_alert_for_an_account_no_case_owns_counts_as_generated_and_unexpected(mini):
    run, _, _ = mini
    stranger = next(case for case in run.cases if case.case_id == "??")
    assert stranger.unexpected == ["LL-004 on stranger"]
    assert stranger.generated == 1 and stranger.expected == stranger.matched == 0


def test_the_report_labels_the_five_counts_and_states_the_reconciliation(mini):
    run, _, truth = mini
    report = runner.format_report([run], truth)
    for line in (
        "| Expected alerts | 6 |",
        "| Total alerts generated | 8 |",
        "| Correctly matched alerts | 4 |",
        "| Missed expected alerts | 2 |",
        "| Unexpected alerts | 4 |",
        "| Precision (matched / generated) | 50.0% |",
        "| Recall (matched / expected) | 66.7% |",
        "| Matched alerts with the expected severity | 3 of 4 |",
        "Reconciliation (ok): expected 6 = matched 4 + missed 2; "
        "generated 8 = matched 4 + unexpected 4.",
    ):
        assert line in report
    assert "reported" not in report.lower()  # the ambiguous word is gone


# --------------------------------------------------------------------------------------
# The arithmetic itself
# --------------------------------------------------------------------------------------


def test_percentages_round_to_one_decimal_place():
    assert runner._percent(41 / 43) == "95.3%"
    assert runner._percent(39 / 41) == "95.1%"
    assert runner._percent(1) == "100.0%"
    assert runner._percent(0) == "0.0%"


def test_an_empty_evaluation_has_perfect_precision_and_recall_and_reconciles():
    empty = runner.Evaluation(False, 0, 0, 0, [])
    assert (empty.expected, empty.generated, empty.matched) == (0, 0, 0)
    assert empty.precision == empty.recall == 1.0
    assert empty.reconciliation_errors() == []


def test_no_alerts_at_all_means_zero_recall_but_perfect_precision():
    case = runner.CaseResult("X", "positive", "nothing raised", False, expected=3)
    case.missing = ["LL-001 on a", "LL-001 on b", "LL-001 on c"]
    run = runner.Evaluation(False, 10, 10, 0, [case])
    assert (run.precision, run.recall) == (1.0, 0.0)
    assert run.reconciliation_errors() == []


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        (lambda run: replace(run, alerts=run.alerts + 1), "the analyzer returned"),
        (lambda run: _tweak(run, matched=+1), "expected"),
        (lambda run: _tweak(run, generated=+1), "generated"),
    ],
    ids=["alert dropped while attributing", "extra match", "extra generated alert"],
)
def test_a_scorecard_that_does_not_add_up_is_detected(mini, change, fragment):
    run, _, _ = mini
    broken = change(run)
    problems = broken.reconciliation_errors()
    assert problems and any(fragment in problem for problem in problems)
    assert "Reconciliation (FAILED)" in runner.format_report([broken], mini[2])


def _tweak(run, **deltas):
    first, *rest = run.cases
    changed = replace(first, **{name: getattr(first, name) + by for name, by in deltas.items()})
    return replace(run, cases=[changed, *rest])


def test_main_refuses_to_write_results_when_the_counts_do_not_reconcile(
    monkeypatch, tmp_path, capsys
):
    real = runner.evaluate(drop_duplicates=False)
    broken = replace(real, alerts=real.alerts + 1)
    monkeypatch.setattr(runner, "evaluate", lambda **_: broken)
    target = tmp_path / "RESULTS.md"
    monkeypatch.setattr(runner, "RESULTS_PATH", target)
    assert runner.main(["--write"]) == 1
    assert not target.exists()
    assert "do not reconcile" in capsys.readouterr().err


# --------------------------------------------------------------------------------------
# The real evaluation set, recounted without the scorer
# --------------------------------------------------------------------------------------


def _recount(drop_duplicates: bool) -> dict:
    """Generated, expected, matched, missed and unexpected, from raw engine output and raw truth."""
    truth = runner.load_truth()
    parsed = parse_csv(
        runner.CSV_PATH.read_bytes(), source_name="eval.csv", drop_duplicates=drop_duplicates
    )
    alerts = run_detections(parsed.events)
    generated = Counter(
        (a.rule_id, a.source_ips[0] if a.rule_id == "LL-001" else a.usernames[0]) for a in alerts
    )
    expected = Counter(
        (item["rule"], item["entity"])
        for case in truth["cases"]
        for item in case["expected_alerts"]
    )
    return {
        "generated": len(alerts),
        "expected": sum(expected.values()),
        "matched": sum((expected & generated).values()),
        "missed": sum((expected - generated).values()),
        "unexpected": sum((generated - expected).values()),
        "generated_by_rule": Counter(rule for rule, _ in generated.elements()),
        "expected_by_rule": Counter(rule for rule, _ in expected.elements()),
    }


@pytest.mark.parametrize("drop_duplicates", [False, True], ids=["kept", "removed"])
def test_the_scorer_agrees_with_an_independent_recount(drop_duplicates):
    run = runner.evaluate(drop_duplicates=drop_duplicates)
    recount = _recount(drop_duplicates)
    assert {
        "generated": run.generated,
        "expected": run.expected,
        "matched": run.matched,
        "missed": run.missed,
        "unexpected": run.unexpected,
    } == {key: recount[key] for key in ("generated", "expected", "matched", "missed", "unexpected")}
    assert run.alerts == recount["generated"]
    assert run.reconciliation_errors() == []


def test_the_headline_numbers_of_the_real_evaluation():
    kept = _recount(drop_duplicates=False)
    removed = _recount(drop_duplicates=True)
    # 41 alerts were expected; with duplicates kept LogLens generated 43 of which 41 match.
    assert (kept["expected"], kept["generated"], kept["matched"]) == (41, 43, 41)
    assert (kept["missed"], kept["unexpected"]) == (0, 2)
    assert (removed["expected"], removed["generated"], removed["matched"]) == (41, 39, 39)
    assert (removed["missed"], removed["unexpected"]) == (2, 0)
    assert dict(kept["expected_by_rule"]) == {"LL-001": 15, "LL-002": 17, "LL-003": 5, "LL-004": 4}
    assert dict(kept["generated_by_rule"]) == {"LL-001": 16, "LL-002": 18, "LL-003": 5, "LL-004": 4}


@pytest.mark.parametrize("drop_duplicates", [False, True], ids=["kept", "removed"])
def test_every_row_of_the_per_case_table_adds_up(drop_duplicates):
    run = runner.evaluate(drop_duplicates=drop_duplicates)
    rows = [
        [cell.strip() for cell in line.strip("|").split("|")]
        for line in runner.format_report([run]).splitlines()
        if re.match(r"\| [PBNK?]\d* ", line) or line.startswith("| ?? ")
    ]
    assert len(rows) == 45  # every scripted case, no background row
    for case_id, _kind, _title, expected, generated, matched, missed, unexpected, _result in rows:
        assert int(expected) == int(matched) + int(missed), case_id
        assert int(generated) == int(matched) + int(unexpected), case_id


def test_the_readme_table_carries_the_current_numbers():
    text = README.read_text(encoding="utf-8")
    found = {}
    for label in ("kept", "removed"):
        match = re.search(rf"^\| Duplicates \*\*{label}\*\*[^|]*\|(.*)\|$", text, re.MULTILINE)
        assert match, f"README has no '{label}' row in the evaluation table"
        found[label] = [int(cell) for cell in match.group(1).split("|")]
    for label, drop in (("kept", False), ("removed", True)):
        run = runner.evaluate(drop_duplicates=drop)
        assert found[label] == [
            run.expected,
            run.generated,
            run.matched,
            run.missed,
            run.unexpected,
        ]
