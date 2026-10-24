"""The independent evaluation set (``evaluation/``): reproducible, honest, and able to fail."""

from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path

import pytest

from evaluation import build_evaluation_data as builder
from evaluation import run_evaluation as runner
from loglens.detection import DetectionConfig


@pytest.fixture(scope="module")
def kept():
    return runner.evaluate(drop_duplicates=False)


@pytest.fixture(scope="module")
def removed():
    return runner.evaluate(drop_duplicates=True)


@pytest.fixture(scope="module")
def truth():
    return runner.load_truth()


# --------------------------------------------------------------------------------------
# The data set itself
# --------------------------------------------------------------------------------------


def test_the_checked_in_files_are_exactly_what_the_builder_produces(tmp_path, monkeypatch):
    monkeypatch.setattr(builder, "CSV_PATH", tmp_path / "logs.csv")
    monkeypatch.setattr(builder, "TRUTH_PATH", tmp_path / "truth.json")
    builder.write_files()
    assert (tmp_path / "logs.csv").read_bytes() == runner.CSV_PATH.read_bytes()
    assert (tmp_path / "truth.json").read_bytes() == runner.TRUTH_PATH.read_bytes()


def test_the_builder_does_not_depend_on_loglens_or_its_demo_generator():
    tree = ast.parse(Path(builder.__file__).read_text(encoding="utf-8"))
    imported = {
        node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "loglens" not in imported and "streamlit" not in imported and "pandas" not in imported


def test_every_account_and_address_belongs_to_exactly_one_case(truth):
    users = Counter(user for case in truth["cases"] for user in case["users"])
    addresses = Counter(ip for case in truth["cases"] for ip in case["ips"])
    assert max(users.values()) == 1 and max(addresses.values()) == 1


def test_the_set_has_positives_negatives_boundaries_and_documented_limitations(truth):
    kinds = Counter(case["kind"] for case in truth["cases"])
    assert kinds["positive"] >= 20 and kinds["negative"] >= 12
    assert kinds["boundary"] >= 4 and kinds["limitation"] >= 4 and kinds["background"] == 1
    assert sum(case["rows"] for case in truth["cases"]) == truth["total_rows"]
    # all four rules appear in the expectations
    assert {a["rule"] for c in truth["cases"] for a in c["expected_alerts"]} == {
        "LL-001",
        "LL-002",
        "LL-003",
        "LL-004",
    }


def test_the_file_is_not_in_chronological_order_and_is_all_documentation_addresses():
    lines = runner.CSV_PATH.read_text(encoding="utf-8").splitlines()[1:]
    stamps = [line.split(",")[0] for line in lines]
    assert stamps != sorted(stamps)
    addresses = {line.split(",")[1] for line in lines}
    assert all(a.startswith(("198.51.100.", "::ffff:198.51.100.", "2001:")) for a in addresses)


# --------------------------------------------------------------------------------------
# Scoring LogLens
# --------------------------------------------------------------------------------------


def test_with_duplicates_kept_every_expected_alert_is_reported_with_the_right_attributes(kept):
    assert kept.expected == 41 and kept.missed == 0
    assert kept.severity_correct == kept.matched == 41
    assert kept.evidence_correct == 41


def test_the_only_false_positives_come_from_replayed_duplicate_lines(kept):
    assert kept.failing == ["N14"]
    (replayed,) = (c for c in kept.cases if c.case_id == "N14")
    assert sorted(item.split(" on ")[0] for item in replayed.unexpected) == ["LL-001", "LL-002"]
    assert kept.unexpected == 2 and kept.generated == 43


def test_removing_duplicates_trades_that_false_positive_for_a_missed_attack(removed):
    assert removed.failing == ["P21"]
    assert removed.unexpected == 0 and removed.missed == 2
    assert removed.generated == 39 and removed.matched == 39
    (scripted,) = (c for c in removed.cases if c.case_id == "P21")
    assert {m.split(" on ")[0] for m in scripted.missing} == {"LL-001", "LL-002"}


def test_documented_blind_spots_are_real_and_nothing_else_is_missed(kept, removed):
    for run in (kept, removed):
        gaps = [c for c in run.cases if c.kind == "limitation"]
        assert len(gaps) == 4 and all(c.gaps_unexpectedly_flagged == [] for c in gaps)
        assert sum(c.gaps_confirmed for c in gaps) == 5


def test_background_traffic_and_near_misses_stay_silent(kept):
    quiet = kept.cases_of("negative", "background")
    assert [c.case_id for c in quiet if not c.passed] == ["N14"]
    assert len(quiet) == 15


def test_the_harness_can_fail_a_stricter_configuration_misses_alerts():
    run = runner.evaluate(
        drop_duplicates=False, config=DetectionConfig(ip_failure_threshold=6, denial_threshold=5)
    )
    assert run.missed > 0 and run.recall < 1
    assert {"P01", "P09"} <= set(run.failing)


def test_the_harness_can_fail_a_looser_configuration_raises_false_alarms():
    run = runner.evaluate(
        drop_duplicates=False,
        config=DetectionConfig(ip_failure_threshold=3, account_failure_threshold=3),
    )
    assert run.unexpected > 0 and run.precision < 1
    assert {"N01", "N10"} & set(run.failing)


def test_results_do_not_depend_on_the_order_of_the_rows():
    lines = runner.CSV_PATH.read_text(encoding="utf-8").splitlines()
    reordered = "\n".join([lines[0], *reversed(lines[1:])]) + "\n"
    original = runner.evaluate(drop_duplicates=False)
    again = runner.evaluate(reordered.encode(), drop_duplicates=False)
    assert [(c.case_id, c.matched, c.missing, c.unexpected) for c in again.cases] == [
        (c.case_id, c.matched, c.missing, c.unexpected) for c in original.cases
    ]


def test_the_report_names_every_scripted_case_and_its_deviations(kept, removed, truth):
    report = runner.format_report([kept, removed])
    for case in truth["cases"]:
        if case["kind"] != "background":
            assert f"| {case['id']} |" in report
    assert "N14 - unexpected alert: LL-001" in report
    assert "P21 - missed: LL-001" in report
    assert json.loads(runner.TRUTH_PATH.read_text())["seed"] == builder.SEED


def test_the_checked_in_results_file_matches_a_fresh_run(kept, removed):
    assert (
        runner.RESULTS_PATH.read_text(encoding="utf-8")
        == runner.format_report([kept, removed]) + "\n"
    )


def test_the_application_default_is_the_duplicates_kept_run(kept):
    from loglens.pipeline import build_dataset

    dataset = build_dataset(runner.CSV_PATH.name, runner.CSV_PATH.read_bytes())
    assert dataset.drop_duplicates is False
    assert len(dataset.events) == kept.events == kept.rows_read
