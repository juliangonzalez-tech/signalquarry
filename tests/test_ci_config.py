"""The CI workflow and the dependency bounds it relies on stay consistent.

These are text checks: PyYAML is not a dependency, and the workflow itself only runs on GitHub.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
REQUIREMENTS_DEV = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")


def _matrix_versions() -> list[str]:
    match = re.search(r"python-version:\s*\[([^\]]+)\]", WORKFLOW)
    assert match, "the workflow has no python-version matrix"
    return re.findall(r'"(\d+\.\d+)"', match.group(1))


def test_the_matrix_covers_python_311_312_and_313():
    assert _matrix_versions() == ["3.11", "3.12", "3.13"]


def test_the_oldest_matrix_version_is_the_declared_minimum():
    declared = re.search(r'requires-python\s*=\s*">=(\d+\.\d+)"', PYPROJECT)
    assert declared and declared.group(1) == _matrix_versions()[0]
    assert re.search(r'target-version\s*=\s*"py311"', PYPROJECT)


def test_the_workflow_runs_lint_format_check_and_tests_in_every_job():
    for command in ("ruff check .", "ruff format --check .", "python -m pytest"):
        assert re.search(rf"^\s+run: {re.escape(command)}$", WORKFLOW, re.MULTILINE), command
    assert "fail-fast: false" in WORKFLOW  # one version failing must not hide the others


def test_the_workflow_has_read_only_permissions_and_a_timeout():
    assert re.search(r"^permissions:\n  contents: read$", WORKFLOW, re.MULTILINE)
    assert "timeout-minutes:" in WORKFLOW


def test_ruff_is_held_to_one_minor_series_in_both_places():
    for text in (REQUIREMENTS_DEV, PYPROJECT):
        assert re.search(r"ruff>=0\.\d+,<0\.\d+", text)


def test_the_workflow_is_not_excluded_from_version_control():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".github" not in gitignore


def test_line_endings_are_pinned_so_a_windows_checkout_keeps_the_evaluation_files_intact():
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert re.search(r"^\* text=auto eol=lf$", attributes, re.MULTILINE)
    assert b"\r" not in (ROOT / "evaluation" / "eval_logs_synthetic.csv").read_bytes()
