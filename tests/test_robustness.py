"""Invalid, hostile or damaged input must produce a clear result or error - never a crash."""

from __future__ import annotations

import random

import pytest

from loglens.detection import run_detections
from loglens.parser import LogValidationError, ParseResult, parse_csv
from loglens.pipeline import annotate_events, build_dataset, load_demo_dataset
from loglens.sample_data import SAMPLE_PATH

VALID_HEADER = "timestamp,source_ip,username,event_type,outcome,host,message\n"
VALID_ROW = "2026-03-02T10:00:00Z,192.0.2.1,alice,login,failure,sso,bad password\n"

HOSTILE_INPUTS = {
    "only commas": b",,,,,,\n,,,,,,\n",
    "header only commas": b",,,\n,,,\n",
    "single column": b"timestamp\n2026-03-02T10:00:00Z\n",
    "no header, data first": VALID_ROW.encode(),
    "huge field": (VALID_HEADER + VALID_ROW.replace("bad password", "x" * 500_000)).encode(),
    "unbalanced quotes": (
        VALID_HEADER + '"2026-03-02T10:00:00Z,192.0.2.1,a,login,failure\n'
    ).encode(),
    "nul bytes": (VALID_HEADER + VALID_ROW).encode().replace(b"alice", b"al\x00ce"),
    "zip magic": b"PK\x03\x04" + bytes(range(256)),
    "png magic": b"\x89PNG\r\n\x1a\n" + bytes(range(256)),
    "latin-1 text": (VALID_HEADER + VALID_ROW).replace("alice", "\xe9lise").encode("latin-1"),
    "emoji and rtl": (VALID_HEADER + VALID_ROW.replace("alice", "\u202e\U0001f600")).encode(),
    "script and sql payloads": (
        VALID_HEADER
        + VALID_ROW.replace("alice", "<script>alert(1)</script>").replace(
            "sso", "'; DROP TABLE x;--"
        )
    ).encode(),
    "shell and format strings": (
        VALID_HEADER + VALID_ROW.replace("bad password", "$(rm -rf /) {0.__class__} %s %n")
    ).encode(),
    "markdown image payload": (
        VALID_HEADER + VALID_ROW.replace("alice", "![x](https://example.invalid/p.png)")
    ).encode(),
    "very long header": ("a," * 50_000 + "\n1\n").encode(),
    "cr only line endings": (VALID_HEADER + VALID_ROW).replace("\n", "\r").encode(),
    "null bytes only": b"\x00" * 100,
    "just a newline": b"\n",
    "wrong delimiter": b"timestamp;source_ip;username;event_type;outcome\n1;2;3;4;5\n",
    "tab delimited": VALID_HEADER.replace(",", "\t").encode()
    + VALID_ROW.replace(",", "\t").encode(),
}


def analyse(data: bytes | str) -> ParseResult | None:
    """Run the full ingest + detect path; only LogValidationError is an acceptable failure."""
    try:
        result = parse_csv(data)
    except LogValidationError as error:
        assert str(error)  # always carries a human-readable message
        return None
    alerts = run_detections(result.events)
    annotate_events(result.events, alerts)
    return result


@pytest.mark.parametrize("name", HOSTILE_INPUTS)
def test_hostile_input_never_crashes(name):
    analyse(HOSTILE_INPUTS[name])


def test_hostile_values_are_treated_as_inert_data():
    result = analyse(HOSTILE_INPUTS["script and sql payloads"])
    assert result is not None and result.rows_accepted == 1
    assert result.events["username"].iloc[0] == "<script>alert(1)</script>"  # stored, not executed


def test_valid_rows_survive_alongside_garbage_rows():
    text = VALID_HEADER + VALID_ROW + "garbage\n" + VALID_ROW.replace("10:00:00", "10:00:01")
    result = parse_csv(text)
    assert result.rows_accepted == 2
    assert result.rows_rejected == 1


def test_all_rows_invalid_returns_an_explained_empty_result():
    result = parse_csv(VALID_HEADER + "x,y,z,w,v,,\n" * 5)
    assert result.rows_accepted == 0
    assert result.rows_rejected == 5
    assert len(result.issues) > 0
    assert run_detections(result.events) == []


def test_build_dataset_wraps_the_same_errors():
    with pytest.raises(LogValidationError):
        build_dataset("empty.csv", b"")
    with pytest.raises(LogValidationError):
        build_dataset("wrong.csv", b"a,b,c\n1,2,3\n")


def test_random_corruption_of_the_sample_never_crashes():
    original = SAMPLE_PATH.read_bytes()
    rng = random.Random(1234)
    for _ in range(60):
        data = bytearray(original[: rng.randint(500, len(original))])
        for _ in range(rng.randint(1, 40)):
            position = rng.randrange(len(data))
            action = rng.random()
            if action < 0.4:
                data[position] = rng.randrange(256)
            elif action < 0.7:
                del data[position]
            else:
                data[position:position] = rng.choice([b",", b'"', b"\n", b"\xff", b"\x00", b" "])
        analyse(bytes(data))


def test_random_garbage_text_never_crashes():
    rng = random.Random(99)
    alphabet = list(",\n\r\"' abcXYZ019:-TZ.+=@;\t")
    for _ in range(80):
        analyse(VALID_HEADER + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 600))))


def test_demo_dataset_loads_without_user_input():
    dataset = load_demo_dataset()
    assert dataset.is_demo
    assert len(dataset.events) > 500


def test_unbalanced_quote_is_explained_to_the_user():
    text = VALID_HEADER + '2026-03-02T10:00:00Z,192.0.2.1,"alice,login,success,h,m\n' + VALID_ROW
    result = parse_csv(text)
    assert result.rows_accepted == 0 and result.rows_rejected == 1  # the quote ate the next line
    reasons = " ".join(result.issues["reason"])
    assert "unbalanced quote" in reasons and "control characters" in reasons
