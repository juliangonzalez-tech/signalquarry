"""CSV ingestion: parse, validate and normalise security logs into the canonical schema.

Design rules:
  * A file that cannot be used at all (empty, binary, wrong columns, too large) raises
    :class:`LogValidationError` with a message that says what to fix.
  * A file with some bad rows is still processed. Bad rows are *rejected, never silently
    dropped*: every rejection is recorded in ``ParseResult.issues`` with its row number,
    column and reason.
  * Uploaded content is treated as data only. It is read with the ``csv`` module and pandas;
    nothing in it is ever evaluated, and error messages never echo free-text fields such as
    usernames or messages.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field

import pandas as pd

from .schema import (
    CANONICAL_COLUMNS,
    EVENT_ID_COLUMN,
    EVENT_TYPES,
    MAX_FIELD_LENGTH,
    MAX_MESSAGE_LENGTH,
    MAX_UPLOAD_BYTES,
    MAX_YEAR,
    MIN_YEAR,
    OPTIONAL_COLUMNS,
    OUTCOME_ALIASES,
    OUTCOMES,
    REQUIRED_COLUMNS,
    SOURCE_ROW_COLUMN,
)

# Order used to number events, so IDs do not depend on the order of rows in the file.
SORT_COLUMNS = ["timestamp", "source_ip", "username", "event_type", "outcome", "host", "message"]

_TIMESTAMP_SHAPE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
_HAS_UTC_OFFSET = re.compile(r"\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?\s*(?:[Zz]|[+-]\d{2}(?::?\d{2})?)$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Invisible characters that change how the text around them is displayed: bidirectional
# overrides (which make "adm<U+202E>nimda" display as "admadmin") and zero-width spaces. In a
# username or host they would let one account pass for another on screen.
_INVISIBLE_FORMATTING = re.compile(r"[\u200b\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]")

# Columns whose (short, constrained) values are safe to quote back in a message.
_ECHO_COLUMNS = {"timestamp", "source_ip", "event_type", "outcome"}
_ECHO_LIMIT = 40

# The csv module refuses fields over 128 KB by default, which would reject a whole file because of
# one long cell. Allow up to the upload limit; over-long messages are then truncated per row.
csv.field_size_limit(max(csv.field_size_limit(), MAX_UPLOAD_BYTES))

ISSUE_COLUMNS = ["row", "column", "reason", "value"]


class LogValidationError(ValueError):
    """The file as a whole cannot be used."""


@dataclass
class ParseResult:
    """Outcome of parsing one file. ``events`` holds only valid, normalised rows."""

    events: pd.DataFrame
    rows_read: int
    issues: pd.DataFrame
    duplicates_removed: int = 0
    duplicate_rows: int = 0  # rows identical to an earlier row, whether removed or kept
    duplicates_dropped: bool = False  # was removal switched on for this parse?
    ignored_columns: list[str] = field(default_factory=list)
    naive_timestamp_rows: int = 0
    out_of_order_rows: int = 0
    blank_lines: int = 0
    truncated_messages: int = 0
    source_name: str = ""

    @property
    def rows_accepted(self) -> int:
        return len(self.events)

    @property
    def rows_rejected(self) -> int:
        return int(self.issues["row"].nunique()) if len(self.issues) else 0

    def rejection_summary(self) -> pd.DataFrame:
        """Number of rows affected per (column, reason), most common first."""
        if self.issues.empty:
            return pd.DataFrame(columns=["column", "reason", "rows"])
        summary = (
            self.issues.groupby(["column", "reason"], sort=False)["row"]
            .nunique()
            .reset_index(name="rows")
            .sort_values(["rows", "column"], ascending=[False, True], kind="stable")
        )
        return summary.reset_index(drop=True)

    def warnings(self) -> list[str]:
        """Non-fatal observations an analyst should know about."""
        notes: list[str] = []
        if self.rows_rejected:
            notes.append(
                f"Rejected {self.rows_rejected:,} of {self.rows_read:,} rows as invalid; "
                "they are not part of the analysis (see the rejection table)."
            )
        if self.duplicates_removed:
            notes.append(
                f"Removed {_count(self.duplicates_removed, 'exact duplicate row')} "
                "(identical in every field)."
            )
        elif self.duplicate_rows:
            single = self.duplicate_rows == 1
            notes.append(
                f"Kept {_count(self.duplicate_rows, 'exact duplicate row')} (identical in every "
                f"field). {'It counts' if single else 'They count'} toward the detections. If "
                f"{'it is a repeated log line' if single else 'they are repeated log lines'} "
                "rather than "
                f"{'a repeated event' if single else 'repeated events'}, switch on the "
                "'Remove exact duplicate rows' option."
            )
        if self.naive_timestamp_rows:
            notes.append(
                f"Assumed UTC for {_count(self.naive_timestamp_rows, 'timestamp')} "
                "with no UTC offset."
            )
        if self.out_of_order_rows:
            notes.append(
                f"The file was not in chronological order ({self.out_of_order_rows:,} "
                "out-of-order rows); events were sorted by timestamp."
            )
        if self.truncated_messages:
            notes.append(
                f"Truncated {_count(self.truncated_messages, 'message')} longer than "
                f"{MAX_MESSAGE_LENGTH:,} characters."
            )
        if self.blank_lines:
            notes.append(f"Skipped {_count(self.blank_lines, 'blank line')}.")
        if self.ignored_columns:
            shown = ", ".join(repr(c[:30]) for c in self.ignored_columns[:8])
            notes.append(f"Unrecognised columns were ignored: {shown}.")
        return notes


def _count(number: int, noun: str) -> str:
    return f"{number:,} {noun}" + ("" if number == 1 else "s")


def parse_csv(
    data: bytes | str,
    *,
    source_name: str = "upload",
    max_bytes: int = MAX_UPLOAD_BYTES,
    drop_duplicates: bool = False,
) -> ParseResult:
    """Parse CSV content into validated, normalised events.

    Exact duplicate rows (identical in every field) are counted but KEPT unless
    ``drop_duplicates`` is true: with one-second timestamps, genuinely repeated events such as
    scripted login attempts are indistinguishable from duplicated log lines, and removing them
    silently would lower the counts the detection rules depend on.

    Raises :class:`LogValidationError` when the file as a whole is unusable.
    """
    text = _decode(data, max_bytes)
    header, records, row_numbers, blank_lines = _read_records(text)
    columns, ignored = _resolve_columns(header)

    raw = _records_to_frame(records, row_numbers, header, columns)
    issues: list[dict[str, object]] = []
    work = _normalise_and_validate(raw, issues)

    issue_frame = _issues_to_frame(issues)
    invalid_rows = set(issue_frame["row"]) if len(issue_frame) else set()
    valid = work[~work["_row"].isin(invalid_rows)].copy()

    too_long = valid["message"].str.len() > MAX_MESSAGE_LENGTH
    truncated = int(too_long.sum())
    if truncated:
        valid.loc[too_long, "message"] = valid.loc[too_long, "message"].str.slice(
            0, MAX_MESSAGE_LENGTH
        )

    naive_rows = int((~valid["_has_offset"]).sum())
    out_of_order = int((valid["timestamp"] < valid["timestamp"].cummax().shift()).sum())

    duplicate_rows = 0
    if len(valid):
        duplicate_mask = valid.duplicated(subset=list(CANONICAL_COLUMNS), keep="first")
        duplicate_rows = int(duplicate_mask.sum())
        if drop_duplicates:
            valid = valid[~duplicate_mask]

    events = _finalise(valid)
    return ParseResult(
        events=events,
        rows_read=len(raw),
        issues=issue_frame,
        duplicates_removed=duplicate_rows if drop_duplicates else 0,
        duplicate_rows=duplicate_rows,
        duplicates_dropped=drop_duplicates,
        ignored_columns=ignored,
        naive_timestamp_rows=naive_rows,
        out_of_order_rows=out_of_order,
        blank_lines=blank_lines,
        truncated_messages=truncated,
        source_name=source_name,
    )


# --------------------------------------------------------------------------------------
# File-level handling
# --------------------------------------------------------------------------------------


def _decode(data: bytes | str, max_bytes: int) -> str:
    if isinstance(data, str):
        text = data.removeprefix(chr(0xFEFF))
        size = len(text.encode("utf-8"))
    else:
        size = len(data)
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            raise LogValidationError(
                "This file is UTF-16 text (Excel's 'Unicode Text' format, which also uses tabs). "
                "Re-save it as 'CSV (UTF-8)' and try again."
            )
        if b"\x00" in data[:8192]:
            raise LogValidationError(
                "This file looks like binary data, not a text CSV. "
                "If it is an Excel file, export it as 'CSV (UTF-8)' first."
            )
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise LogValidationError(
                "The file is not valid UTF-8 text. Re-save it as 'CSV (UTF-8)' and try again."
            ) from exc
    if size > max_bytes:
        size_mb, limit_mb = size / 1024 / 1024, max_bytes / 1024 / 1024
        raise LogValidationError(
            f"The file is {size_mb:.1f} MB; the limit is {limit_mb:.0f} MB. "
            "Split the log into smaller files."
        )
    if not text.strip():
        raise LogValidationError("The file is empty.")
    return text


def _read_records(text: str) -> tuple[list[str], list[list[str]], list[int], int]:
    """Read CSV records, keeping each record's row number (the header is the first record)."""
    reader = csv.reader(io.StringIO(text, newline=""))
    header: list[str] | None = None
    records: list[list[str]] = []
    row_numbers: list[int] = []
    blank_lines = 0
    row_number = 0
    try:
        for row_number, record in enumerate(reader, start=1):
            if not any(cell.strip() for cell in record):
                if header is not None:
                    blank_lines += 1
                continue
            if header is None:
                header = record
            else:
                records.append(record)
                row_numbers.append(row_number)
    except csv.Error as exc:
        raise LogValidationError(
            f"The file could not be read as CSV near row {row_number + 1}: {exc}. "
            "Check for unbalanced quotes or an extremely long field."
        ) from exc
    if header is None:
        raise LogValidationError("The file is empty.")
    if not records:
        raise LogValidationError("The file has a header row but no data rows.")
    return header, records, row_numbers, blank_lines


def _resolve_columns(header: list[str]) -> tuple[dict[str, int], list[str]]:
    """Map canonical column name -> position in the file; also return ignored column names."""
    normalised = [name.strip().lower() for name in header]
    seen: set[str] = set()
    for name in normalised:
        # Repeats of columns SignalQuarry ignores anyway are harmless; repeats of its own are
        # ambiguous.
        if name in CANONICAL_COLUMNS and name in seen:
            raise LogValidationError(f"The column '{name}' appears more than once in the header.")
        seen.add(name)

    missing = [name for name in REQUIRED_COLUMNS if name not in seen]
    if missing:
        found = ", ".join(repr(n[:40]) for n in normalised[:10]) or "none"
        hint = ""
        if len(header) == 1 and any(sep in header[0] for sep in (";", "\t", "|")):
            hint = (
                " The file looks like it uses a different delimiter; SignalQuarry expects commas."
            )
        raise LogValidationError(
            f"Missing required column(s): {', '.join(missing)}. Columns found: {found}.{hint} "
            f"Required columns are: {', '.join(REQUIRED_COLUMNS)}."
        )

    positions = {name: i for i, name in enumerate(normalised) if name in CANONICAL_COLUMNS}
    ignored = [
        header[i].strip() or "(unnamed)" for i, n in enumerate(normalised) if n not in positions
    ]
    return positions, ignored


def _records_to_frame(
    records: list[list[str]],
    row_numbers: list[int],
    header: list[str],
    columns: dict[str, int],
) -> pd.DataFrame:
    """Build a string DataFrame. Rows with extra fields are padded/flagged later."""
    width = len(header)
    padded = []
    field_count_problem = []
    for record in records:
        field_count_problem.append(len(record) > width)
        padded.append(
            record + [""] * (width - len(record)) if len(record) < width else record[:width]
        )

    frame = pd.DataFrame({"_row": row_numbers, "_too_many_fields": field_count_problem})
    for name in CANONICAL_COLUMNS:
        if name in columns:
            idx = columns[name]
            frame[name] = [record[idx].strip() for record in padded]
        else:
            frame[name] = ""
    return frame


# --------------------------------------------------------------------------------------
# Row-level validation and normalisation
# --------------------------------------------------------------------------------------


def _flag(
    issues: list[dict[str, object]],
    frame: pd.DataFrame,
    mask: pd.Series,
    column: str,
    reason: str,
    *,
    echo: bool = True,
) -> None:
    """Record an issue for every row selected by ``mask``."""
    rows = frame.loc[mask, "_row"]
    # Only short, constrained fields are quoted back; free text (username, host, message) never is.
    if echo and column in _ECHO_COLUMNS:
        values = [str(v)[:_ECHO_LIMIT] for v in frame.loc[mask, column]]
    else:
        values = [""] * len(rows)
    for row, value in zip(rows, values, strict=True):
        issues.append({"row": int(row), "column": column, "reason": reason, "value": value})


def _normalise_and_validate(raw: pd.DataFrame, issues: list[dict[str, object]]) -> pd.DataFrame:
    work = raw.copy()

    # Rows with more fields than the header cannot be trusted to line up with the columns.
    _flag(
        issues,
        work,
        work["_too_many_fields"],
        "(row)",
        "row has more fields than the header (check for unquoted commas)",
    )

    # Required values present?
    for name in REQUIRED_COLUMNS:
        _flag(issues, work, work[name] == "", name, "missing value")

    _validate_timestamps(work, issues)
    _validate_ips(work, issues)

    work["username"] = _normalise_text(work["username"])
    for name in ("username", "host"):
        too_long = work[name].str.len() > MAX_FIELD_LENGTH
        _flag(issues, work, too_long, name, f"longer than {MAX_FIELD_LENGTH} characters")
        control = work[name].str.contains(_CONTROL_CHARACTERS)
        _flag(
            issues,
            work,
            control,
            name,
            "contains control characters (a line break here usually means an unbalanced quote "
            "merged several lines into one field)",
        )
        invisible = work[name].str.contains(_INVISIBLE_FORMATTING)
        _flag(
            issues,
            work,
            invisible,
            name,
            "contains invisible formatting characters (text-direction or zero-width)",
        )

    work["event_type"] = work["event_type"].str.lower()
    unsupported = (work["event_type"] != "") & ~work["event_type"].isin(EVENT_TYPES)
    _flag(
        issues,
        work,
        unsupported,
        "event_type",
        f"unsupported event_type (expected one of: {', '.join(EVENT_TYPES)})",
    )

    work["outcome"] = work["outcome"].str.lower().replace(OUTCOME_ALIASES)
    unsupported = (work["outcome"] != "") & ~work["outcome"].isin(OUTCOMES)
    _flag(
        issues,
        work,
        unsupported,
        "outcome",
        f"unsupported outcome (expected one of: {', '.join(OUTCOMES)})",
    )
    return work


def _validate_timestamps(work: pd.DataFrame, issues: list[dict[str, object]]) -> None:
    # RFC 3339 allows a lower-case 't' and 'z'; pandas only understands the upper-case forms.
    # Only 'T' and 'Z' are letters in a valid timestamp, so upper-casing cannot change a value.
    text = work["timestamp"].str.upper()
    present = text != ""
    shaped = text.str.match(_TIMESTAMP_SHAPE)
    _flag(
        issues,
        work,
        present & ~shaped,
        "timestamp",
        "not an ISO 8601 date and time (expected e.g. 2026-03-02T14:05:09Z)",
    )

    work["_has_offset"] = text.str.contains(_HAS_UTC_OFFSET)
    parsed = pd.to_datetime(
        text.where(present & shaped, None), format="ISO8601", utc=True, errors="coerce"
    )
    unparseable = present & shaped & parsed.isna()
    _flag(issues, work, unparseable, "timestamp", "not a valid calendar date or time")

    in_range = parsed.dt.year.between(MIN_YEAR, MAX_YEAR)
    _flag(
        issues,
        work,
        parsed.notna() & ~in_range,
        "timestamp",
        f"year outside the supported range {MIN_YEAR}-{MAX_YEAR}",
    )
    work["timestamp"] = parsed


def _validate_ips(work: pd.DataFrame, issues: list[dict[str, object]]) -> None:
    # Python accepts an IPv6 zone ID ("fe80::1%eth0") made of almost any text, of any length, so
    # it would let free text into the IP column. The text after '%' is not quoted back either.
    zoned = work["source_ip"].str.contains("%", regex=False)
    _flag(
        issues,
        work,
        zoned,
        "source_ip",
        "IPv6 zone IDs (a '%' suffix such as %eth0) are not supported",
        echo=False,
    )
    normalised = {value: _normalise_ip(value) for value in work["source_ip"].unique()}
    result = work["source_ip"].map(normalised)
    bad = (work["source_ip"] != "") & result.isna() & ~zoned
    _flag(issues, work, bad, "source_ip", "not a valid IPv4 or IPv6 address")
    work["source_ip"] = result.where(result.notna(), work["source_ip"])


def _normalise_text(series: pd.Series) -> pd.Series:
    """Lower-case and Unicode-normalise (NFC), so that the composed and decomposed spellings of
    an accented name (one character vs letter + combining accent) are one account, not two."""
    cleaned = {value: unicodedata.normalize("NFC", value.lower()) for value in series.unique()}
    return series.map(cleaned)


def _normalise_ip(value: str) -> str | None:
    if not value:
        return ""
    if "%" in value:  # zone ID, rejected by _validate_ips
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    # ::ffff:192.0.2.1 is the same host as 192.0.2.1 (dual-stack sockets log either form);
    # keep them as one address so per-IP counts are not split in two.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def _issues_to_frame(issues: list[dict[str, object]]) -> pd.DataFrame:
    if not issues:
        return pd.DataFrame(columns=ISSUE_COLUMNS).astype(
            {"row": "int64", "column": "object", "reason": "object", "value": "object"}
        )
    frame = pd.DataFrame(issues, columns=ISSUE_COLUMNS)
    return frame.sort_values(["row", "column"], kind="stable").reset_index(drop=True)


def _finalise(valid: pd.DataFrame) -> pd.DataFrame:
    """Sort deterministically, assign IDs and return the public event table."""
    events = valid.rename(columns={"_row": SOURCE_ROW_COLUMN})
    events = events[[*CANONICAL_COLUMNS, SOURCE_ROW_COLUMN]].copy()
    events["timestamp"] = events["timestamp"].dt.as_unit("ns")
    events = events.sort_values(SORT_COLUMNS, kind="stable").reset_index(drop=True)
    events.insert(0, EVENT_ID_COLUMN, [f"EVT-{i:06d}" for i in range(1, len(events) + 1)])
    for name in OPTIONAL_COLUMNS:
        events[name] = events[name].fillna("")
    return events
