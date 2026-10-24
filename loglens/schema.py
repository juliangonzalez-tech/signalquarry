"""The canonical LogLens event schema and the vocabulary it accepts.

Every log that enters LogLens is validated against, and normalised to, this schema.
Supporting another log format later means writing a new parser that outputs these columns;
nothing downstream (detection, charts, exports) needs to change.
"""

from __future__ import annotations

REQUIRED_COLUMNS: tuple[str, ...] = ("timestamp", "source_ip", "username", "event_type", "outcome")
OPTIONAL_COLUMNS: tuple[str, ...] = ("host", "message")
CANONICAL_COLUMNS: tuple[str, ...] = REQUIRED_COLUMNS + OPTIONAL_COLUMNS

# Columns added by the parser (not part of the input file).
EVENT_ID_COLUMN = "event_id"
SOURCE_ROW_COLUMN = "source_row"

EVENT_TYPES: tuple[str, ...] = ("login", "logout", "access", "password_change")
OUTCOMES: tuple[str, ...] = ("success", "failure", "denied")

# Common spellings that are mapped onto the canonical outcome values.
OUTCOME_ALIASES: dict[str, str] = {
    "successful": "success",
    "failed": "failure",
    "fail": "failure",
    "deny": "denied",
    "denial": "denied",
}

# Event semantics used by the detection rules.
LOGIN = "login"
ACCESS = "access"
SUCCESS = "success"
FAILURE = "failure"
DENIED = "denied"

# Timestamps outside this range are treated as placeholders / corrupt values.
MIN_YEAR = 1970
MAX_YEAR = 2100

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_FIELD_LENGTH = 256  # username and host: longer values are rejected
MAX_MESSAGE_LENGTH = 2000  # message: longer values are truncated (and counted)


def describe_schema() -> list[dict[str, str]]:
    """Human-readable schema rows, used by the in-app guide."""
    return [
        {
            "column": "timestamp",
            "required": "yes",
            "description": "When the event happened. ISO 8601 with a time, e.g. "
            "2026-03-02T14:05:09Z or 2026-03-02T09:05:09-05:00. "
            "Values without a UTC offset are assumed to be UTC.",
        },
        {
            "column": "source_ip",
            "required": "yes",
            "description": "IPv4 or IPv6 address the event came from. IPv6 zone IDs "
            "(fe80::1%eth0) are not supported.",
        },
        {
            "column": "username",
            "required": "yes",
            "description": "Account involved. Trimmed, lower-cased and Unicode-normalised, so "
            "'Alice' and 'alice' are the same account. Control characters and invisible "
            "text-direction characters are rejected.",
        },
        {
            "column": "event_type",
            "required": "yes",
            "description": "One of: " + ", ".join(EVENT_TYPES) + ".",
        },
        {
            "column": "outcome",
            "required": "yes",
            "description": "One of: " + ", ".join(OUTCOMES) + ".",
        },
        {"column": "host", "required": "no", "description": "System that recorded the event."},
        {"column": "message", "required": "no", "description": "Free-text description."},
    ]
