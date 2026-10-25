"""Tunable detection thresholds."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds and windows for every rule. Defaults match the documented behaviour.

    Windows are in minutes and *inclusive*: with a 10-minute window, events exactly
    10:00 apart still count as inside the same window.
    """

    # LL-001: failed logins from one source IP
    ip_failure_threshold: int = 5
    ip_failure_window_minutes: int = 10

    # LL-002: failed logins against one account (any source IP).
    # LL-003 reuses this definition of a "qualifying burst".
    account_failure_threshold: int = 5
    account_failure_window_minutes: int = 10

    # LL-003: a success counts if it comes within this many minutes after the LAST failure of
    # a qualifying burst (the window runs from the end of the burst).
    success_investigation_minutes: int = 15

    # LL-004: authorization denials for one account
    denial_threshold: int = 4
    denial_window_minutes: int = 10

    # An alert is raised one severity level when its event count reaches
    # escalation_factor x the rule's threshold.
    escalation_factor: int = 3

    def __post_init__(self) -> None:
        thresholds = {
            "ip_failure_threshold": self.ip_failure_threshold,
            "account_failure_threshold": self.account_failure_threshold,
            "denial_threshold": self.denial_threshold,
        }
        for name, value in thresholds.items():
            if value < 2:
                raise ValueError(f"{name} must be at least 2 (got {value}).")
        windows = {
            "ip_failure_window_minutes": self.ip_failure_window_minutes,
            "account_failure_window_minutes": self.account_failure_window_minutes,
            "success_investigation_minutes": self.success_investigation_minutes,
            "denial_window_minutes": self.denial_window_minutes,
        }
        for name, value in windows.items():
            if value < 1:
                raise ValueError(f"{name} must be at least 1 minute (got {value}).")
        if self.escalation_factor < 2:
            raise ValueError(
                f"escalation_factor must be at least 2 (got {self.escalation_factor})."
            )
