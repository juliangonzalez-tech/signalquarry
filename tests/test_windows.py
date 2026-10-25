"""The rolling-window primitive, tested on its own with exact expectations."""

from __future__ import annotations

import numpy as np

from signalquarry.detection.windows import find_clusters

BASE = np.datetime64("2026-03-02T10:00:00", "ns")
WINDOW = np.timedelta64(10, "m")


def times(*seconds: int) -> np.ndarray:
    return np.array([BASE + np.timedelta64(s, "s") for s in seconds], dtype="datetime64[ns]")


def test_empty_and_too_few_events_yield_no_clusters():
    assert find_clusters(times(), 5, WINDOW) == []
    assert find_clusters(times(0, 60, 120, 180), 5, WINDOW) == []


def test_exactly_threshold_events_inside_window_is_a_cluster():
    assert find_clusters(times(0, 60, 120, 180, 240), 5, WINDOW) == [(0, 4)]


def test_window_boundary_is_inclusive():
    assert find_clusters(times(0, 100, 200, 300, 600), 5, WINDOW) == [(0, 4)]  # exactly 10:00
    assert find_clusters(times(0, 100, 200, 300, 601), 5, WINDOW) == []  # 10:01


def test_uses_timestamps_not_adjacent_row_counts():
    # Five events overall, but never five inside any 10 minute span.
    assert find_clusters(times(0, 60, 120, 1200, 1260), 5, WINDOW) == []


def test_sustained_burst_is_one_cluster_not_one_per_event():
    one_per_minute = times(*range(0, 30 * 60, 60))  # 30 events over 29 minutes
    assert find_clusters(one_per_minute, 5, WINDOW) == [(0, 29)]


def test_separate_bursts_stay_separate():
    burst_a = [0, 10, 20, 30, 40]
    burst_b = [3600 + s for s in (0, 10, 20, 30, 40)]
    assert find_clusters(times(*burst_a, *burst_b), 5, WINDOW) == [(0, 4), (5, 9)]


def test_overlapping_windows_merge_into_one_cluster():
    # Qualifying windows end at index 4, 5 and 6 and share events, so they form ONE cluster
    # (0..6). Events 7 and 8 belong to no qualifying window (only 3-4 events fit with them).
    seconds = [0, 60, 120, 180, 240, 500, 700, 900, 1100]
    assert find_clusters(times(*seconds), 5, WINDOW) == [(0, 6)]


def test_windows_that_share_no_events_are_not_merged():
    seconds = [0, 1, 2, 3, 4, 700, 701, 702, 703, 704]  # 11+ minutes apart
    assert find_clusters(times(*seconds), 5, WINDOW) == [(0, 4), (5, 9)]


def test_identical_timestamps_count_as_separate_events():
    assert find_clusters(times(0, 0, 0, 0, 0), 5, WINDOW) == [(0, 4)]
