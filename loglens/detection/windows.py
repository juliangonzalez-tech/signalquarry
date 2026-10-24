"""Rolling-window clustering shared by every threshold rule.

Definitions (all windows are inclusive at both ends):

* A *qualifying window* is a set of at least ``threshold`` events whose first and last
  timestamps differ by at most ``window``.
* The tightest such window ending at event ``j`` consists of the ``threshold`` events
  ``j - threshold + 1 .. j``. Some qualifying window ends at ``j`` exactly when that tight
  window fits, so ``qualifying_window_ends`` only has to compare two timestamps per event.
* Two qualifying windows that share an event belong to one *cluster*. Consecutive qualifying
  ends ``j < j'`` share an event exactly when ``j' - j <= threshold - 1``, so clusters are runs
  of ends with no larger gap.

Everything is based on real timestamps, never on row counts, so gaps in a log correctly break
clusters apart.
"""

from __future__ import annotations

import numpy as np


def qualifying_window_ends(times: np.ndarray, threshold: int, window: np.timedelta64) -> np.ndarray:
    """Indices ``j`` of events that complete a qualifying window.

    ``times`` must be sorted ascending. Vectorised: O(n).
    """
    count = len(times)
    if count < threshold:
        return np.empty(0, dtype=np.intp)
    spans = times[threshold - 1 :] - times[: count - threshold + 1]
    return np.flatnonzero(spans <= window) + (threshold - 1)


def chain_ends(ends: np.ndarray, threshold: int) -> list[tuple[int, int, int, int]]:
    """Group qualifying ends into clusters.

    Returns ``(first_event, last_event, first_pos, stop_pos)`` per cluster: the inclusive event
    index range it covers (contiguous), and the slice ``ends[first_pos:stop_pos]`` of qualifying
    ends that form it.
    """
    if len(ends) == 0:
        return []
    breaks = np.flatnonzero(np.diff(ends) > threshold - 1) + 1
    starts = np.concatenate(([0], breaks))
    stops = np.concatenate((breaks, [len(ends)]))
    return [
        (int(ends[a]) - threshold + 1, int(ends[b - 1]), int(a), int(b))
        for a, b in zip(starts, stops, strict=True)
    ]


def find_clusters(
    times: np.ndarray, threshold: int, window: np.timedelta64
) -> list[tuple[int, int]]:
    """Clusters of events that meet a rolling-window threshold.

    Returns inclusive ``(first_index, last_index)`` pairs into ``times`` (sorted ascending).
    A sustained burst is one cluster, not one per event; bursts separated by more than the
    window are separate clusters.
    """
    ends = qualifying_window_ends(times, threshold, window)
    return [(first, last) for first, last, _, _ in chain_ends(ends, threshold)]
