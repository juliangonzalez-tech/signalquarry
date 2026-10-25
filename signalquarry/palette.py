"""Colours shared by the charts and the UI, chosen for contrast on a dark background.

Colour is never the only signal: severities and outcomes are always also written out as text.
"""

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#FF6B8A",
    "high": "#FFA24C",
    "medium": "#F2D45C",
    "low": "#5EB8F0",
}

OUTCOME_COLORS: dict[str, str] = {
    "success": "#2EC4B6",
    "failure": "#F0636B",
    "denied": "#F5A623",
}

TEXT = "#E6EDF3"
MUTED_TEXT = "#9DA7B3"
GRID = "rgba(255, 255, 255, 0.08)"
ACCENT = "#4DA3FF"
