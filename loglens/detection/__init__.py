"""Explainable, rule-based detection. Independent of the Streamlit UI."""

from .config import DetectionConfig
from .engine import run_detections, severity_counts
from .models import (
    CLASSIFICATION,
    SEVERITIES,
    SEVERITY_RANK,
    Alert,
    RuleInfo,
    alerts_to_frame,
    limited_join,
)
from .rules import RULE_CATALOG, describe_rules

__all__ = [
    "CLASSIFICATION",
    "RULE_CATALOG",
    "SEVERITIES",
    "SEVERITY_RANK",
    "Alert",
    "DetectionConfig",
    "RuleInfo",
    "alerts_to_frame",
    "describe_rules",
    "limited_join",
    "run_detections",
    "severity_counts",
]
