"""Shared table builders for the Streamlit pages (display columns for events)."""

from __future__ import annotations

import pandas as pd
import streamlit as st


def utc_naive(series: pd.Series) -> pd.Series:
    return series.dt.tz_convert("UTC").dt.tz_localize(None)


def event_table(events: pd.DataFrame, *, with_alerts: bool = False) -> pd.DataFrame:
    columns = {
        "Time (UTC)": utc_naive(events["timestamp"]),
        "Event": events["event_id"],
        "Source IP": events["source_ip"],
        "Account": events["username"],
        "Type": events["event_type"].str.replace("_", " "),
        "Outcome": events["outcome"],
    }
    if with_alerts:
        # Before the free-text columns, which are wide and push later columns off-screen.
        columns["Alerts"] = events["alert_ids"]
    columns["Host"] = events["host"]
    columns["Message"] = events["message"]
    return pd.DataFrame(columns)


EVENT_COLUMN_CONFIG = {
    "Time (UTC)": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss", width="medium"),
    "Message": st.column_config.TextColumn(width="large"),
}
