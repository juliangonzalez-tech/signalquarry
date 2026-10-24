"""LogLens - Streamlit entry point.

Run from the project folder with:  streamlit run app.py
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from loglens.ui import components, sidebar, state, theme
from loglens.ui.views import alerts, explorer, guide, overview, reports

LOGO = Path(__file__).resolve().parent / "loglens" / "ui" / "assets" / "logo.svg"

st.set_page_config(
    page_title="LogLens - Security Log Analyzer",
    page_icon=":material/search_insights:",
    layout="wide",
    initial_sidebar_state="auto",
)
st.logo(str(LOGO), size="large")
theme.inject_css()
state.init_state()

pages = [
    st.Page(
        overview.render,
        title="Overview",
        icon=":material/dashboard:",
        url_path="overview",
        default=True,
    ),
    st.Page(
        alerts.render, title="Alerts", icon=":material/notifications_active:", url_path="alerts"
    ),
    st.Page(
        explorer.render, title="Event explorer", icon=":material/table_rows:", url_path="events"
    ),
    st.Page(reports.render, title="Reports", icon=":material/download:", url_path="reports"),
    st.Page(guide.render, title="Guide", icon=":material/menu_book:", url_path="guide"),
]
navigation = st.navigation(pages)
sidebar.render()  # builds the shared filters before the selected page reads them
components.show_load_error()
navigation.run()
