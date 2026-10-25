"""Drive the real Streamlit script headlessly (streamlit.testing) through the main workflows."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from signalquarry.ui.safe import escape_html, escape_label

APP = str(Path(__file__).resolve().parent.parent / "app.py")
TIMEOUT = 180  # generous: a cold start on a loaded machine must not make a test flaky


def fresh_app() -> AppTest:
    app = AppTest.from_file(APP, default_timeout=TIMEOUT)
    app.run()
    return app


def load_demo(app: AppTest) -> AppTest:
    next(b for b in app.sidebar.button if b.key == "sidebar_demo").click()
    return app.run()


def metric_values(app: AppTest) -> dict[str, str]:
    return {m.label: m.value for m in app.metric}


def test_first_screen_is_a_welcome_with_no_errors():
    app = fresh_app()
    assert not app.exception
    text = " ".join(m.value for m in app.markdown)
    assert "Welcome to SignalQuarry" in text
    assert any(b.key == "welcome_demo" for b in app.button)
    assert not app.metric  # no numbers before data is loaded


def test_loading_demo_data_shows_real_metrics_and_the_synthetic_label():
    app = load_demo(fresh_app())
    assert not app.exception
    values = metric_values(app)
    assert values["Total events"] == "777"
    assert values["Failed authentications"] == "70"
    assert values["Unique source IPs"] == "38"
    assert values["Flagged event clusters"] == "10"
    assert any("Synthetic demo data" in i.value for i in app.info)


def test_welcome_button_also_loads_the_demo():
    app = fresh_app()
    next(b for b in app.button if b.key == "welcome_demo").click()
    app.run()
    assert not app.exception
    assert metric_values(app)["Total events"] == "777"


def test_filters_change_the_numbers_and_reset_restores_them():
    app = load_demo(fresh_app())
    users = next(m for m in app.sidebar.multiselect if m.label == "Username")
    users.set_value(["svc.reporting"]).run()
    assert not app.exception
    scoped = metric_values(app)
    assert int(scoped["Total events"].replace(",", "")) < 777
    assert scoped["Flagged event clusters"] == "3"  # the three svc.reporting alerts

    next(b for b in app.sidebar.button if b.key == "sidebar_reset").click()
    app.run()
    assert metric_values(app)["Total events"] == "777"


def test_time_range_slider_filters_events_with_inclusive_end_minute():
    from datetime import datetime

    import pandas as pd

    from signalquarry.pipeline import load_demo_dataset

    events = load_demo_dataset().events
    app = load_demo(fresh_app())
    slider = next(s for s in app.sidebar.slider if s.label == "Time range (UTC)")
    low, high = slider.value  # defaults to the full range of the data

    start = pd.Timestamp("2026-03-03T00:00:00Z")
    slider.set_range(datetime(2026, 3, 3, 0, 0), high).run()
    assert not app.exception
    assert metric_values(app)["Total events"] == f"{(events['timestamp'] >= start).sum():,}"

    # Minute precision: the selected end minute is included in full (03:17:00 - 03:17:59).
    slider = next(s for s in app.sidebar.slider if s.label == "Time range (UTC)")
    slider.set_range(datetime(2026, 3, 2, 3, 12), datetime(2026, 3, 2, 3, 17)).run()
    window = events[
        (events["timestamp"] >= pd.Timestamp("2026-03-02T03:12:00Z"))
        & (events["timestamp"] < pd.Timestamp("2026-03-02T03:18:00Z"))
    ]
    assert metric_values(app)["Total events"] == f"{len(window):,}"
    assert len(window) == 16  # the svc.backup brute-force burst, last attempt at 03:17:52
    assert metric_values(app)["Flagged event clusters"] == "2"  # ALR-0001 and ALR-0002


def test_each_sidebar_filter_widget_is_wired_to_the_right_field():
    from signalquarry.pipeline import load_demo_dataset

    events = load_demo_dataset().events
    cases = {
        "Source IP": (["203.0.113.45"], events["source_ip"] == "203.0.113.45"),
        "Username": (["svc.etl"], events["username"] == "svc.etl"),
        "Event type": (["password_change"], events["event_type"] == "password_change"),
        "Outcome": (["denied"], events["outcome"] == "denied"),
    }
    for label, (values, mask) in cases.items():
        app = load_demo(fresh_app())
        next(m for m in app.sidebar.multiselect if m.label == label).set_value(values).run()
        assert not app.exception
        assert metric_values(app)["Total events"] == f"{int(mask.sum()):,}", label
        assert 0 < int(mask.sum()) < len(events), f"{label}: pick a filter that really filters"

    # Widgets combine with AND, and several selections within one widget combine with OR.
    app = load_demo(fresh_app())
    next(m for m in app.sidebar.multiselect if m.label == "Username").set_value(["svc.reporting"])
    next(m for m in app.sidebar.multiselect if m.label == "Outcome").set_value(["failure"]).run()
    assert metric_values(app)["Total events"] == "16"
    next(m for m in app.sidebar.multiselect if m.label == "Outcome").set_value(
        ["failure", "success"]
    ).run()
    expected = int(
        (
            (events["username"] == "svc.reporting") & events["outcome"].isin(["failure", "success"])
        ).sum()
    )
    assert metric_values(app)["Total events"] == str(expected)


def test_search_filter_matches_the_scope_bar_and_metrics():
    app = load_demo(fresh_app())
    next(t for t in app.sidebar.text_input if t.label == "Search").set_value("ALR-0010").run()
    assert not app.exception
    assert metric_values(app)["Total events"] == "6"
    assert metric_values(app)["Flagged event clusters"] == "1"


def test_every_detection_setting_explains_itself_and_matches_the_defaults():
    from signalquarry.detection import DetectionConfig

    app = load_demo(fresh_app())
    controls = {n.key.removeprefix("cfg_"): n for n in app.sidebar.number_input}
    defaults = DetectionConfig()
    assert len(controls) == 7
    for name, control in controls.items():
        assert control.help and len(control.help) > 30, name
        assert control.value == getattr(defaults, name), name
    assert "AFTER the last failure" in controls["success_investigation_minutes"].help


def test_detection_settings_change_the_alerts():
    app = load_demo(fresh_app())
    box = next(n for n in app.sidebar.number_input if n.key == "cfg_denial_threshold")
    box.set_value(3).run()  # emma.larsen has exactly 3 denials in the demo data
    assert not app.exception
    assert metric_values(app)["Flagged event clusters"] == "11"
    next(b for b in app.sidebar.button if b.key == "sidebar_defaults").click()
    app.run()
    assert metric_values(app)["Flagged event clusters"] == "10"


def _render_view(page: str, load_demo_data: bool) -> None:
    """Script executed by AppTest: sidebar + one page, as app.py would run them."""
    import importlib

    import streamlit as st

    from signalquarry.ui import sidebar, state

    state.init_state()
    if load_demo_data and st.session_state[state.DATASET] is None:
        state.load_demo()
    sidebar.render()
    importlib.import_module(f"signalquarry.ui.views.{page}").render()


def view_app(page: str, *, demo: bool = True) -> AppTest:
    app = AppTest.from_function(_render_view, args=(page, demo), default_timeout=TIMEOUT)
    return app.run()


@pytest.mark.parametrize("page", ["overview", "alerts", "explorer", "reports", "guide"])
@pytest.mark.parametrize("demo", [True, False])
def test_every_page_renders_with_and_without_data(page, demo):
    app = view_app(page, demo=demo)
    assert not app.exception
    if not demo and page != "guide":
        assert any("Welcome to SignalQuarry" in m.value for m in app.markdown)


def test_reference_content_is_wrapping_text_not_a_truncating_grid():
    # Regression: the rule triggers, CSV columns and scenarios were in data grids, which cut
    # long sentences off ("5+ failed logins from the same sour..."), hiding the key information.
    guide = view_app("guide", demo=False)
    markdown = " ".join(m.value for m in guide.markdown)
    for rule in ("LL-001", "LL-002", "LL-003", "LL-004"):
        assert f"**{rule} - " in markdown
    assert markdown.count("**Triggers when**") == 4
    assert "5+ failed logins from the same source IP within 10 minutes" in markdown
    assert "| `timestamp` | yes |" in markdown and "| S1 | Single-source brute force" in markdown
    assert not guide.dataframe  # nothing important sits inside a truncating grid

    welcome = AppTest.from_file(APP, default_timeout=TIMEOUT).run()
    assert "| `username` | yes |" in " ".join(m.value for m in welcome.markdown)


def test_alerts_page_lists_every_alert_and_shows_its_evidence():
    app = view_app("alerts")
    assert not app.exception
    inspector = next(s for s in app.selectbox if s.key == "inspect_alert")
    assert len(inspector.options) == 10
    table = app.dataframe[0].value
    assert len(table) == 10
    assert list(table.columns[:3]) == ["Time (UTC)", "Alert", "Severity"]

    inspector.select("ALR-0009").run()  # critical: brute force then success
    evidence = app.dataframe[1].value
    assert len(evidence) == 17  # 16 failures + the success
    assert set(evidence["Outcome"]) == {"failure", "success"}
    assert set(evidence["Account"]) == {"svc.reporting"}


def test_alert_filters_narrow_the_table():
    app = view_app("alerts")
    next(m for m in app.multiselect if m.key == "alerts_severity").set_value(["critical"]).run()
    assert not app.exception
    assert list(app.dataframe[0].value["Alert"]) == ["ALR-0009"]

    app = view_app("alerts")
    next(m for m in app.multiselect if m.key == "alerts_rule").set_value(["LL-004"]).run()
    assert list(app.dataframe[0].value["Alert"]) == ["ALR-0010"]

    app = view_app("alerts")
    next(t for t in app.text_input if t.key == "alerts_text").set_value("203.0.113.99").run()
    assert list(app.dataframe[0].value["Alert"]) == ["ALR-0003"]


def test_alerts_sort_option_orders_the_table():
    app = view_app("alerts")
    by_severity = list(app.dataframe[0].value["Alert"])
    assert by_severity[0] == "ALR-0009"  # critical first
    assert by_severity[-1] == "ALR-0010"  # the only low alert last
    next(s for s in app.selectbox if s.key == "alerts_sort").select("Time (oldest first)").run()
    # Equal start times are ordered by severity, highest first: ALR-0006 (high) before
    # ALR-0005 (medium) at 16:20, and the critical ALR-0009 before ALR-0007/8 at 01:47.
    expected = [1, 2, 3, 4, 6, 5, 9, 7, 8, 10]
    assert list(app.dataframe[0].value["Alert"]) == [f"ALR-{n:04d}" for n in expected]


def test_event_explorer_table_matches_the_scope():
    app = view_app("explorer")
    assert not app.exception
    assert len(app.dataframe[0].value) == 777
    next(t for t in app.sidebar.text_input if t.label == "Search").set_value("priya.raman").run()
    table = app.dataframe[0].value
    assert set(table["Account"]) == {"priya.raman"}
    assert len(table) == next(int(m.value) for m in app.metric if m.label == "Events shown")
    next(t for t in app.toggle if t.key == "explorer_only_flagged").set_value(True).run()
    assert len(app.dataframe[0].value) == 6  # only the six denials that form ALR-0010


def test_empty_filter_result_shows_a_helpful_empty_state():
    app = view_app("explorer")
    next(t for t in app.sidebar.text_input if t.label == "Search").set_value("zzz-no-match").run()
    assert not app.exception
    assert any("No events match" in i.value for i in app.info)


def test_label_and_html_escaping():
    hostile = "![x](https://example.invalid/p.png)"
    assert "![" not in escape_label(hostile) and "](" not in escape_label(hostile)
    for ordinary in ("svc.backup_01-a@example", "WS01$", "alice.morgan", "o'brien"):
        assert escape_label(ordinary) == ordinary  # ordinary names read and search naturally
    assert escape_label("<img src=x>") == r"\<img src=x\>"
    assert escape_html("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def _render_hostile(page: str) -> None:
    """Script executed by AppTest: a *valid* file whose text fields are all attack payloads."""
    import importlib

    import streamlit as st

    from signalquarry.pipeline import build_dataset
    from signalquarry.ui import sidebar, state

    state.init_state()
    if st.session_state[state.DATASET] is None:
        evil = [
            "![x](https://example.invalid/pixel.png)",
            "[click](https://example.invalid/c)",
            "<img src=x onerror=alert(1)>",
            "=cmd|' /C calc'!A0",
            ":red[boom]",
            "https://example.invalid/autolink",
        ]
        lines = ["timestamp,source_ip,username,event_type,outcome,host,message"]
        for i in range(6):  # a burst that raises alerts naming the first payload
            lines.append(
                f'2026-03-02T10:0{i}:00Z,203.0.113.7,"{evil[0]}",login,failure,'
                '"=HYPERLINK(""https://example.invalid/h"")","![m](https://example.invalid/m.png)"'
            )
        for i, name in enumerate(evil[1:]):
            lines.append(
                f'2026-03-02T11:0{i}:00Z,192.0.2.{i + 1},"{name.replace(chr(34), chr(34) * 2)}",'
                "login,success,h,ok"
            )
        name = "![f](https://example.invalid/f.png).csv"
        state._install(build_dataset(name, "\n".join(lines).encode()))
    sidebar.render()
    importlib.import_module(f"signalquarry.ui.views.{page}").render()


MARKDOWN_ELEMENTS = ("markdown", "caption", "info", "error", "warning", "success", "subheader")


@pytest.mark.parametrize("page", ["overview", "alerts", "explorer", "reports"])
def test_hostile_log_content_never_reaches_markdown_rendering(page):
    app = AppTest.from_function(_render_hostile, args=(page,), default_timeout=TIMEOUT).run()
    assert not app.exception
    for kind in MARKDOWN_ELEMENTS:
        for element in app.get(kind):
            assert "example.invalid" not in element.value, (page, kind, element.value)
            assert "onerror" not in element.value, (page, kind, element.value)
    # the hostile usernames are still usable as filter options, with markup characters escaped
    users = next(m for m in app.sidebar.multiselect if m.label == "Username")
    assert any("example" in label for label in users.options)
    for label in users.options:
        assert "![" not in label.replace("\\!", "") and "](" not in label.replace("\\)", "")
    # the hostile file name appears (escaped) only in an html element, never as markdown
    assert not any("example.invalid" in c.value for c in app.sidebar.caption)


def _render_many_users() -> None:
    import streamlit as st

    from signalquarry.pipeline import build_dataset
    from signalquarry.ui import sidebar, state

    state.init_state()
    if st.session_state[state.DATASET] is None:
        lines = ["timestamp,source_ip,username,event_type,outcome"]
        for i in range(2500):  # 2,500 distinct usernames and 2,500 distinct IPs
            lines.append(
                f"2026-03-02T10:{i // 60 % 60:02d}:{i % 60:02d}Z,10.{i // 250}.{i % 250}.1,"
                f"user{i:04d},login,success"
            )
        state._install(build_dataset("many.csv", "\n".join(lines).encode()))
    sidebar.render()


def _run_ingest_scenario(scenario: str) -> None:
    """Script executed by AppTest: feed ``state.ingest_upload`` stand-ins for uploaded files."""
    from types import SimpleNamespace

    import streamlit as st

    from signalquarry.ui import state

    state.init_state()
    header = "timestamp,source_ip,username,event_type,outcome\n"
    good = header + "2026-03-02T10:00:00Z,192.0.2.1,alice,login,success\n"

    def upload(name, content, file_id):
        data = content.encode()
        return SimpleNamespace(name=name, file_id=file_id, getvalue=lambda: data)

    def dataset_label():
        dataset = st.session_state[state.DATASET]
        return dataset.label if dataset else None

    probe = {}
    if scenario == "invalid_after_valid":
        state.ingest_upload(upload("good.csv", good, "id-1"))
        state.ingest_upload(upload("bad.csv", "a,b\n1,2\n", "id-2"))
    elif scenario == "invalid_then_removed":
        state.ingest_upload(upload("good.csv", good, "id-1"))
        state.ingest_upload(upload("bad.csv", "a,b\n1,2\n", "id-2"))
        state.ingest_upload(None)  # the user clears the uploader
    elif scenario == "same_upload_twice":
        state.ingest_upload(upload("first.csv", good, "id-1"))
        state.ingest_upload(upload("second.csv", good, "id-1"))  # same widget file id: ignored
    elif scenario == "no_valid_rows":
        state.ingest_upload(upload("junk.csv", header + "nope,x,y,z,w\n" * 3, "id-1"))
    elif scenario == "unexpected_exception":
        state.ingest_upload(upload("good.csv", good, "id-1"))
        original = state.build_dataset

        def explode(*args, **kwargs):
            raise RuntimeError("secret-data-123 must never be shown")

        state.build_dataset = explode
        try:
            state.ingest_upload(upload("next.csv", good, "id-2"))
        finally:
            state.build_dataset = original
    elif scenario == "duplicate_toggle":
        twice = header + good.split("\n")[1] + "\n" + good.split("\n")[1] + "\n"
        state.ingest_upload(upload("dupes.csv", twice, "id-1"))
        probe["kept"] = len(st.session_state[state.DATASET].events)
        epoch = st.session_state[state.FILTER_EPOCH]
        st.session_state[state.DROP_DUPLICATES] = True
        state.on_duplicate_toggle()
        probe["removed"] = len(st.session_state[state.DATASET].events)
        probe["epoch_bumped"] = st.session_state[state.FILTER_EPOCH] > epoch
    probe["label"] = dataset_label()
    probe["error"] = st.session_state[state.LOAD_ERROR]
    st.session_state["probe"] = probe


def ingest(scenario: str) -> dict:
    app = AppTest.from_function(_run_ingest_scenario, args=(scenario,), default_timeout=TIMEOUT)
    app.run()
    assert not app.exception
    return app.session_state["probe"]


def test_an_invalid_upload_keeps_the_previously_loaded_data():
    probe = ingest("invalid_after_valid")
    assert probe["label"] == "good.csv"
    assert "Missing required column" in probe["error"] and "bad.csv" in probe["error"]


def test_the_same_uploaded_file_is_only_processed_once():
    assert ingest("same_upload_twice")["label"] == "first.csv"


def test_an_upload_with_no_valid_rows_is_refused_with_the_reasons():
    probe = ingest("no_valid_rows")
    assert probe["label"] is None
    assert "none of its 3 rows were valid" in probe["error"]
    assert "timestamp" in probe["error"]


def test_an_unexpected_parser_failure_is_contained_and_never_echoes_data():
    probe = ingest("unexpected_exception")
    assert probe["label"] == "good.csv"  # previous data intact
    assert "RuntimeError" in probe["error"]
    assert "secret-data-123" not in probe["error"]


def test_toggling_duplicate_removal_reparses_the_same_file():
    probe = ingest("duplicate_toggle")
    assert (probe["kept"], probe["removed"]) == (2, 1)  # duplicates are kept until asked
    assert not probe["epoch_bumped"]  # same file: the filters are kept (see the next test)


def test_toggling_duplicate_removal_keeps_the_sidebar_filters():
    app = load_demo(fresh_app())
    users = next(m for m in app.sidebar.multiselect if m.label == "Username")
    users.set_value(["svc.reporting"]).run()
    scoped = metric_values(app)["Total events"]
    assert scoped != "777"

    next(c for c in app.sidebar.checkbox if c.key == "opt_drop_duplicates").check().run()
    assert not app.exception
    users = next(m for m in app.sidebar.multiselect if m.label == "Username")
    assert users.value == ["svc.reporting"]
    assert metric_values(app)["Total events"] == scoped  # the demo has no duplicates


def test_a_load_error_names_the_data_still_shown_and_clears_when_the_file_is_removed():
    probe = ingest("invalid_after_valid")
    assert "still show the previously loaded data (good.csv)" in probe["error"]
    assert ingest("invalid_then_removed")["error"] is None


def test_settings_widgets_take_their_values_only_from_session_state(monkeypatch):
    """'Restore defaults' writes the cfg_ keys. A widget that also passed ``value=`` made the real
    server log "created with a default value but also had its value set via the Session State
    API" with a stack trace. (AppTest cannot observe that log line, so check its cause.)"""
    import streamlit as st

    calls = []
    original = st.number_input

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(st, "number_input", spy)
    app = load_demo(fresh_app())
    next(n for n in app.sidebar.number_input if n.key == "cfg_ip_failure_threshold").set_value(
        4
    ).run()
    assert metric_values(app)["Flagged event clusters"] == "11"
    next(b for b in app.sidebar.button if b.key == "sidebar_defaults").click()
    app.run()
    assert not app.exception
    assert metric_values(app)["Flagged event clusters"] == "10"
    settings = [c for c in calls if str(c.get("key", "")).startswith("cfg_")]
    assert settings and all("value" not in c for c in settings)


def test_changed_detection_settings_are_named_in_the_scope_bar():
    from signalquarry.detection import DetectionConfig
    from signalquarry.ui.state import changed_settings

    app = load_demo(fresh_app())
    assert "Detection settings changed" not in " ".join(h.proto.body for h in app.get("html"))
    next(n for n in app.sidebar.number_input if n.key == "cfg_ip_failure_threshold").set_value(
        4
    ).run()
    html = " ".join(h.proto.body for h in app.get("html"))
    assert "Detection settings changed:" in html
    assert "LL-001: failed logins per IP = 4 (default 5)" in html
    assert changed_settings(DetectionConfig()) == []


def test_severity_labels_sort_in_severity_order():
    from signalquarry.detection import SEVERITIES
    from signalquarry.ui.components import severity_label

    labels = [severity_label(level) for level in SEVERITIES]
    assert sorted(labels) == labels  # what clicking the column header does
    assert [label.split(" - ")[1].split()[0].lower() for label in labels] == list(SEVERITIES)


def test_filter_pick_lists_are_capped_but_search_still_finds_everything():
    app = AppTest.from_function(_render_many_users, default_timeout=TIMEOUT).run()
    assert not app.exception
    users = next(m for m in app.sidebar.multiselect if m.label == "Username")
    ips = next(m for m in app.sidebar.multiselect if m.label == "Source IP")
    assert len(users.options) == 2000 and len(ips.options) == 2000
    assert any("2,000 most frequent" in c.value for c in app.sidebar.caption)
    next(t for t in app.sidebar.text_input if t.label == "Search").set_value("user2499").run()
    assert not app.exception  # a value outside the pick-list is still reachable via Search


def test_hostile_alert_evidence_is_shown_as_data_and_flagged():
    app = AppTest.from_function(_render_hostile, args=("alerts",), default_timeout=TIMEOUT).run()
    assert not app.exception
    table = app.dataframe[0].value
    assert len(table) == 2  # LL-001 and LL-002 for the burst against the hostile username
    assert any("![x](https://example.invalid/pixel.png)" in value for value in table["Account"])
