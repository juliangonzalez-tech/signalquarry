"""Guide page: the CSV format, how each rule works, and the limits of this kind of detection."""

from __future__ import annotations

import streamlit as st

from ...detection import RULE_CATALOG, describe_rules
from ...sample_data import BENIGN_SCENARIOS, SCENARIOS
from .. import components, state


def render() -> None:
    components.page_header(
        "Guide", "What LogLens does, how each detection works, and what it cannot tell you."
    )
    config = state.current_config()

    st.markdown("### Glossary")
    st.markdown(
        "- **Event**: one line of a log, such as a login attempt or an access request.\n"
        "- **Alert**: a *cluster* of events that crossed a detection threshold. One alert covers a "
        "whole burst, not one per event.\n"
        "- **Heuristic flag**: a rule-based lead that needs human review. LogLens never declares "
        "an incident confirmed.\n"
        "- **Rolling window**: the last N minutes before each event, measured with real "
        "timestamps. Window edges are inclusive: events exactly 10:00 apart share a 10-minute "
        "window.\n"
        "- **Evidence**: the exact log rows that support an alert."
    )

    st.markdown("### CSV format")
    components.schema_table()
    st.code(components.EXAMPLE_CSV, language="csv")
    st.markdown(
        "Comma-separated, UTF-8, one event per row, header in the first row, maximum 25 MB. "
        "Rows that fail validation are rejected **and reported** with their row number and "
        "reason; they are never dropped silently. Exact duplicate rows are counted and, by "
        "default, kept: with one-second timestamps, repeated attempts look like duplicates. "
        "The sidebar can remove them."
    )

    st.markdown("### Detection rules")
    # Cards, not a data grid: grids truncate long sentences, and the trigger is the point.
    for item in describe_rules(config):
        rule = item["rule"]
        with st.container(border=True):
            st.markdown(f"**{rule.rule_id} - {rule.name}**  \nBase severity: {rule.base_severity}")
            st.markdown(f"**Triggers when** (current settings): {item['trigger']}")
    st.markdown(
        "**How LL-003 correlates events.** The link between failures and a success is the "
        "**username**, regardless of source IP. A *qualifying burst* is a cluster of that "
        "account's failed logins, defined exactly as for LL-002. For every successful login at "
        "time *s*, LogLens considers the account's failures strictly before *s*; if the **last "
        "failure of a qualifying burst** was no more than the investigation window before *s*, "
        "the success is flagged. The window runs from the end of the burst, so a long burst does "
        "not shorten it. The evidence is every burst that ended inside the window plus the "
        "success, and several successes after the same burst are merged into one alert.\n\n"
        "**Severity.** Each rule has a base severity. It is raised by one level when an alert "
        "contains at least 3 times the rule's threshold in events (e.g. 15+ failures for the "
        "default threshold of 5).\n\n"
        "**No double counting inside a rule.** Overlapping windows are merged, so a sustained "
        "burst is one alert. Different rules may flag the same events, because they describe "
        "different perspectives (one IP versus one account)."
    )
    for rule in RULE_CATALOG.values():
        with st.expander(f"{rule.rule_id}: harmless explanations"):
            st.markdown("\n".join(f"- {cause}" for cause in rule.benign_causes))

    st.markdown("### Limitations and false positives")
    st.markdown(
        "- Rules use fixed thresholds. A determined attacker can stay under them (low-and-slow "
        "attempts), and a busy legitimate service can cross them.\n"
        "- Shared NAT, VPN and proxy addresses make many users look like one source IP.\n"
        "- A user who mistypes a password several times and then succeeds matches LL-003.\n"
        "- Logs with only second-level timestamps cannot order events within the same second.\n"
        "- An event recorded by two systems (say a gateway and an application server) is two rows "
        "and is counted twice, which can push a quiet account over a threshold.\n"
        "- Accounts are matched by exact (lower-cased) name: `DOMAIN\\alice`, `alice` and "
        "`alice@example.com` are three accounts.\n"
        "- Messages longer than 2,000 characters are truncated; usernames and hosts over 256 "
        "characters are rejected.\n"
        "- LogLens analyses one file at a time and has no knowledge of your network, users or "
        "threat intelligence.\n"
        "- **No alerts does not mean no attack**, and an alert does not mean there was one."
    )

    st.markdown("### Demo data scenarios")
    st.caption(
        "The demo dataset is synthetic. Accounts, addresses and incidents are made up. Scripted "
        "scenarios and the alerts they should produce with the default settings:"
    )
    table = ["| ID | Scenario | When | What happens | Expected |", "|---|---|---|---|---|"]
    table += [
        f"| {s.scenario_id} | {s.title} | {s.when} | {s.description} | {s.expect} |"
        for s in (*SCENARIOS, *BENIGN_SCENARIOS)
    ]
    st.markdown("\n".join(table))  # static text from sample_data; wraps instead of truncating

    st.markdown("### Privacy")
    st.markdown(
        "LogLens runs on this computer and only accepts connections from it. Your log data is "
        "parsed in memory, never transmitted to any service, and not stored on disk. Closing or "
        "reloading the browser tab ends the session: Streamlit keeps it for about two minutes in "
        "case you reconnect, then discards it, so reloading means loading the file again. Text "
        "from your logs is displayed as plain text, never interpreted as markup or code."
    )
