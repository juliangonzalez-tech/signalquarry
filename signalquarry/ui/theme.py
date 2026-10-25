"""Page styling. The CSS is static; no log content is ever interpolated into it."""

from __future__ import annotations

import streamlit as st

from ..palette import ACCENT, MUTED_TEXT, SEVERITY_COLORS

_SEVERITY_RULES = "\n".join(
    f"  .ll-sev-{name} {{{{ border-left-color: {color}; }}}}\n"
    f"  .ll-badge-{name} {{{{ color: {color}; border-color: {color}; }}}}"
    for name, color in SEVERITY_COLORS.items()
)

_CSS = f"""
<style>
  .block-container {{ padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1400px; }}
  h1, h2, h3 {{ letter-spacing: -0.01em; }}

  .ll-header h1 {{ margin: 0 0 .15rem 0; font-size: 1.9rem; font-weight: 700; }}
  .ll-header p {{ margin: 0 0 1rem 0; color: {MUTED_TEXT}; font-size: .98rem; }}

  .ll-scope {{
    background: #161B22; border: 1px solid #2A313C; border-left: 3px solid {ACCENT};
    border-radius: 8px; padding: .55rem .9rem; margin: 0 0 1.1rem 0;
    font-size: .88rem; color: #C9D1D9;
  }}
  .ll-scope b {{ color: #E6EDF3; }}
  .ll-scope .ll-dim {{ color: {MUTED_TEXT}; }}

  .ll-sev {{
    background: #161B22; border: 1px solid #2A313C; border-radius: 10px;
    padding: .75rem 1rem; border-left-width: 5px;
  }}
  .ll-sev .ll-n {{ font-size: 1.85rem; font-weight: 700; line-height: 1.15; color: #E6EDF3; }}
  .ll-sev .ll-l {{
    font-size: .76rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: .07em; color: {MUTED_TEXT};
  }}
  .ll-badge {{
    display: inline-block; padding: .08rem .6rem; border-radius: 999px;
    font-size: .78rem; font-weight: 650; border: 1px solid; text-transform: uppercase;
    letter-spacing: .04em;
  }}
{_SEVERITY_RULES}

  .ll-dim {{ color: {MUTED_TEXT}; }}
  .ll-plain {{ margin: 0 0 .6rem 0; line-height: 1.55; color: #E6EDF3; overflow-wrap: anywhere; }}
  ul.ll-plain {{ padding-left: 1.2rem; }}
  .ll-sidecap {{ font-size: .85rem; color: {MUTED_TEXT}; overflow-wrap: anywhere; }}
  .ll-sidecap b {{ color: #E6EDF3; }}
  .ll-alert {{
    border-radius: 8px; padding: .75rem 1rem; margin: 0 0 1rem 0; line-height: 1.5;
    overflow-wrap: anywhere;
  }}
  .ll-alert-error {{
    background: rgba(240, 99, 107, .12); border: 1px solid rgba(240, 99, 107, .55);
    color: #FFD9DC;
  }}
  .ll-step {{ font-weight: 650; color: {ACCENT}; }}
  [data-testid="stMetricValue"] {{ font-weight: 700; }}
</style>
"""


def inject_css() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
