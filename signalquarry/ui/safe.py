"""Helpers for showing untrusted log content safely.

Usernames, file names and messages come from the uploaded file and must never be interpreted as
markup. Streamlit renders ``st.markdown`` text as Markdown, which can include images and - via
GitHub-style autolinking - clickable links, and backslash-escaping cannot stop the autolinker.
So the UI never passes log content to markdown. It uses:

* tables (``st.dataframe``), which show text literally;
* ``st.html`` with :func:`escape_html`, for the few sentences that mention log content;
* :func:`escape_label` for multiselect option labels (see its note).
"""

from __future__ import annotations

import html
import re

# Only the characters needed to build links, images, code spans or HTML. Everything else
# (including '.', '-', '_', '@' and '$', as in 'svc.backup' or 'WS01$') is left alone so that
# normal names read and search naturally.
_LABEL_SPECIAL = re.compile(r"([\\`\[\]()!<>])")


def escape_label(text: str) -> str:
    r"""Backslash-escape markup characters in a widget option label.

    Streamlit 1.66 shows option labels as plain text, so this is defence in depth in case a
    later release renders them as Markdown. The visible cost is a backslash before such
    characters, which ordinary usernames do not contain.
    """
    return _LABEL_SPECIAL.sub(r"\\\1", str(text))


def escape_html(text: str) -> str:
    """Escape text for use inside the few static HTML snippets the UI renders."""
    return html.escape(str(text), quote=True)
