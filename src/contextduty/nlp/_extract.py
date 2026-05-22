"""Text segment extraction from source code and notebooks.

Pulls natural-language fragments (strings, comments, docstrings,
markdown cells, cell outputs) out of source files so the NER model
only sees prose — not raw syntax.
"""

from __future__ import annotations

import json
import re

# ---------------------------------------------------------------------------
# Compiled patterns (module-level for reuse)
# ---------------------------------------------------------------------------

_STRING_LITERAL = re.compile(
    r'(?:'
    r'"""[\s\S]*?"""|'        # triple-double-quoted
    r"'''[\s\S]*?'''|"        # triple-single-quoted
    r'f"""[\s\S]*?"""|'       # f-string triple-double
    r"f'''[\s\S]*?'''|"       # f-string triple-single
    r'"(?:[^"\\]|\\.)*"|'     # double-quoted
    r"'(?:[^'\\]|\\.)*'"      # single-quoted
    r')'
)

_COMMENT_LINE = re.compile(
    r'(?:'
    r'#\s*(.*?)$|'            # Python / Ruby / Shell
    r'//\s*(.*?)$|'           # JS / Java / Go / Rust
    r'/\*\s*([\s\S]*?)\s*\*/' # Block comments
    r')',
    re.MULTILINE,
)

# Minimum "looks like words" filter — avoids feeding symbols to the model.
_HAS_WORDS = re.compile(r'[a-zA-Z]{2,}')


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

Segment = tuple[str, str]  # (text, segment_type)


def extract_text_segments(source: str) -> list[Segment]:
    """Extract natural-language segments from source code.

    Returns:
        List of ``(segment_text, segment_type)`` tuples where
        *segment_type* is one of ``"string"``, ``"comment"``, or
        ``"docstring"``.
    """
    segments: list[Segment] = []

    for match in _STRING_LITERAL.finditer(source):
        raw = match.group(0)
        if raw.startswith(('"""', "'''", 'f"""', "f'''")):
            prefix = 4 if raw.startswith("f") else 3
            text = raw[prefix:-3]
            seg_type = "docstring"
        else:
            prefix = 2 if raw.startswith(("f'", 'f"')) else 1
            text = raw[prefix:-1]
            seg_type = "string"

        if text and _HAS_WORDS.search(text):
            segments.append((text, seg_type))

    for match in _COMMENT_LINE.finditer(source):
        text = match.group(1) or match.group(2) or match.group(3) or ""
        text = text.strip()
        if text and _HAS_WORDS.search(text):
            segments.append((text, "comment"))

    return segments


def extract_notebook_text(notebook_source: str) -> list[Segment]:
    """Extract text segments from a Jupyter ``.ipynb`` JSON string.

    Handles markdown cells (as-is), code cells (via
    :func:`extract_text_segments`), and cell outputs.
    """
    segments: list[Segment] = []
    try:
        nb = json.loads(notebook_source)
    except (json.JSONDecodeError, TypeError):
        return segments

    for cell in nb.get("cells", []):
        cell_type = cell.get("cell_type", "")
        raw_source = cell.get("source", [])
        text = "".join(raw_source) if isinstance(raw_source, list) else raw_source

        if cell_type == "markdown":
            segments.append((text, "markdown"))
        elif cell_type == "code":
            segments.extend(extract_text_segments(text))

        for output in cell.get("outputs", []):
            out_text = output.get("text", [])
            if isinstance(out_text, list):
                out_text = "".join(out_text)
            if out_text and _HAS_WORDS.search(out_text):
                segments.append((out_text, "output"))

    return segments
