"""Team-layer metadata model — the privacy contract.

The team layer aggregates *metadata only* from many endpoints. The matched
value, file content, and prompt text NEVER leave the machine. This module is
the single enforcement point: :func:`sanitize_event` allow-lists the fields
that may be transmitted and drops everything else, so a bug elsewhere cannot
leak content into the fleet stream.

This "metadata never content" property is the differentiator that cloud DLP
tools (Nightfall, Cyberhaven, LayerX) structurally cannot offer. Guard it.
"""

from __future__ import annotations

from typing import Any

# The ONLY keys allowed to leave an endpoint. Anything else is dropped.
_ALLOWED_TOP_LEVEL: frozenset[str] = frozenset(
    {
        "schema",  # metadata schema version
        "ts",  # ISO timestamp
        "host",  # hostname or hash (identity, not content)
        "user",  # username or hash
        "repo",  # repo name or hash
        "tool",  # cli | hook | proxy | mcp | ci
        "event",  # heartbeat | block | warn | redact | bypass | uninstall | proxy_stop
        "policy_hash",  # sha256 of the active policy (not its content)
        "surfaces",  # {hook: bool, proxy: bool, ide: bool, mcp: bool}
        "detector_counts",  # {detector_name: int}  — names + counts ONLY
        "findings_count",  # int
        "blocked",  # bool
        "detail",  # short enum string for bypass/uninstall events (no content)
    }
)

# Nested dicts whose *keys* are detector names and *values* are integer counts.
_COUNT_MAPS: frozenset[str] = frozenset({"detector_counts"})

VALID_EVENTS: frozenset[str] = frozenset(
    {
        "heartbeat",
        "block",
        "warn",
        "redact",
        "bypass",
        "hook_uninstall",
        "proxy_stop",
    }
)

SCHEMA_VERSION = 1


def sanitize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *raw* containing only allow-listed metadata fields.

    Drops any unknown key, coerces count maps to ``{str: int}``, and guarantees
    no free-text/content field can pass through. This is defense-in-depth: even
    if a caller accidentally attaches a matched value, it is stripped here.
    """
    clean: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in _ALLOWED_TOP_LEVEL:
            continue
        if key in _COUNT_MAPS and isinstance(value, dict):
            counts: dict[str, int] = {}
            for k, v in value.items():
                if isinstance(v, bool):
                    continue
                try:
                    counts[str(k)] = int(v)
                except (ValueError, TypeError):
                    continue
            clean[key] = counts
        elif key == "surfaces" and isinstance(value, dict):
            clean[key] = {str(k): bool(v) for k, v in value.items()}
        else:
            clean[key] = value
    clean["schema"] = SCHEMA_VERSION
    return clean


def is_content_free(event: dict[str, Any]) -> bool:
    """Return True if *event* contains only allow-listed keys (no content leak)."""
    return set(event).issubset(_ALLOWED_TOP_LEVEL)
