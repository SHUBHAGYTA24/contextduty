"""Shared workspace-scanning utilities used by protect, cursor, and adapters.

All workspace-level helpers live here so they have a single implementation.
Other modules import from this module instead of duplicating the logic.
"""

from __future__ import annotations

import os
from pathlib import Path

from .config import BINARY_EXTENSIONS, DEFAULT_POLICY_FILE, SKIP_DIRECTORIES
from .engine import _active_detectors, _scan_line
from .policy import Policy, load_policy

__all__ = [
    "load_policy_auto",
    "scan_workspace",
    "load_gitignore",
    "matches_gitignore",
]


def load_policy_auto(policy_path: str | None) -> Policy:
    """Return a Policy from *policy_path*, or the workspace default, or the built-in default.

    Args:
        policy_path: Explicit path supplied by the caller, or None.

    Returns:
        A fully resolved Policy object.
    """
    if policy_path:
        p = Path(policy_path)
        return load_policy(p if p.exists() else None)
    default = Path(DEFAULT_POLICY_FILE)
    return load_policy(default if default.exists() else None)


def scan_workspace(
    workspace: Path,
    policy: Policy,
) -> list[tuple[str, set[str]]]:
    """Scan all text files under *workspace* and return those containing secrets/PII.

    Args:
        workspace: Root directory to walk.
        policy: Active policy controlling which detectors fire.

    Returns:
        List of *(relative_path, detector_names)* for every file that produced
        at least one finding.  Relative paths use the OS path separator.
    """
    detectors = _active_detectors(policy)
    gitignore_patterns = load_gitignore(workspace)
    sensitive: list[tuple[str, set[str]]] = []

    for root, dirs, files in os.walk(workspace):
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".") and d not in SKIP_DIRECTORIES
        ]

        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in BINARY_EXTENSIONS:
                continue

            rel = str(fpath.relative_to(workspace))
            if matches_gitignore(rel, gitignore_patterns):
                continue

            try:
                detector_hits: set[str] = set()
                with fpath.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        for finding in _scan_line(line, detectors):
                            detector_hits.add(finding.detector)
                if detector_hits:
                    sensitive.append((rel, detector_hits))
            except (OSError, UnicodeDecodeError):
                continue

    return sensitive


def load_gitignore(workspace: Path) -> list[str]:
    """Return non-comment, non-empty patterns from *workspace*/.gitignore."""
    gi = workspace / ".gitignore"
    if not gi.exists():
        return []
    return [
        line.strip()
        for line in gi.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def matches_gitignore(rel_path: str, patterns: list[str]) -> bool:
    """Return True if *rel_path* is matched by any pattern in *patterns*.

    Supports directory prefixes and ``*.ext`` glob-suffix patterns.  This is
    intentionally a simplified subset of gitignore semantics sufficient for
    workspace scanning.
    """
    for pat in patterns:
        pat_clean = pat.rstrip("/")
        if pat_clean in rel_path or rel_path.startswith(pat_clean + "/"):
            return True
        if pat_clean.startswith("*") and rel_path.endswith(pat_clean[1:]):
            return True
    return False
