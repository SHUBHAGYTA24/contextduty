"""Cursor workspace protection — generate and maintain .cursorignore.

Scans the workspace for files containing secrets/PII and writes them to
.cursorignore so Cursor never indexes or sends them to any AI model
(Claude, GPT-4, Gemini — all covered by a single upstream block).

Commands:
    contextduty cursor setup  — scan workspace, write .cursorignore
    contextduty cursor watch  — background daemon, update .cursorignore on change
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .engine import _BINARY_EXTENSIONS, _active_detectors, _scan_line
from .policy import Policy, load_policy

_HEADER = """\
# ContextDuty — auto-generated .cursorignore
# Files listed here contain secrets or PII detected by ContextDuty.
# Cursor will NOT index or send these files to any AI model.
#
# Re-generate: contextduty cursor setup
# Auto-update: contextduty cursor watch
#
# Manual entries below the AUTO-END marker are preserved.

# ── AUTO-START (do not edit between START/END) ──
"""

_FOOTER = "# ── AUTO-END ──\n"

_BOLD = "\033[1m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def cursor_setup(
    workspace: Path,
    policy_path: str | None = None,
    output: Path | None = None,
) -> int:
    """Scan workspace and write .cursorignore with sensitive file paths."""
    policy = _load_policy(policy_path)
    ignore_path = output or (workspace / ".cursorignore")

    print(f"\n{_BOLD}ContextDuty — Cursor Workspace Protection{_RESET}\n")
    print(f"  Scanning   {_DIM}{workspace}{_RESET}")
    print(f"  Policy     {_DIM}{policy_path or 'default'}{_RESET}")
    print()

    sensitive_files = _scan_workspace(workspace, policy)

    if not sensitive_files:
        print(f"  {_GREEN}✓{_RESET}  No secrets detected — workspace is clean.")
        print("     Cursor can safely index all files.")
        return 0

    print(f"  {_YELLOW}⚠{_RESET}  {len(sensitive_files)} file(s) contain secrets/PII:\n")
    for fpath, detectors in sensitive_files[:20]:
        det_str = ", ".join(sorted(detectors))
        print(f"     {_DIM}{fpath}{_RESET}  [{det_str}]")
    if len(sensitive_files) > 20:
        print(f"     {_DIM}... and {len(sensitive_files) - 20} more{_RESET}")

    # Write .cursorignore
    _write_cursorignore(ignore_path, sensitive_files, workspace)

    print(f"\n  {_GREEN}✓{_RESET}  Written {_BOLD}{ignore_path}{_RESET}")
    print(f"     {len(sensitive_files)} files blocked from Cursor indexing.")
    print(f"\n  {_DIM}Keep it updated: contextduty cursor watch{_RESET}\n")
    return 0


def cursor_watch(
    workspace: Path,
    policy_path: str | None = None,
    interval: int = 30,
) -> int:
    """Watch workspace and update .cursorignore when files change."""
    policy = _load_policy(policy_path)
    ignore_path = workspace / ".cursorignore"

    print(f"\n{_BOLD}ContextDuty — Cursor Watch Mode{_RESET}\n")
    print(f"  Workspace  {_DIM}{workspace}{_RESET}")
    print(f"  Interval   {_DIM}{interval}s{_RESET}")
    print(f"  Output     {_DIM}{ignore_path}{_RESET}")
    print(f"\n  {_DIM}Press Ctrl+C to stop.{_RESET}\n")

    last_state: set[str] = set()
    try:
        while True:
            sensitive_files = _scan_workspace(workspace, policy)
            current_state = {f for f, _ in sensitive_files}

            if current_state != last_state:
                added = current_state - last_state
                removed = last_state - current_state
                _write_cursorignore(ignore_path, sensitive_files, workspace)

                ts = time.strftime("%H:%M:%S")
                if added:
                    for f in sorted(added)[:5]:
                        print(f"  {ts}  {_YELLOW}+{_RESET} {f}")
                if removed:
                    for f in sorted(removed)[:5]:
                        print(f"  {ts}  {_GREEN}-{_RESET} {f}")
                if not last_state:
                    print(f"  {ts}  {_DIM}Watching... {len(current_state)} files blocked{_RESET}")
                else:
                    print(
                        f"  {ts}  {_DIM}Updated .cursorignore "
                        f"(+{len(added)} -{len(removed)}){_RESET}"
                    )
                last_state = current_state

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n  {_GREEN}✓{_RESET}  Watch stopped.\n")
        return 0


def _load_policy(policy_path: str | None) -> Policy:
    if policy_path:
        p = Path(policy_path)
        return load_policy(p if p.exists() else None)
    return load_policy(Path(".contextduty.json") if Path(".contextduty.json").exists() else None)


def _scan_workspace(workspace: Path, policy: Policy) -> list[tuple[str, set[str]]]:
    """Scan all text files, return list of (relative_path, detector_names) for files with findings."""
    detectors = _active_detectors(policy)
    sensitive: list[tuple[str, set[str]]] = []

    # Respect existing .gitignore patterns
    gitignore_patterns = _load_gitignore(workspace)

    for root, dirs, files in os.walk(workspace):
        # Skip hidden dirs and common non-source dirs
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and d not in {"node_modules", "__pycache__", "venv", ".venv", "dist", "build", "target"}
        ]

        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in _BINARY_EXTENSIONS:
                continue

            rel = str(fpath.relative_to(workspace))

            # Skip if matched by gitignore
            if _matches_gitignore(rel, gitignore_patterns):
                continue

            try:
                detector_hits: set[str] = set()
                with fpath.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        findings = _scan_line(line, detectors)
                        for finding in findings:
                            detector_hits.add(finding.detector)
                if detector_hits:
                    sensitive.append((rel, detector_hits))
            except (OSError, UnicodeDecodeError):
                continue

    return sensitive


def _write_cursorignore(
    path: Path, sensitive_files: list[tuple[str, set[str]]], workspace: Path
) -> None:
    """Write .cursorignore preserving any manual entries after AUTO-END."""
    manual_section = ""
    if path.exists():
        content = path.read_text(encoding="utf-8")
        marker = "# ── AUTO-END ──"
        if marker in content:
            manual_section = content[content.index(marker) + len(marker) :]

    lines = [_HEADER]
    for fpath, detectors in sorted(sensitive_files):
        det_comment = ", ".join(sorted(detectors))
        lines.append(f"{fpath}  # {det_comment}\n")
    lines.append(_FOOTER)

    if manual_section.strip():
        lines.append(manual_section)

    path.write_text("".join(lines), encoding="utf-8")


def _load_gitignore(workspace: Path) -> list[str]:
    """Load .gitignore patterns (simple glob matching only)."""
    gi = workspace / ".gitignore"
    if not gi.exists():
        return []
    patterns = []
    for line in gi.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _matches_gitignore(rel_path: str, patterns: list[str]) -> bool:
    """Simple gitignore matching — handles directory prefixes and glob suffixes."""
    for pat in patterns:
        pat_clean = pat.rstrip("/")
        if pat_clean in rel_path or rel_path.startswith(pat_clean + "/"):
            return True
        # Handle *.ext patterns
        if pat_clean.startswith("*") and rel_path.endswith(pat_clean[1:]):
            return True
    return False
