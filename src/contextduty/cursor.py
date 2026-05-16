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

from .config import BINARY_EXTENSIONS, SKIP_DIRECTORIES
from .engine import _active_detectors, _scan_line
from .policy import Policy, load_policy
from .ui.output import style

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



def cursor_setup(
    workspace: Path,
    policy_path: str | None = None,
    output: Path | None = None,
) -> int:
    """Scan workspace and write .cursorignore with sensitive file paths."""
    policy = _load_policy(policy_path)
    ignore_path = output or (workspace / ".cursorignore")

    print(f"\n{style.bold}ContextDuty — Cursor Workspace Protection{style.reset}\n")
    print(f"  Scanning   {style.dim}{workspace}{style.reset}")
    print(f"  Policy     {style.dim}{policy_path or 'default'}{style.reset}")
    print()

    sensitive_files = _scan_workspace(workspace, policy)

    if not sensitive_files:
        print(f"  {style.green}✓{style.reset}  No secrets detected — workspace is clean.")
        print("     Cursor can safely index all files.")
        return 0

    print(f"  {style.yellow}⚠{style.reset}  {len(sensitive_files)} file(s) contain secrets/PII:\n")
    for fpath, detectors in sensitive_files[:20]:
        det_str = ", ".join(sorted(detectors))
        print(f"     {style.dim}{fpath}{style.reset}  [{det_str}]")
    if len(sensitive_files) > 20:
        print(f"     {style.dim}... and {len(sensitive_files) - 20} more{style.reset}")

    # Write .cursorignore
    _write_cursorignore(ignore_path, sensitive_files, workspace)

    print(f"\n  {style.green}✓{style.reset}  Written {style.bold}{ignore_path}{style.reset}")
    print(f"     {len(sensitive_files)} files blocked from Cursor indexing.")
    print(f"\n  {style.dim}Keep it updated: contextduty cursor watch{style.reset}\n")
    return 0


def cursor_watch(
    workspace: Path,
    policy_path: str | None = None,
    interval: int = 30,
) -> int:
    """Watch workspace and update .cursorignore when files change."""
    policy = _load_policy(policy_path)
    ignore_path = workspace / ".cursorignore"

    print(f"\n{style.bold}ContextDuty — Cursor Watch Mode{style.reset}\n")
    print(f"  Workspace  {style.dim}{workspace}{style.reset}")
    print(f"  Interval   {style.dim}{interval}s{style.reset}")
    print(f"  Output     {style.dim}{ignore_path}{style.reset}")
    print(f"\n  {style.dim}Press Ctrl+C to stop.{style.reset}\n")

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
                        print(f"  {ts}  {style.yellow}+{style.reset} {f}")
                if removed:
                    for f in sorted(removed)[:5]:
                        print(f"  {ts}  {style.green}-{style.reset} {f}")
                if not last_state:
                    print(f"  {ts}  {style.dim}Watching... {len(current_state)} files blocked{style.reset}")
                else:
                    print(
                        f"  {ts}  {style.dim}Updated .cursorignore "
                        f"(+{len(added)} -{len(removed)}){style.reset}"
                    )
                last_state = current_state

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n  {style.green}✓{style.reset}  Watch stopped.\n")
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
            and d not in SKIP_DIRECTORIES
        ]

        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in BINARY_EXTENSIONS:
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
