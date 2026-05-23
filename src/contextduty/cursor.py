"""Cursor workspace protection — generate and maintain .cursorignore.

Scans the workspace for files containing secrets/PII and writes them to
.cursorignore so Cursor never indexes or sends them to any AI model
(Claude, GPT-4, Gemini — all covered by a single upstream block).

Commands:
    contextduty cursor setup  — scan workspace, write .cursorignore
    contextduty cursor watch  — background daemon, update .cursorignore on change
"""

from __future__ import annotations

import time
from pathlib import Path

from .adapters.ide import (
    AI_TOOLS,
    resolve_policy,
    scan_workspace,
    write_ignore_file,
)
from .ui.output import style

# Find the Cursor tool entry from the canonical registry
_CURSOR_TOOL = next(t for t in AI_TOOLS if t.name == "Cursor")


def cursor_setup(
    workspace: Path,
    policy_path: str | None = None,
    output: Path | None = None,
) -> int:
    """Scan workspace and write .cursorignore with sensitive file paths."""
    policy = resolve_policy(policy_path)
    ignore_path = output or (workspace / ".cursorignore")

    print(f"\n{style.bold}ContextDuty — Cursor Workspace Protection{style.reset}\n")
    print(f"  Scanning   {style.dim}{workspace}{style.reset}")
    print(f"  Policy     {style.dim}{policy_path or 'default'}{style.reset}")
    print()

    sensitive_files = scan_workspace(workspace, policy)

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
    write_ignore_file(ignore_path, sensitive_files, _CURSOR_TOOL)

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
    policy = resolve_policy(policy_path)
    ignore_path = workspace / ".cursorignore"

    print(f"\n{style.bold}ContextDuty — Cursor Watch Mode{style.reset}\n")
    print(f"  Workspace  {style.dim}{workspace}{style.reset}")
    print(f"  Interval   {style.dim}{interval}s{style.reset}")
    print(f"  Output     {style.dim}{ignore_path}{style.reset}")
    print(f"\n  {style.dim}Press Ctrl+C to stop.{style.reset}\n")

    last_state: set[str] = set()
    try:
        while True:
            sensitive_files = scan_workspace(workspace, policy)
            current_state = {f for f, _ in sensitive_files}

            if current_state != last_state:
                added = current_state - last_state
                removed = last_state - current_state
                write_ignore_file(ignore_path, sensitive_files, _CURSOR_TOOL)

                ts = time.strftime("%H:%M:%S")
                if added:
                    for f in sorted(added)[:5]:
                        print(f"  {ts}  {style.yellow}+{style.reset} {f}")
                if removed:
                    for f in sorted(removed)[:5]:
                        print(f"  {ts}  {style.green}-{style.reset} {f}")
                if not last_state:
                    print(
                        f"  {ts}  {style.dim}Watching... {len(current_state)} files blocked{style.reset}"
                    )
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
