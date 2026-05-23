"""Universal AI workspace protection — tool-agnostic.

One command to protect your workspace from ALL AI tools — current and future.
Generates ignore files for every known AI tool, and the HTTPS proxy intercepts
any AI API traffic regardless of which tool makes the call.

The design principle: ContextDuty doesn't care which AI tool you use.
It protects at two layers:
  1. UPSTREAM: prevent sensitive files from being indexed (ignore files)
  2. DOWNSTREAM: intercept and redact if secrets reach the API call (proxy)

Commands:
    contextduty protect         — scan workspace, write all ignore files, show status
    contextduty protect watch   — background daemon, keep ignore files updated
    contextduty protect status  — show what's protected and what's not
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
from .proxy.scope import AI_API_HOSTS
from .ui.output import style

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def protect_workspace(
    workspace: Path,
    policy_path: str | None = None,
    output_dir: Path | None = None,
) -> int:
    """Scan workspace and write ignore files for ALL AI tools at once."""
    policy = resolve_policy(policy_path)
    out_dir = output_dir or workspace

    print(f"\n{style.bold}{'─' * 56}{style.reset}")
    print(f"{style.bold}  ContextDuty — Universal AI Workspace Protection{style.reset}")
    print(f"{style.bold}{'─' * 56}{style.reset}\n")
    print(f"  Workspace   {style.dim}{workspace}{style.reset}")
    print(f"  Policy      {style.dim}{policy_path or 'default'}{style.reset}")
    print()

    # Scan
    sensitive_files = scan_workspace(workspace, policy)

    if not sensitive_files:
        print(f"  {style.green}✓{style.reset}  No secrets or PII detected.")
        print("     All AI tools can safely index this workspace.")
        print()
        _print_coverage_status(workspace)
        return 0

    # Report findings
    print(
        f"  {style.yellow}⚠{style.reset}  {style.bold}{len(sensitive_files)}{style.reset} file(s) contain secrets/PII:\n"
    )
    for fpath, detectors in sensitive_files[:15]:
        det_str = ", ".join(sorted(detectors))
        print(f"     {fpath}  {style.dim}[{det_str}]{style.reset}")
    if len(sensitive_files) > 15:
        print(f"     {style.dim}... and {len(sensitive_files) - 15} more{style.reset}")
    print()

    # Write ignore files for ALL tools
    tools_written = 0
    for tool in AI_TOOLS:
        if not tool.has_ignore_file:
            continue
        ignore_path = out_dir / tool.ignore_file
        ignore_path.parent.mkdir(parents=True, exist_ok=True)
        write_ignore_file(ignore_path, sensitive_files, tool)
        tools_written += 1

    print(
        f"  {style.green}✓{style.reset}  Written {style.bold}{tools_written}{style.reset} ignore files:\n"
    )
    for tool in AI_TOOLS:
        if tool.has_ignore_file:
            exists = (out_dir / tool.ignore_file).exists()
            icon = f"{style.green}✓{style.reset}" if exists else f"{style.red}✗{style.reset}"
            print(f"     {icon}  {tool.ignore_file:<20} {style.dim}{tool.name}{style.reset}")
    print()

    # Show coverage
    _print_coverage_status(workspace)

    print(f"\n  {style.dim}Keep updated: contextduty protect watch{style.reset}")
    print(f"  {style.dim}Full interception: contextduty proxy start{style.reset}\n")
    return 0


def protect_watch(
    workspace: Path,
    policy_path: str | None = None,
    interval: int = 30,
) -> int:
    """Watch workspace and update ALL ignore files on change."""
    policy = resolve_policy(policy_path)

    print(f"\n{style.bold}ContextDuty — Watch Mode (all AI tools){style.reset}\n")
    print(f"  Workspace  {style.dim}{workspace}{style.reset}")
    print(f"  Interval   {style.dim}{interval}s{style.reset}")
    tools_str = ", ".join(t.name for t in AI_TOOLS if t.has_ignore_file)
    print(f"  Protecting {style.dim}{tools_str}{style.reset}")
    print(f"\n  {style.dim}Press Ctrl+C to stop.{style.reset}\n")

    last_state: set[str] = set()
    try:
        while True:
            sensitive_files = scan_workspace(workspace, policy)
            current_state = {f for f, _ in sensitive_files}

            if current_state != last_state:
                added = current_state - last_state
                removed = last_state - current_state

                # Update all ignore files
                for tool in AI_TOOLS:
                    if not tool.has_ignore_file:
                        continue
                    ignore_path = workspace / tool.ignore_file
                    ignore_path.parent.mkdir(parents=True, exist_ok=True)
                    write_ignore_file(ignore_path, sensitive_files, tool)

                ts = time.strftime("%H:%M:%S")
                if not last_state:
                    print(
                        f"  {ts}  {style.dim}Watching... "
                        f"{len(current_state)} files blocked across "
                        f"{len(AI_TOOLS)} AI tools{style.reset}"
                    )
                else:
                    if added:
                        for f in sorted(added)[:3]:
                            print(f"  {ts}  {style.yellow}+blocked{style.reset} {f}")
                    if removed:
                        for f in sorted(removed)[:3]:
                            print(f"  {ts}  {style.green}-cleared{style.reset} {f}")
                    extra = len(added) + len(removed) - 6
                    if extra > 0:
                        print(f"  {ts}  {style.dim}... and {extra} more changes{style.reset}")

                last_state = current_state

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n  {style.green}✓{style.reset}  Watch stopped.\n")
        return 0


def protect_status(workspace: Path) -> int:
    """Show protection status for the workspace."""
    print(f"\n{style.bold}{'─' * 56}{style.reset}")
    print(f"{style.bold}  ContextDuty — Protection Status{style.reset}")
    print(f"{style.bold}{'─' * 56}{style.reset}\n")

    _print_coverage_status(workspace)

    # Check proxy
    from .proxy.server import _is_running, _read_pid

    print(f"\n  {style.bold}HTTPS Proxy (downstream interception){style.reset}\n")
    if _is_running():
        pid = _read_pid()
        print(f"  {style.green}✓{style.reset}  Proxy running (PID {pid})")
        print(f"     Intercepting {len(AI_API_HOSTS)} AI API endpoints")
    else:
        print(f"  {style.yellow}⚠{style.reset}  Proxy not running")
        print(f"     Start with: {style.cyan}contextduty proxy start{style.reset}")

    print()
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Internal
# ─────────────────────────────────────────────────────────────────────────────


def _print_coverage_status(workspace: Path) -> None:
    """Print which AI tools are covered by ignore files."""
    print(f"  {style.bold}Upstream Protection (ignore files){style.reset}\n")
    for tool in AI_TOOLS:
        if not tool.has_ignore_file:
            continue
        ignore_path = workspace / tool.ignore_file
        if ignore_path.exists():
            # Count entries
            content = ignore_path.read_text(encoding="utf-8")
            entries = [
                line
                for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            print(
                f"  {style.green}✓{style.reset}  {tool.name:<25} {style.dim}{len(entries)} files blocked{style.reset}"
            )
        else:
            print(
                f"  {style.red}✗{style.reset}  {tool.name:<25} {style.dim}not configured{style.reset}"
            )
