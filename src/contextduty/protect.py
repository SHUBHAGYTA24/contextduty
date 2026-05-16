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

import os
import time
from dataclasses import dataclass
from pathlib import Path

from .engine import _BINARY_EXTENSIONS, _active_detectors, _scan_line
from .policy import Policy, load_policy

# ──────────���──────────────────────────────────────��───────────────────────────
# AI Tool Registry — add new tools here. That's it. Everything else is generic.
# ─────────────────────────────────────────────────────────────────────────���───


@dataclass
class AITool:
    """Definition of an AI tool's ignore file format."""

    name: str  # human-readable name
    ignore_file: str  # filename relative to workspace root
    description: str  # what this tool does
    # Some tools use different comment syntax
    comment_prefix: str = "#"
    # Some tools don't support ignore files — proxy-only coverage
    has_ignore_file: bool = True


# Every AI coding tool that indexes workspaces.
# When a new tool launches, add ONE entry here — everything else adapts.
AI_TOOLS: list[AITool] = [
    AITool(
        name="Cursor",
        ignore_file=".cursorignore",
        description="Cursor IDE (Claude, GPT-4, Gemini inside Cursor)",
    ),
    AITool(
        name="GitHub Copilot",
        ignore_file=".copilotignore",
        description="GitHub Copilot in VS Code / JetBrains",
    ),
    AITool(
        name="Codeium / Windsurf",
        ignore_file=".codeiumignore",
        description="Codeium and Windsurf AI completions",
    ),
    AITool(
        name="Tabnine",
        ignore_file=".tabnine_ignore",
        description="Tabnine AI completions",
    ),
    AITool(
        name="Amazon CodeWhisperer",
        ignore_file=".amazonq/ignore",
        description="Amazon Q / CodeWhisperer",
    ),
    AITool(
        name="Sourcegraph Cody",
        ignore_file=".cody/ignore",
        description="Sourcegraph Cody AI assistant",
    ),
]

# HTTPS proxy host registry — intercepts API calls from ANY tool.
# This is the downstream safety net. Even if an AI tool doesn't support
# ignore files, the proxy catches secrets in the actual API request.
AI_API_HOSTS: dict[str, str] = {
    # Cursor
    "api2.cursor.sh": "Cursor",
    "cursor.sh": "Cursor",
    # Anthropic / Claude
    "api.anthropic.com": "Claude API",
    # OpenAI
    "api.openai.com": "OpenAI / ChatGPT",
    # GitHub Copilot
    "copilot.github.com": "GitHub Copilot",
    "api.githubcopilot.com": "GitHub Copilot",
    "copilot-proxy.githubusercontent.com": "GitHub Copilot",
    # Google
    "generativelanguage.googleapis.com": "Google Gemini",
    "aiplatform.googleapis.com": "Google Vertex AI",
    # Azure
    "openai.azure.com": "Azure OpenAI",
    # Codeium / Windsurf
    "server.codeium.com": "Codeium",
    # Amazon
    "codewhisperer.us-east-1.amazonaws.com": "CodeWhisperer",
    # Sourcegraph
    "sourcegraph.com": "Sourcegraph Cody",
    # Tabnine
    "api.tabnine.com": "Tabnine",
    # Perplexity (developers use it for code)
    "api.perplexity.ai": "Perplexity",
    # Mistral
    "api.mistral.ai": "Mistral",
    # Groq
    "api.groq.com": "Groq",
    # Together AI
    "api.together.xyz": "Together AI",
    # Fireworks AI
    "api.fireworks.ai": "Fireworks AI",
    # Cohere
    "api.cohere.ai": "Cohere",
    # DeepSeek
    "api.deepseek.com": "DeepSeek",
}


# ──────────────────���──────────────────────────��───────────────────────────────
# Terminal formatting
# ─────────────────────────────────────────────────────────────────────────────

_BOLD = "\033[1m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"


# ─────────────────────────────────────────────────────��───────────────────────
# Public API
# ────────────────────────────────────��───────────────────────────────────────���


def protect_workspace(
    workspace: Path,
    policy_path: str | None = None,
    output_dir: Path | None = None,
) -> int:
    """Scan workspace and write ignore files for ALL AI tools at once."""
    policy = _load_policy(policy_path)
    out_dir = output_dir or workspace

    print(f"\n{_BOLD}{'─' * 56}{_RESET}")
    print(f"{_BOLD}  ContextDuty — Universal AI Workspace Protection{_RESET}")
    print(f"{_BOLD}{'─' * 56}{_RESET}\n")
    print(f"  Workspace   {_DIM}{workspace}{_RESET}")
    print(f"  Policy      {_DIM}{policy_path or 'default'}{_RESET}")
    print()

    # Scan
    sensitive_files = _scan_workspace(workspace, policy)

    if not sensitive_files:
        print(f"  {_GREEN}✓{_RESET}  No secrets or PII detected.")
        print("     All AI tools can safely index this workspace.")
        print()
        _print_coverage_status(workspace)
        return 0

    # Report findings
    print(f"  {_YELLOW}⚠{_RESET}  {_BOLD}{len(sensitive_files)}{_RESET} file(s) contain secrets/PII:\n")
    for fpath, detectors in sensitive_files[:15]:
        det_str = ", ".join(sorted(detectors))
        print(f"     {fpath}  {_DIM}[{det_str}]{_RESET}")
    if len(sensitive_files) > 15:
        print(f"     {_DIM}... and {len(sensitive_files) - 15} more{_RESET}")
    print()

    # Write ignore files for ALL tools
    tools_written = 0
    for tool in AI_TOOLS:
        if not tool.has_ignore_file:
            continue
        ignore_path = out_dir / tool.ignore_file
        # Create parent dirs for nested ignore files (e.g. .amazonq/ignore)
        ignore_path.parent.mkdir(parents=True, exist_ok=True)
        _write_ignore_file(ignore_path, sensitive_files, workspace, tool)
        tools_written += 1

    print(f"  {_GREEN}✓{_RESET}  Written {_BOLD}{tools_written}{_RESET} ignore files:\n")
    for tool in AI_TOOLS:
        if tool.has_ignore_file:
            exists = (out_dir / tool.ignore_file).exists()
            icon = f"{_GREEN}✓{_RESET}" if exists else f"{_RED}✗{_RESET}"
            print(f"     {icon}  {tool.ignore_file:<20} {_DIM}{tool.name}{_RESET}")
    print()

    # Show coverage
    _print_coverage_status(workspace)

    print(f"\n  {_DIM}Keep updated: contextduty protect watch{_RESET}")
    print(f"  {_DIM}Full interception: contextduty proxy start{_RESET}\n")
    return 0


def protect_watch(
    workspace: Path,
    policy_path: str | None = None,
    interval: int = 30,
) -> int:
    """Watch workspace and update ALL ignore files on change."""
    policy = _load_policy(policy_path)

    print(f"\n{_BOLD}ContextDuty — Watch Mode (all AI tools){_RESET}\n")
    print(f"  Workspace  {_DIM}{workspace}{_RESET}")
    print(f"  Interval   {_DIM}{interval}s{_RESET}")
    tools_str = ", ".join(t.name for t in AI_TOOLS if t.has_ignore_file)
    print(f"  Protecting {_DIM}{tools_str}{_RESET}")
    print(f"\n  {_DIM}Press Ctrl+C to stop.{_RESET}\n")

    last_state: set[str] = set()
    try:
        while True:
            sensitive_files = _scan_workspace(workspace, policy)
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
                    _write_ignore_file(ignore_path, sensitive_files, workspace, tool)

                ts = time.strftime("%H:%M:%S")
                if not last_state:
                    print(
                        f"  {ts}  {_DIM}Watching... "
                        f"{len(current_state)} files blocked across "
                        f"{len(AI_TOOLS)} AI tools{_RESET}"
                    )
                else:
                    if added:
                        for f in sorted(added)[:3]:
                            print(f"  {ts}  {_YELLOW}+blocked{_RESET} {f}")
                    if removed:
                        for f in sorted(removed)[:3]:
                            print(f"  {ts}  {_GREEN}-cleared{_RESET} {f}")
                    extra = len(added) + len(removed) - 6
                    if extra > 0:
                        print(f"  {ts}  {_DIM}... and {extra} more changes{_RESET}")

                last_state = current_state

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n  {_GREEN}✓{_RESET}  Watch stopped.\n")
        return 0


def protect_status(workspace: Path) -> int:
    """Show protection status for the workspace."""
    print(f"\n{_BOLD}{'─' * 56}{_RESET}")
    print(f"{_BOLD}  ContextDuty — Protection Status{_RESET}")
    print(f"{_BOLD}{'─' * 56}{_RESET}\n")

    _print_coverage_status(workspace)

    # Check proxy
    from .proxy import _is_running, _read_pid

    print(f"\n  {_BOLD}HTTPS Proxy (downstream interception){_RESET}\n")
    if _is_running():
        pid = _read_pid()
        print(f"  {_GREEN}✓{_RESET}  Proxy running (PID {pid})")
        print(f"     Intercepting {len(AI_API_HOSTS)} AI API endpoints")
    else:
        print(f"  {_YELLOW}⚠{_RESET}  Proxy not running")
        print(f"     Start with: {_CYAN}contextduty proxy start{_RESET}")

    print()
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Internal
# ─────────────────────────────────────────────────────────────────────────────


def _print_coverage_status(workspace: Path) -> None:
    """Print which AI tools are covered by ignore files."""
    print(f"  {_BOLD}Upstream Protection (ignore files){_RESET}\n")
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
                f"  {_GREEN}✓{_RESET}  {tool.name:<25} "
                f"{_DIM}{len(entries)} files blocked{_RESET}"
            )
        else:
            print(f"  {_RED}✗{_RESET}  {tool.name:<25} {_DIM}not configured{_RESET}")


def _load_policy(policy_path: str | None) -> Policy:
    if policy_path:
        p = Path(policy_path)
        return load_policy(p if p.exists() else None)
    default = Path(".contextduty.json")
    return load_policy(default if default.exists() else None)


def _scan_workspace(workspace: Path, policy: Policy) -> list[tuple[str, set[str]]]:
    """Scan all text files, return (relative_path, detector_names) for sensitive files."""
    detectors = _active_detectors(policy)
    sensitive: list[tuple[str, set[str]]] = []
    gitignore_patterns = _load_gitignore(workspace)

    for root, dirs, files in os.walk(workspace):
        # Skip hidden dirs, dependency dirs, build output
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and d
            not in {
                "node_modules",
                "__pycache__",
                "venv",
                ".venv",
                "dist",
                "build",
                "target",
                "vendor",
                "packages",
                ".next",
                ".nuxt",
                "coverage",
            }
        ]

        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in _BINARY_EXTENSIONS:
                continue

            rel = str(fpath.relative_to(workspace))

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


def _write_ignore_file(
    path: Path,
    sensitive_files: list[tuple[str, set[str]]],
    workspace: Path,
    tool: AITool,
) -> None:
    """Write an AI tool's ignore file. Preserves manual entries after AUTO-END."""
    cp = tool.comment_prefix
    manual_section = ""
    marker = f"{cp} ── AUTO-END ──"

    if path.exists():
        content = path.read_text(encoding="utf-8")
        if marker in content:
            manual_section = content[content.index(marker) + len(marker) :]

    lines = [
        f"{cp} ContextDuty — auto-generated {path.name}\n",
        f"{cp} Blocks sensitive files from {tool.name} AI indexing.\n",
        f"{cp} ANY AI tool that reads this workspace is covered.\n",
        f"{cp}\n",
        f"{cp} Re-generate: contextduty protect\n",
        f"{cp} Auto-update: contextduty protect watch\n",
        f"{cp}\n",
        f"{cp} Manual entries below AUTO-END are preserved.\n",
        "\n",
        f"{cp} ── AUTO-START (do not edit between START/END) ──\n",
    ]

    for fpath, detectors in sorted(sensitive_files):
        det_comment = ", ".join(sorted(detectors))
        lines.append(f"{fpath}  {cp} {det_comment}\n")

    lines.append(f"{marker}\n")

    if manual_section.strip():
        lines.append(manual_section)

    path.write_text("".join(lines), encoding="utf-8")


def _load_gitignore(workspace: Path) -> list[str]:
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
    for pat in patterns:
        pat_clean = pat.rstrip("/")
        if pat_clean in rel_path or rel_path.startswith(pat_clean + "/"):
            return True
        if pat_clean.startswith("*") and rel_path.endswith(pat_clean[1:]):
            return True
    return False
