"""IDE integration — AI tool registry and ignore file generation.

The AI tool registry is the declarative config that makes ContextDuty
future-proof. When a new AI coding assistant launches:
    1. Add an AITool entry (3 lines)
    2. That's it. contextduty protect handles the rest.

This module contains ONLY the data model and file generation logic.
CLI output and terminal formatting live in cli/output.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..config import BINARY_EXTENSIONS, SKIP_DIRECTORIES
from ..engine import _active_detectors, _scan_line
from ..policy import Policy, load_policy


@dataclass(frozen=True)
class AITool:
    """Definition of an AI tool's ignore file format."""

    name: str
    ignore_file: str
    description: str
    comment_prefix: str = "#"
    has_ignore_file: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# AI Tool Registry — add new tools here. Everything else adapts automatically.
# ─────────────────────────────────────────────────────────────────────────────

AI_TOOLS: tuple[AITool, ...] = (
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
        name="Amazon Q",
        ignore_file=".amazonq/ignore",
        description="Amazon Q / CodeWhisperer",
    ),
    AITool(
        name="Sourcegraph Cody",
        ignore_file=".cody/ignore",
        description="Sourcegraph Cody AI assistant",
    ),
)


def write_ignore_file(
    path: Path,
    sensitive_files: list[tuple[str, set[str]]],
    tool: AITool,
) -> None:
    """Write an AI tool's ignore file. Preserves manual entries after AUTO-END marker."""
    cp = tool.comment_prefix
    marker = f"{cp} ── AUTO-END ──"
    manual_section = ""

    if path.exists():
        content = path.read_text(encoding="utf-8")
        if marker in content:
            manual_section = content[content.index(marker) + len(marker) :]

    lines = [
        f"{cp} ContextDuty — auto-generated {path.name}\n",
        f"{cp} Blocks sensitive files from {tool.name} AI indexing.\n",
        f"{cp} Covers ALL AI tools that read this workspace.\n",
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

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(lines), encoding="utf-8")


def resolve_policy(policy_path: str | None) -> Policy:
    """Load a policy from the given path, falling back to defaults."""
    if policy_path:
        p = Path(policy_path)
        return load_policy(p if p.exists() else None)
    default = Path(".contextduty.json")
    return load_policy(default if default.exists() else None)


def load_gitignore(workspace: Path) -> list[str]:
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


def matches_gitignore(rel_path: str, patterns: list[str]) -> bool:
    """Simple gitignore matching — handles directory prefixes and glob suffixes."""
    for pat in patterns:
        pat_clean = pat.rstrip("/")
        if pat_clean in rel_path or rel_path.startswith(pat_clean + "/"):
            return True
        if pat_clean.startswith("*") and rel_path.endswith(pat_clean[1:]):
            return True
    return False


def scan_workspace(workspace: Path, policy: Policy) -> list[tuple[str, set[str]]]:
    """Scan all text files, return (relative_path, detector_names) for sensitive files."""
    detectors = _active_detectors(policy)
    sensitive: list[tuple[str, set[str]]] = []
    gitignore_patterns = load_gitignore(workspace)

    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRECTORIES]

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
                        findings = _scan_line(line, detectors)
                        for finding in findings:
                            detector_hits.add(finding.detector)
                if detector_hits:
                    sensitive.append((rel, detector_hits))
            except (OSError, UnicodeDecodeError):
                continue

    return sensitive


def write_all_ignore_files(
    workspace: Path,
    sensitive_files: list[tuple[str, set[str]]],
) -> list[Path]:
    """Write ignore files for ALL registered AI tools. Returns paths written."""
    written: list[Path] = []
    for tool in AI_TOOLS:
        if not tool.has_ignore_file:
            continue
        ignore_path = workspace / tool.ignore_file
        write_ignore_file(ignore_path, sensitive_files, tool)
        written.append(ignore_path)
    return written
