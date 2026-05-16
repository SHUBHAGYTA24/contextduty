"""IDE integration — AI tool registry and ignore file generation.

The AI tool registry is the declarative config that makes ContextDuty
future-proof. When a new AI coding assistant launches:
    1. Add an AITool entry (3 lines)
    2. That's it. contextduty protect handles the rest.

This module contains ONLY the data model and file generation logic.
CLI output and terminal formatting live in cli/output.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
