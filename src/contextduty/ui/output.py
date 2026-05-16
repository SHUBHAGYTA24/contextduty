"""Terminal output formatting — the SINGLE source of truth for all UI output.

All CLI modules import from here. No ANSI codes anywhere else in the codebase.
Respects NO_COLOR environment variable (https://no-color.org/).
"""

from __future__ import annotations

import sys

from ..config import NO_COLOR


class Style:
    """Terminal styling. All attributes return empty string when color is disabled."""

    def __init__(self, enabled: bool = True):
        self._enabled = enabled

    @property
    def bold(self) -> str:
        return "\033[1m" if self._enabled else ""

    @property
    def dim(self) -> str:
        return "\033[2m" if self._enabled else ""

    @property
    def green(self) -> str:
        return "\033[32m" if self._enabled else ""

    @property
    def red(self) -> str:
        return "\033[31m" if self._enabled else ""

    @property
    def yellow(self) -> str:
        return "\033[33m" if self._enabled else ""

    @property
    def cyan(self) -> str:
        return "\033[36m" if self._enabled else ""

    @property
    def reset(self) -> str:
        return "\033[0m" if self._enabled else ""


# Global style instance
style = Style(enabled=not NO_COLOR)


def section(title: str) -> None:
    """Print a section header with horizontal rules."""
    s = style
    print(f"\n{s.bold}{'─' * 56}{s.reset}")
    print(f"{s.bold}  {title}{s.reset}")
    print(f"{s.bold}{'─' * 56}{s.reset}\n")


def step(msg: str) -> None:
    """Print an in-progress step."""
    print(f"  → {msg}", flush=True)


def success(msg: str) -> None:
    """Print a success message with green checkmark."""
    print(f"  {style.green}✓{style.reset}  {msg}", flush=True)


def warning(msg: str) -> None:
    """Print a warning message with yellow indicator."""
    print(f"  {style.yellow}⚠{style.reset}  {msg}", flush=True)


def error(msg: str) -> None:
    """Print an error message to stderr with red indicator."""
    print(f"  {style.red}✗{style.reset}  {msg}", file=sys.stderr, flush=True)


def info(msg: str = "") -> None:
    """Print an informational message."""
    print(msg, flush=True)


def detail(msg: str) -> None:
    """Print a dimmed detail line."""
    print(f"  {style.dim}{msg}{style.reset}", flush=True)


def kv(key: str, value: str, indent: int = 2) -> None:
    """Print a key-value pair with aligned formatting."""
    pad = " " * indent
    print(f"{pad}{key:<14}{style.dim}{value}{style.reset}", flush=True)
