"""Live terminal feed — shows AI API interception events in real time.

Displays a continuous stream of intercepted requests with:
- Timestamp
- Source tool (Cursor, Claude, Copilot, etc.)
- Target API host
- Action taken (redacted, blocked, clean)
- Detector summary
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from ..ui.output import style
from .scope import get_host_label


@dataclass
class InterceptionEvent:
    """A single proxy interception event."""

    timestamp: float
    host: str
    action: str  # "redacted", "blocked", "clean", "warn"
    findings_count: int = 0
    detector_counts: dict[str, int] = field(default_factory=dict)

    @property
    def tool_name(self) -> str:
        return get_host_label(self.host)

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))


class LiveFeed:
    """Collects and displays interception events in the terminal."""

    def __init__(self, max_events: int = 1000):
        self.events: deque[InterceptionEvent] = deque(maxlen=max_events)
        self._total_intercepted = 0
        self._total_findings = 0
        self._total_blocked = 0

    def record(self, event: InterceptionEvent) -> None:
        """Record an event and print it to the terminal."""
        self.events.append(event)
        self._total_intercepted += 1
        self._total_findings += event.findings_count
        if event.action == "blocked":
            self._total_blocked += 1
        self._print_event(event)

    def print_header(self) -> None:
        """Print the live feed header."""
        print(f"\n  {style.bold}Live Interception Feed{style.reset}")
        print(f"  {style.dim}{'─' * 50}{style.reset}\n")

    def print_summary(self) -> None:
        """Print session summary on exit."""
        print(f"\n  {style.dim}{'─' * 50}{style.reset}")
        print(f"  {style.bold}Session Summary{style.reset}")
        print(f"    Requests intercepted: {self._total_intercepted}")
        print(f"    Findings redacted:    {self._total_findings}")
        print(f"    Requests blocked:     {self._total_blocked}")
        print()

    def _print_event(self, event: InterceptionEvent) -> None:
        tool = f"{event.tool_name:<10}"
        host = f"{event.host:<35}"

        if event.action == "clean":
            status = f"{style.green}clean{style.reset}"
            detail = ""
        elif event.action == "blocked":
            status = f"{style.red}BLOCKED{style.reset}"
            det_str = ", ".join(f"{k}:{v}" for k, v in event.detector_counts.items())
            detail = f"  {style.dim}[{det_str}]{style.reset}"
        elif event.action == "redacted":
            status = f"{style.yellow}{event.findings_count} redacted{style.reset}"
            det_str = ", ".join(sorted(event.detector_counts.keys()))
            detail = f"  {style.dim}[{det_str}]{style.reset}"
        elif event.action == "warn":
            status = f"{style.cyan}warn ({event.findings_count}){style.reset}"
            det_str = ", ".join(sorted(event.detector_counts.keys()))
            detail = f"  {style.dim}[{det_str}]{style.reset}"
        else:
            status = event.action
            detail = ""

        print(
            f"  {style.dim}{event.time_str}{style.reset}  {tool} → {host} {status}{detail}",
            flush=True,
        )


# Global feed instance — the proxy addon writes to this
_feed: LiveFeed | None = None


def get_feed() -> LiveFeed:
    """Get or create the global feed instance."""
    global _feed
    if _feed is None:
        _feed = LiveFeed()
    return _feed


def record_interception(
    host: str,
    action: str,
    findings_count: int = 0,
    detector_counts: dict[str, int] | None = None,
) -> None:
    """Record an interception event to the live feed (if active)."""
    feed = get_feed()
    event = InterceptionEvent(
        timestamp=time.time(),
        host=host,
        action=action,
        findings_count=findings_count,
        detector_counts=detector_counts or {},
    )
    feed.record(event)
