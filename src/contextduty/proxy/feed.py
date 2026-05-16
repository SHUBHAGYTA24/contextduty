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

_BOLD = "\033[1m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"

# Host → human-readable tool name
_HOST_LABELS: dict[str, str] = {
    "api2.cursor.sh": "Cursor",
    "cursor.sh": "Cursor",
    "api.anthropic.com": "Claude",
    "api.openai.com": "OpenAI",
    "copilot.github.com": "Copilot",
    "api.githubcopilot.com": "Copilot",
    "generativelanguage.googleapis.com": "Gemini",
    "aiplatform.googleapis.com": "Vertex",
    "openai.azure.com": "Azure",
    "server.codeium.com": "Codeium",
    "api.deepseek.com": "DeepSeek",
    "api.mistral.ai": "Mistral",
    "api.groq.com": "Groq",
    "api.together.xyz": "Together",
    "api.fireworks.ai": "Fireworks",
    "api.cohere.ai": "Cohere",
    "api.perplexity.ai": "Perplexity",
}


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
        for pattern, name in _HOST_LABELS.items():
            if pattern in self.host:
                return name
        return self.host.split(".")[0].title()

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
        print(f"\n  {_BOLD}Live Interception Feed{_RESET}")
        print(f"  {_DIM}{'─' * 50}{_RESET}\n")

    def print_summary(self) -> None:
        """Print session summary on exit."""
        print(f"\n  {_DIM}{'─' * 50}{_RESET}")
        print(f"  {_BOLD}Session Summary{_RESET}")
        print(f"    Requests intercepted: {self._total_intercepted}")
        print(f"    Findings redacted:    {self._total_findings}")
        print(f"    Requests blocked:     {self._total_blocked}")
        print()

    def _print_event(self, event: InterceptionEvent) -> None:
        tool = f"{event.tool_name:<10}"
        host = f"{event.host:<35}"

        if event.action == "clean":
            status = f"{_GREEN}clean{_RESET}"
            detail = ""
        elif event.action == "blocked":
            status = f"{_RED}BLOCKED{_RESET}"
            det_str = ", ".join(f"{k}:{v}" for k, v in event.detector_counts.items())
            detail = f"  {_DIM}[{det_str}]{_RESET}"
        elif event.action == "redacted":
            status = f"{_YELLOW}{event.findings_count} redacted{_RESET}"
            det_str = ", ".join(sorted(event.detector_counts.keys()))
            detail = f"  {_DIM}[{det_str}]{_RESET}"
        elif event.action == "warn":
            status = f"{_CYAN}warn ({event.findings_count}){_RESET}"
            det_str = ", ".join(sorted(event.detector_counts.keys()))
            detail = f"  {_DIM}[{det_str}]{_RESET}"
        else:
            status = event.action
            detail = ""

        print(
            f"  {_DIM}{event.time_str}{_RESET}  {tool} → {host} {status}{detail}",
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
