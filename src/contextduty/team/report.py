"""Endpoint → collector reporting (Phase 0).

When a policy sets ``report_to: {"url": ..., "token": ...}``, endpoints emit
**metadata-only** events to the team collector: heartbeats, block/warn/redact
counts, and bypass events. Reporting is:

* **opt-in** — nothing is sent unless ``report_to`` is configured;
* **non-blocking** — failures never break a scan or commit (fire-and-forget);
* **content-free** — every payload passes through :func:`sanitize_event`.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import urllib.request
from pathlib import Path
from typing import Any

from .model import sanitize_event

_TIMEOUT = 3.0


def _host() -> str:
    return socket.gethostname()


def _user() -> str:
    return (
        os.environ.get("CONTEXTDUTY_USER")
        or os.environ.get("USER")
        or os.environ.get("USERNAME")
        or "unknown"
    )


def policy_hash(policy: Any) -> str:
    """A stable short hash identifying the active policy (never its content)."""
    material = "|".join(
        [
            getattr(policy, "mode", ""),
            ",".join(sorted(getattr(policy, "detectors", []))),
            json.dumps(getattr(policy, "detector_modes", {}), sort_keys=True),
        ]
    )
    return "sha256:" + hashlib.sha256(material.encode()).hexdigest()[:16]


def detect_surfaces() -> dict[str, bool]:
    """Best-effort: which protection surfaces are installed in the cwd."""
    return {
        "hook": Path(".git/hooks/pre-commit").exists(),
        "ide": any(Path(f).exists() for f in (".cursorignore", ".copilotignore", ".codeiumignore")),
    }


def _post(url: str, token: str, event: dict[str, Any], timeout: float) -> None:
    try:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            url.rstrip("/") + "/api/ingest",
            data=json.dumps(event).encode(),
            headers=headers,
            method="POST",
        )
        urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
    except Exception:
        pass  # reporting must NEVER break the developer's workflow


def report(
    policy: Any, event: dict[str, Any], *, blocking: bool = False, timeout: float = _TIMEOUT
) -> None:
    """Send one metadata event to the configured collector, if any."""
    cfg = getattr(policy, "report_to", None) or {}
    url = cfg.get("url")
    if not url:
        return
    payload = sanitize_event(
        {
            "host": _host(),
            "user": _user(),
            **event,
        }
    )
    token = cfg.get("token", "")
    if blocking:
        _post(url, token, payload, timeout)
    else:
        threading.Thread(target=_post, args=(url, token, payload, timeout), daemon=True).start()


def report_scan(policy: Any, result: Any, *, tool: str = "cli", repo: str = "") -> None:
    """Emit a heartbeat plus, if there were findings, a block/warn/redact event."""
    ph = policy_hash(policy)
    report(policy, {"event": "heartbeat", "surfaces": detect_surfaces(), "policy_hash": ph})
    if getattr(result, "findings_count", 0) == 0:
        return
    if getattr(result, "blocked", False):
        ev = "block"
    elif getattr(policy, "mode", "redact") == "warn":
        ev = "warn"
    else:
        ev = "redact"
    report(
        policy,
        {
            "event": ev,
            "repo": repo,
            "tool": tool,
            "detector_counts": dict(getattr(result, "detector_counts", {})),
            "findings_count": result.findings_count,
            "blocked": bool(getattr(result, "blocked", False)),
            "policy_hash": ph,
        },
    )


def report_bypass(policy: Any, *, repo: str = "", detail: str = "git commit --no-verify") -> None:
    """Emit a bypass event (blocking — a post-commit hook is short-lived)."""
    report(
        policy,
        {"event": "bypass", "repo": repo, "tool": "hook", "detail": detail},
        blocking=True,
    )
