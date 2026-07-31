"""Synthetic fleet metadata for `contextduty team serve --demo`.

All values are metadata only — the same shape real endpoints emit — so the
demo faithfully represents the product without any real or fake secrets.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

_USERS = ["priya", "alex", "sam", "jordan", "wei", "diego", "mia", "omar", "lena", "raj"]
_REPOS = ["payments-api", "web-app", "infra", "ml-pipeline", "mobile"]
_DETECTORS = ["aws_key", "github_pat", "openai_key", "stripe_secret", "email", "postgres_dsn"]


def build_demo_fleet(*, seed: int = 7) -> list[dict[str, Any]]:
    """Return a realistic fleet of metadata events for the demo dashboard."""
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    events: list[dict[str, Any]] = []

    for i, user in enumerate(_USERS):
        host = f"laptop-{user}"
        # Two endpoints are "dark" (last heartbeat > 24h ago).
        dark = i >= len(_USERS) - 2
        last_hb = now - (
            timedelta(days=rng.randint(2, 6)) if dark else timedelta(minutes=rng.randint(1, 90))
        )
        surfaces = {
            "hook": True,
            "proxy": rng.random() > 0.4,
            "ide": True,
            "mcp": rng.random() > 0.6,
        }
        events.append(
            {
                "ts": last_hb.isoformat(),
                "host": host,
                "user": user,
                "tool": "cli",
                "event": "heartbeat",
                "policy_hash": "sha256:" + ("a1b2c3d4" if i % 3 else "e5f6a7b8"),
                "surfaces": surfaces,
            }
        )
        # Prevention events over the last 30 days.
        for _ in range(rng.randint(20, 120)):
            # Dark endpoints stopped reporting: all their events are older than
            # the 24h coverage window (min 2 days ago).
            lo = 2 if dark else 0
            day = now - timedelta(days=rng.randint(lo, 29), minutes=rng.randint(0, 1440))
            ev = rng.choices(["block", "redact", "warn"], weights=[3, 5, 2])[0]
            det = rng.choice(_DETECTORS)
            events.append(
                {
                    "ts": day.isoformat(),
                    "host": host,
                    "user": user,
                    "repo": rng.choice(_REPOS),
                    "tool": rng.choice(["hook", "proxy", "cli", "mcp"]),
                    "event": ev,
                    "detector_counts": {det: rng.randint(1, 3)},
                    "findings_count": rng.randint(1, 3),
                    "blocked": ev == "block",
                }
            )

    # A few tamper/bypass events this week.
    for _ in range(4):
        user = rng.choice(_USERS)
        events.append(
            {
                "ts": (
                    now - timedelta(days=rng.randint(0, 6), hours=rng.randint(0, 23))
                ).isoformat(),
                "host": f"laptop-{user}",
                "user": user,
                "repo": rng.choice(_REPOS),
                "tool": "hook",
                "event": rng.choice(["bypass", "proxy_stop", "hook_uninstall"]),
                "detail": "git commit --no-verify",
            }
        )

    return events
