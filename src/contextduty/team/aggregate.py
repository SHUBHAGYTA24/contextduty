"""Aggregate fleet metadata into the team-dashboard view."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

# An endpoint that hasn't sent a heartbeat within this window is "dark".
_DARK_AFTER = timedelta(hours=24)


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def aggregate_fleet(events: list[dict[str, Any]], *, now: datetime | None = None) -> dict[str, Any]:
    """Turn a stream of metadata events into fleet-level summary data."""
    now = now or datetime.now(timezone.utc)
    dark_cutoff = now - _DARK_AFTER

    # Per-endpoint latest state (identity = host).
    endpoints: dict[str, dict[str, Any]] = {}
    prevented = {"block": 0, "warn": 0, "redact": 0}
    detector_totals: dict[str, int] = {}
    tamper: list[dict[str, Any]] = []
    policy_hashes: dict[str, int] = {}

    # daily prevented (last 30 days)
    daily: dict[str, int] = {}
    for i in range(29, -1, -1):
        daily[(now - timedelta(days=i)).strftime("%Y-%m-%d")] = 0

    for e in events:
        host = e.get("host", "unknown")
        ts = _parse_ts(e.get("ts", "")) or now
        ev = e.get("event", "heartbeat")

        state = endpoints.setdefault(
            host, {"host": host, "last_seen": None, "surfaces": {}, "user": e.get("user", "")}
        )
        if state["last_seen"] is None or ts > state["last_seen"]:
            state["last_seen"] = ts
            state["surfaces"] = e.get("surfaces", state["surfaces"])
            state["user"] = e.get("user", state["user"])

        if ev in prevented:
            prevented[ev] += 1
            day = e.get("ts", "")[:10]
            if day in daily:
                daily[day] += 1
        for det, cnt in (e.get("detector_counts") or {}).items():
            detector_totals[det] = detector_totals.get(det, 0) + int(cnt)
        if ev in ("bypass", "hook_uninstall", "proxy_stop"):
            tamper.append(
                {
                    "ts": e.get("ts", ""),
                    "host": host,
                    "user": e.get("user", ""),
                    "repo": e.get("repo", ""),
                    "event": ev,
                    "detail": e.get("detail", ""),
                }
            )
        ph = e.get("policy_hash")
        if ph:
            policy_hashes[ph] = policy_hashes.get(ph, 0) + 1

    total = len(endpoints)
    enforcing = sum(
        1 for s in endpoints.values() if s["last_seen"] and s["last_seen"] >= dark_cutoff
    )
    dark = total - enforcing

    endpoint_rows = sorted(
        (
            {
                "host": s["host"],
                "user": s["user"],
                "surfaces": s["surfaces"],
                "last_seen": s["last_seen"].isoformat() if s["last_seen"] else "",
                "status": "enforcing"
                if (s["last_seen"] and s["last_seen"] >= dark_cutoff)
                else "dark",
            }
            for s in endpoints.values()
        ),
        key=lambda r: r["status"] != "dark",  # dark endpoints first
    )

    tamper.sort(key=lambda t: t["ts"], reverse=True)

    return {
        "summary": {
            "endpoints_total": total,
            "endpoints_enforcing": enforcing,
            "endpoints_dark": dark,
            "coverage_pct": round(100 * enforcing / total, 1) if total else 0,
            "leaks_prevented": prevented["block"] + prevented["redact"],
            "blocks": prevented["block"],
            "redactions": prevented["redact"],
            "warnings": prevented["warn"],
            "tamper_events": len(tamper),
            "policy_variants": len(policy_hashes),
        },
        "endpoints": endpoint_rows,
        "tamper_feed": tamper[:50],
        "detector_totals": dict(
            sorted(detector_totals.items(), key=lambda x: x[1], reverse=True)[:15]
        ),
        "daily_prevented": daily,
        "generated_at": now.isoformat(),
    }
