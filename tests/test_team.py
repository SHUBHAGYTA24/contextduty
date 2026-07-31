"""Tests for the team layer — the privacy contract and fleet aggregation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from contextduty.team.aggregate import aggregate_fleet
from contextduty.team.demo import build_demo_fleet
from contextduty.team.model import is_content_free, sanitize_event

# ---------------------------------------------------------------------------
# The privacy contract — metadata only, never content
# ---------------------------------------------------------------------------


def test_sanitize_strips_content_fields():
    raw = {
        "event": "block",
        "host": "laptop-1",
        "detector_counts": {"aws_key": 2},
        # These must be dropped — they are content, not metadata:
        "matched_value": "AKIA1234567890ABCDEF",
        "file_content": "secret stuff",
        "prompt": "my password is hunter2",
    }
    clean = sanitize_event(raw)
    assert "matched_value" not in clean
    assert "file_content" not in clean
    assert "prompt" not in clean
    assert clean["detector_counts"] == {"aws_key": 2}
    assert is_content_free(clean)


def test_sanitize_coerces_count_maps_and_surfaces():
    clean = sanitize_event(
        {
            "event": "warn",
            "detector_counts": {"email": "3", "note": "x"},  # non-int dropped
            "surfaces": {"hook": 1, "proxy": 0},
        }
    )
    assert clean["detector_counts"] == {"email": 3}
    assert clean["surfaces"] == {"hook": True, "proxy": False}


# ---------------------------------------------------------------------------
# Fleet aggregation
# ---------------------------------------------------------------------------


def test_aggregate_coverage_and_dark_endpoints():
    now = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
    events = [
        {"host": "a", "event": "heartbeat", "ts": now.isoformat(), "surfaces": {"hook": True}},
        {"host": "b", "event": "heartbeat", "ts": (now - timedelta(hours=2)).isoformat()},
        {"host": "c", "event": "heartbeat", "ts": (now - timedelta(days=3)).isoformat()},  # dark
        {"host": "a", "event": "block", "ts": now.isoformat(), "detector_counts": {"aws_key": 1}},
        {"host": "b", "event": "bypass", "ts": now.isoformat(), "detail": "--no-verify"},
    ]
    agg = aggregate_fleet(events, now=now)
    s = agg["summary"]
    assert s["endpoints_total"] == 3
    assert s["endpoints_enforcing"] == 2
    assert s["endpoints_dark"] == 1
    assert s["leaks_prevented"] == 1
    assert s["tamper_events"] == 1
    assert agg["tamper_feed"][0]["event"] == "bypass"
    assert agg["detector_totals"]["aws_key"] == 1


def test_demo_fleet_is_content_free():
    for ev in build_demo_fleet():
        assert is_content_free(ev), f"demo event leaked a non-metadata field: {ev}"
